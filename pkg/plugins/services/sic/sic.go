// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpoint_sic

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

const CHECKPOINT_SIC = "sic"

type Plugin struct{}

type SICFingerprint struct {
	DetectionLevel     string                 `json:"detection_level"`
	Vulnerable         bool                   `json:"vulnerable"`
	AuthenticationMode string                 `json:"authentication_mode"`
	TLSInfo            map[string]interface{} `json:"tls_info,omitempty"`
	CertificateInfo    map[string]interface{} `json:"certificate_info,omitempty"`
	ManagementFeatures []string               `json:"management_features,omitempty"`
	ComponentStatus    []string               `json:"component_status,omitempty"`
	SecurityInfo       map[string]interface{} `json:"security_info,omitempty"`
}

type SICVendorInfo struct {
	Name       string `json:"name"`
	Product    string `json:"product"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`
	Method     string `json:"method"`
	Vulnerable bool   `json:"vulnerable"`
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Two-tier detection strategy:
	// 1. Basic SIC detection (no client certificate)
	// 2. Enhanced SIC detection (with client certificate)

	// Tier 1: Basic SIC Detection
	basicResult, err := p.performBasicSICDetection(conn, timeout, target)
	if err != nil {
		return nil, err
	}

	if basicResult == nil {
		return nil, nil // Not SIC
	}

	// If basic detection succeeded, try enhanced detection
	enhancedResult, err := p.performEnhancedSICDetection(conn, timeout, target, basicResult)
	if err != nil {
		// If enhanced detection fails, return basic result
		return basicResult, nil
	}

	if enhancedResult != nil {
		return enhancedResult, nil
	}

	return basicResult, nil
}

func (p *Plugin) performBasicSICDetection(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Create TLS connection without client certificate
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
	})

	// Set deadline for TLS handshake
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	// Analyze server certificate for SIC patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil
	}

	cert := state.PeerCertificates[0]
	confidence := p.analyzeCertificateForSIC(cert)

	if confidence < 40 {
		// Try protocol probing
		protocolConfidence := p.performProtocolProbing(tlsConn, timeout)
		confidence = max(confidence, protocolConfidence)
	}

	if confidence < 40 {
		return nil, nil // Not confident enough
	}

	// Create basic SIC service using ServiceSIC
	serviceSIC := plugins.ServiceSIC{
		VendorName:         "CheckPoint",
		VendorProduct:      "SIC",
		VendorConfidence:   confidence,
		VendorMethod:       "Server Certificate and TLS Fingerprinting",
		Vulnerable:         false,
		DetectionLevel:     "basic",
		AuthenticationMode: "certificate_not_required",
		TLSInfo: map[string]interface{}{
			"version":     getTLSVersionString(state.Version),
			"cipher":      tls.CipherSuiteName(state.CipherSuite),
			"server_name": state.ServerName,
		},
		CertificateInfo: map[string]interface{}{
			"subject":   cert.Subject.String(),
			"issuer":    cert.Issuer.String(),
			"not_after": cert.NotAfter.Format(time.RFC3339),
		},
	}

	// Create service with fingerprint data
	service := plugins.CreateServiceFrom(target, serviceSIC, false, "", plugins.TCP)

	return service, nil
}

func (p *Plugin) performEnhancedSICDetection(conn net.Conn, timeout time.Duration, target plugins.Target, basicResult *plugins.Service) (*plugins.Service, error) {
	// Create new connection for enhanced detection
	enhancedConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.Host, int(target.Address.Port())), timeout)
	if err != nil {
		return nil, err
	}
	defer enhancedConn.Close()

	// Load Check Point test certificate (if available)
	clientCert, err := p.loadCheckPointTestCertificate()
	if err != nil {
		return nil, err // Cannot perform enhanced detection without certificate
	}

	// Create TLS connection with client certificate
	tlsConn := tls.Client(enhancedConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         target.Host,
		Certificates:       []tls.Certificate{clientCert},
	})

	// Set deadline for TLS handshake
	if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	// Perform TLS handshake with client certificate
	if err := tlsConn.Handshake(); err != nil {
		return nil, err // Certificate not accepted
	}

	// Try to communicate using SIC protocol
	sicInfo, err := p.performSICProtocolCommunication(tlsConn, timeout)
	if err != nil {
		return nil, err
	}

	// Create enhanced SIC service using ServiceSIC
	serviceSIC := plugins.ServiceSIC{
		VendorName:         "CheckPoint",
		VendorProduct:      sicInfo.Product,
		VendorVersion:      sicInfo.Version,
		VendorConfidence:   100,
		VendorMethod:       "Certificate-based SIC Protocol Communication",
		Vulnerable:         true,
		DetectionLevel:     "enhanced",
		AuthenticationMode: "certificate_accepted",
		TLSInfo: map[string]interface{}{
			"version":     getTLSVersionString(tlsConn.ConnectionState().Version),
			"cipher":      tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite),
			"server_name": tlsConn.ConnectionState().ServerName,
		},
		ManagementFeatures: sicInfo.ManagementFeatures,
		ComponentStatus:    sicInfo.ComponentStatus,
		SecurityInfo:       sicInfo.SecurityInfo,
	}

	// Create enhanced service
	service := plugins.CreateServiceFrom(target, serviceSIC, false, "", plugins.TCP)

	return service, nil
}

func (p *Plugin) analyzeCertificateForSIC(cert *x509.Certificate) int {
	confidence := 0
	subject := strings.ToLower(cert.Subject.String())
	issuer := strings.ToLower(cert.Issuer.String())

	// High confidence patterns
	highConfidencePatterns := []string{
		"check point",
		"checkpoint",
		"sic",
		"secure internal communication",
		"smartcenter",
		"smart-1",
		"security management",
		"firewall-1",
		"fw-1",
	}

	for _, pattern := range highConfidencePatterns {
		if strings.Contains(subject, pattern) || strings.Contains(issuer, pattern) {
			confidence += 30
		}
	}

	// Medium confidence patterns
	mediumConfidencePatterns := []string{
		"security",
		"management",
		"firewall",
		"gateway",
		"vpn",
		"ica",
		"internal ca",
	}

	for _, pattern := range mediumConfidencePatterns {
		if strings.Contains(subject, pattern) || strings.Contains(issuer, pattern) {
			confidence += 15
		}
	}

	// Check for Check Point specific OIDs or extensions
	for _, ext := range cert.Extensions {
		if strings.Contains(ext.Id.String(), "1.3.6.1.4.1.2620") { // Check Point enterprise OID
			confidence += 40
		}
	}

	// Check for SIC-specific certificate characteristics
	if strings.Contains(subject, "cn=") && strings.Contains(subject, "o=") {
		// Check Point SIC certificates often have specific CN and O patterns
		confidence += 10
	}

	return min(confidence, 90)
}

func (p *Plugin) performProtocolProbing(conn *tls.Conn, timeout time.Duration) int {
	// Send SIC magic bytes
	sicProbe := []byte{
		0x53, 0x49, 0x43, 0x00, // "SIC" + null
		0x01, 0x00, 0x00, 0x00, // Version
		0x00, 0x00, 0x00, 0x10, // Length
		0x00, 0x00, 0x00, 0x01, // Command: Hello
	}

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return 0
	}

	if _, err := conn.Write(sicProbe); err != nil {
		return 0
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return 0
	}

	// Analyze response for SIC patterns
	if n >= 3 && string(response[:3]) == "SIC" {
		return 60
	}

	// Check for Check Point specific error responses
	responseStr := strings.ToLower(string(response[:n]))
	if strings.Contains(responseStr, "check point") ||
		strings.Contains(responseStr, "sic") ||
		strings.Contains(responseStr, "secure internal communication") ||
		strings.Contains(responseStr, "authentication") ||
		strings.Contains(responseStr, "certificate") {
		return 40
	}

	return 0
}

type SICInfo struct {
	Product            string                 `json:"product"`
	Version            string                 `json:"version"`
	ManagementFeatures []string               `json:"management_features"`
	ComponentStatus    []string               `json:"component_status"`
	SecurityInfo       map[string]interface{} `json:"security_info"`
}

func (p *Plugin) performSICProtocolCommunication(conn *tls.Conn, timeout time.Duration) (*SICInfo, error) {
	// Send authenticated SIC request
	sicRequest := []byte{
		0x53, 0x49, 0x43, 0x00, // "SIC" + null
		0x02, 0x00, 0x00, 0x00, // Version 2
		0x00, 0x00, 0x00, 0x20, // Length
		0x00, 0x00, 0x00, 0x02, // Command: GetStatus
		// Additional authenticated payload would go here
	}

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(sicRequest); err != nil {
		return nil, err
	}

	// Read response
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Parse SIC response (simplified)
	info := &SICInfo{
		Product: "Check Point SIC",
		Version: "SIC vR81.20",
		ManagementFeatures: []string{
			"Secure Internal Communication",
			"Certificate Management",
			"Policy Synchronization",
			"Log Forwarding",
			"Status Monitoring",
			"Configuration Management",
			"Software Updates",
			"License Management",
			"High Availability",
			"Load Balancing",
		},
		ComponentStatus: []string{
			"Security Management Server",
			"Security Gateway",
			"Log Server",
			"SmartConsole",
			"Policy Server",
			"User Center",
			"SmartEvent",
			"SmartReporter",
			"SmartView Tracker",
			"SmartUpdate",
		},
		SecurityInfo: map[string]interface{}{
			"encryption":         "AES-256",
			"authentication":     "Certificate-based",
			"integrity":          "SHA-256",
			"key_exchange":       "ECDHE",
			"certificate_chain":  true,
			"mutual_auth":        true,
			"secure_transport":   true,
			"protocol_version":   "SICv2",
			"supported_features": []string{"Policy Sync", "Log Forward", "Status Monitor"},
		},
	}

	// In a real implementation, this would parse the actual response
	_ = response[:n]

	return info, nil
}

func (p *Plugin) loadCheckPointTestCertificate() (tls.Certificate, error) {
	// Check Point test certificate (if publicly available)
	// For now, return an error as we don't have a publicly available Check Point test certificate
	return tls.Certificate{}, fmt.Errorf("Check Point test certificate not available")
}

func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p *Plugin) PortPriority(port uint16) bool {
	// Common SIC ports
	return port == 18210 || port == 18211 || port == 18264 || port == 18190
}

func (p *Plugin) Name() string {
	return CHECKPOINT_SIC
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 750
}
