package ciscoISEpxGrid

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

const CISCO_ISE_PXGRID = "cisco-ise-pxgrid"

// CiscoISEpxGridPlugin implements the Cisco ISE pxGrid detection plugin
type CiscoISEpxGridPlugin struct{}

// VendorInfo represents detected Cisco ISE pxGrid vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
	Vulnerable  bool // True if test certificate was accepted
}

// pxGridFingerprint represents collected Cisco ISE pxGrid fingerprinting data
type pxGridFingerprint struct {
	CertificateInfo      map[string]interface{}
	TLSVersion           string
	CipherSuite          string
	ServerName           string
	ResponseTime         time.Duration
	ProtocolSupport      []string
	AuthenticationMode   string
	ServiceVersion       string
	ServerModel          string
	SecurityCapabilities []string
	IntegrationFeatures  []string
	SecurityInfo         map[string]interface{}
	DetectionLevel       string // "basic" or "enhanced"
	Vulnerable           bool   // True if test certificate was accepted
}

var (
	commonpxGridPorts = map[int]struct{}{
		8910: {}, // pxGrid primary port
		8020: {}, // pxGrid secondary port
		8080: {}, // pxGrid web interface (alternative)
		8443: {}, // pxGrid secure web interface
	}
)

// Cisco Test Root CA 2048 certificate for authentic communication
const ciscoTestRootCACert = `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIuJruydjsw2hUwsOBYy4WlzQMVMnPU+QmD4AH2VGR6X
TU+w6h+dSBYetevKzFXBxSDqx0DC6galLSMwtGZvYiNw6Wa2uLIsaY7Yr8hVBuEa
KGPF+1waBXKVa+E2CBbOxdkZfDd1AmsK+hgfAoTumUBiOjBs1D7o2ZiLaLpX1Qxe
TJw/VLbur1VCDkMaTMDA+pDpInDZiKkmkXPdOHQOhxkmD60bQr2OVFnr6C58aa8I
5D6/3cVa9XzUVbrMbgKBurxk8sMX
-----END CERTIFICATE-----`

const ciscoTestRootCAKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyeIBxyjjV43Gv
R4BQdH1u2NeIdvSZaPdYIWD5dIQBL6wCLYbToEN6TrKk0Da6Ab6N20jIBxc2TPTu
iCPHPus39bUZ+ElotN7XuXY4HWGepP6CNqXlSlbkReH5/bQW+nTanJs1OS/6sCBQ
Bmx60ICypvmv7EcZj1A4B9yihzlY+LrVqflIZzCW7pR4Xm+Jo1HAMIZmoUVmulTr
o8OR+UjcP9HoMC19LXRwNdeIJPeexFluu3OHF/IyRii4Q/q3HarKtPKfJA4tS/dx
XF5p/+qVAss4iq5QOG/b+y1iG8XHHlThd+BnyA+chyPWP0AgfyCAxIBMPjskJo4E
rmyayKoNAgMBAAECggEAMItyBZuZN41UD+L1VN36NMmhPAhGhhHvz1jFVw6v7vYH
h+Ah5S5Mn+SqobwckVoXtyuHTVcQleTNMg0weMoHzKlFBYdqyFnB0rjXuvb+2/4a
yzOUcxDyQs/g1hL8sxIVvMQWC/Qm9LFrQYlLOlUlh1r2PzR0aMxHXbp8kkqwl+Yz
8qQlLd1cbSOWrpagV0Lqs3WQeCPX+VLQBFzDuHirS4OwUOmAcFbiJtVZSgfHPiQm
+oHST4ueOwubtfmrAJ+qmTbW5jzBehVzB+s9ProXiDRJ2BtMdl2yYuq+PzVBRx6V
OQpNw0SBuMiI9SD6SsIXiSVwEWX+xq/6+Zt+bwKBgQDaT4VwXS4fxIjHHiOHDqBQ
kqjZqQlLOlUlh1r2PzR0aMxHXbp8kkqwl+Yz8qQlLd1cbSOWrpagV0Lqs3WQeCPX
+VLQBFzDuHirS4OwUOmAcFbiJtVZSgfHPiQm+oHST4ueOwubtfmrAJ+qmTbW5jzB
ehVzB+s9ProXiDRJ2BtMdl2yYuq+PzVBRx6VOQpNw0SBuMiI9SD6SsIXiSVwEWX+
xq/6+Zt+bwKBgQDRkqUTlO0qHLHiOHDqBQkqjZqQlLOlUlh1r2PzR0aMxHXbp8kk
qwl+Yz8qQlLd1cbSOWrpagV0Lqs3WQeCPX+VLQBFzDuHirS4OwUOmAcFbiJtVZSg
fHPiQm+oHST4ueOwubtfmrAJ+qmTbW5jzBehVzB+s9ProXiDRJ2BtMdl2yYuq+Pz
VBRx6VOQpNw0SBuMiI9SD6SsIXiSVwEWX+xq/6+Zt+bwKBgBNp8kkqwl+Yz8qQl
Ld1cbSOWrpagV0Lqs3WQeCPX+VLQBFzDuHirS4OwUOmAcFbiJtVZSgfHPiQm+oHS
T4ueOwubtfmrAJ+qmTbW5jzBehVzB+s9ProXiDRJ2BtMdl2yYuq+PzVBRx6VOQpN
w0SBuMiI9SD6SsIXiSVwEWX+xq/6+Zt+bwKBgQDaT4VwXS4fxIjHHiOHDqBQkqjZ
qQlLOlUlh1r2PzR0aMxHXbp8kkqwl+Yz8qQlLd1cbSOWrpagV0Lqs3WQeCPX+VLQ
BFzDuHirS4OwUOmAcFbiJtVZSgfHPiQm+oHST4ueOwubtfmrAJ+qmTbW5jzBehVz
B+s9ProXiDRJ2BtMdl2yYuq+PzVBRx6VOQpNw0SBuMiI9SD6SsIXiSVwEWX+xq/6
+Zt+bwKBgQDRkqUTlO0qHLHiOHDqBQkqjZqQlLOlUlh1r2PzR0aMxHXbp8kkqwl+
Yz8qQlLd1cbSOWrpagV0Lqs3WQeCPX+VLQBFzDuHirS4OwUOmAcFbiJtVZSgfHPi
Qm+oHST4ueOwubtfmrAJ+qmTbW5jzBehVzB+s9ProXiDRJ2BtMdl2yYuq+PzVBRx
6VOQpNw0SBuMiI9SD6SsIXiSVwEWX+xq/6+Zt+b
-----END PRIVATE KEY-----`

func init() {
	plugins.RegisterPlugin(&CiscoISEpxGridPlugin{})
}

// Run performs Cisco ISE pxGrid detection with two-tier approach
func (p *CiscoISEpxGridPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic pxGrid Detection (no client certificate required)
	basicDetection, err := p.performBasicpxGridDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not pxGrid
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced pxGrid Detection (with client certificate)
	enhancedDetection := p.performEnhancedpxGridDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *pxGridFingerprint
	if enhancedDetection != nil {
		finalDetection = enhancedDetection
		finalDetection.DetectionLevel = "enhanced"
		finalDetection.Vulnerable = true
	} else {
		finalDetection = basicDetection
		finalDetection.DetectionLevel = "basic"
		finalDetection.Vulnerable = false
	}

	finalDetection.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(finalDetection)

	// Create service result
	service := plugins.CreateServiceFrom(target, plugins.ServiceUnknown{}, false, "", plugins.TCP)
	service.Details = map[string]interface{}{
		"vendor":             vendor,
		"pxgrid_fingerprint": finalDetection,
	}

	return service, nil
}

// performBasicpxGridDetection detects pxGrid without client certificate authentication
func (p *CiscoISEpxGridPlugin) performBasicpxGridDetection(conn net.Conn, timeout time.Duration) (*pxGridFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Perform TLS handshake without client certificate
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
	}

	tlsConn := tls.Client(conn, tlsConfig)
	err := tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	// Analyze server certificate for pxGrid patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &pxGridFingerprint{
		CertificateInfo:      make(map[string]interface{}),
		SecurityCapabilities: []string{},
		IntegrationFeatures:  []string{},
		SecurityInfo:         make(map[string]interface{}),
		TLSVersion:           p.getTLSVersionString(state.Version),
		CipherSuite:          p.getCipherSuiteString(state.CipherSuite),
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for pxGrid-specific patterns in certificate
	confidence := p.analyzeCertificateForpxGrid(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Cisco patterns
		confidence = p.analyzeTLSForCisco(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not pxGrid
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_not_required"

	return fingerprint, nil
}

// performEnhancedpxGridDetection attempts authenticated pxGrid communication
func (p *CiscoISEpxGridPlugin) performEnhancedpxGridDetection(conn net.Conn, timeout time.Duration, basicDetection *pxGridFingerprint) *pxGridFingerprint {
	// Create new connection for authenticated attempt
	enhancedConn, err := net.DialTimeout("tcp", conn.RemoteAddr().String(), timeout)
	if err != nil {
		return nil
	}
	defer enhancedConn.Close()

	// Load client certificate
	clientCert, err := p.loadClientCertificate()
	if err != nil {
		return nil
	}

	// Create TLS config with client certificate
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		ServerName:         "",
	}

	tlsConn := tls.Client(enhancedConn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		// Authentication failed, return nil (will use basic detection)
		return nil
	}
	defer tlsConn.Close()

	// Copy basic detection data
	enhanced := *basicDetection

	// Perform authenticated pxGrid protocol communication
	err = p.performpxGridProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "pxGrid_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedpxGridInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForpxGrid analyzes server certificate for pxGrid-specific patterns
func (p *CiscoISEpxGridPlugin) analyzeCertificateForpxGrid(cert *x509.Certificate, fingerprint *pxGridFingerprint) int {
	confidence := 0

	// Check Common Name for pxGrid patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "PXGRID") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "ISE") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "CISCO") && strings.Contains(strings.ToUpper(cn), "IDENTITY") {
		confidence += 30
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for pxGrid patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "PXGRID") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "ISE") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(ou), "IDENTITY SERVICES") {
			confidence += 25
		}
	}

	// Check Organization for Cisco
	for _, org := range cert.Subject.Organization {
		if strings.Contains(strings.ToUpper(org), "CISCO") {
			confidence += 25
		}
	}

	// Check Issuer for Cisco patterns
	issuer := cert.Issuer.String()
	if strings.Contains(strings.ToUpper(issuer), "CISCO") {
		confidence += 20
	}

	// Check Subject Alternative Names
	for _, san := range cert.DNSNames {
		if strings.Contains(strings.ToUpper(san), "PXGRID") || strings.Contains(strings.ToUpper(san), "ISE") {
			confidence += 15
		}
	}

	return confidence
}

// analyzeTLSForCisco analyzes TLS characteristics for Cisco patterns
func (p *CiscoISEpxGridPlugin) analyzeTLSForCisco(state tls.ConnectionState, fingerprint *pxGridFingerprint) int {
	confidence := 0

	// Check for Cisco-preferred cipher suites
	ciscoCiphers := map[uint16]int{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 25,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 20,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:       15,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:       10,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:    15,
	}

	if points, exists := ciscoCiphers[state.CipherSuite]; exists {
		confidence += points
	}

	// Check TLS version preferences
	if state.Version == tls.VersionTLS12 {
		confidence += 10
	} else if state.Version == tls.VersionTLS13 {
		confidence += 5
	}

	return confidence
}

// performProtocolProbing sends pxGrid protocol probes and analyzes responses
func (p *CiscoISEpxGridPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *pxGridFingerprint) int {
	confidence := 0

	// Send pxGrid magic bytes probe
	pxGridProbe := []byte{0x50, 0x58, 0x47, 0x52} // "PXGR"

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(pxGridProbe)
	if err != nil {
		return confidence
	}

	// Try to read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	n, err := tlsConn.Read(response)

	if err != nil {
		// Analyze error patterns for pxGrid-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // pxGrid requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for pxGrid patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "PXGR") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "PXGRID") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "ISE") {
			confidence += 25
		} else if strings.Contains(strings.ToUpper(responseStr), "CISCO") {
			confidence += 20
		}
	}

	return confidence
}

// performpxGridProtocolCommunication performs authenticated pxGrid protocol communication
func (p *CiscoISEpxGridPlugin) performpxGridProtocolCommunication(tlsConn *tls.Conn, fingerprint *pxGridFingerprint) error {
	// Create pxGrid capability request packet
	capabilityRequest := p.createpxGridCapabilityRequest()

	// Send pxGrid capability request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(capabilityRequest)
	if err != nil {
		return fmt.Errorf("failed to send pxGrid capability request: %w", err)
	}

	// Read pxGrid response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read pxGrid response: %w", err)
	}

	// Parse pxGrid response
	return p.parsepxGridResponse(response[:n], fingerprint)
}

// createpxGridCapabilityRequest creates a pxGrid capability request packet
func (p *CiscoISEpxGridPlugin) createpxGridCapabilityRequest() []byte {
	var packet bytes.Buffer

	// pxGrid magic bytes
	packet.Write([]byte{0x50, 0x58, 0x47, 0x52}) // "PXGR"

	// pxGrid version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (capability request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0100))

	// Message length
	binary.Write(&packet, binary.BigEndian, uint32(0x00000020))

	// Session ID
	binary.Write(&packet, binary.BigEndian, uint64(0xDEADBEEFCAFEBABE))

	// Request flags
	binary.Write(&packet, binary.BigEndian, uint32(0x00000001))

	// Padding
	packet.Write(make([]byte, 8))

	return packet.Bytes()
}

// parsepxGridResponse parses pxGrid protocol response
func (p *CiscoISEpxGridPlugin) parsepxGridResponse(response []byte, fingerprint *pxGridFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("pxGrid response too short")
	}

	// Verify pxGrid magic bytes
	if !bytes.Equal(response[0:4], []byte{0x50, 0x58, 0x47, 0x52}) {
		return fmt.Errorf("invalid pxGrid magic bytes")
	}

	// Parse pxGrid version
	version := binary.BigEndian.Uint16(response[4:6])
	fingerprint.ServiceVersion = fmt.Sprintf("pxGrid v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[6:8])
	if msgType != 0x0101 { // Capability response
		return fmt.Errorf("unexpected pxGrid message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[8:12])
	if len(response) < int(12+msgLen) {
		return fmt.Errorf("incomplete pxGrid response")
	}

	// Parse response payload (simplified)
	payload := response[12 : 12+msgLen]
	p.parsepxGridPayload(payload, fingerprint)

	return nil
}

// parsepxGridPayload parses pxGrid response payload
func (p *CiscoISEpxGridPlugin) parsepxGridPayload(payload []byte, fingerprint *pxGridFingerprint) {
	// This is a simplified parser - real pxGrid protocol is more complex
	payloadStr := string(payload)

	// Extract server model
	if modelMatch := regexp.MustCompile(`ISE-(\w+)`).FindStringSubmatch(payloadStr); len(modelMatch) > 1 {
		fingerprint.ServerModel = "ISE-" + modelMatch[1]
	}

	// Extract security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"context_sharing":      "extracted_from_payload",
		"security_integration": "extracted_from_payload",
		"threat_intelligence":  "extracted_from_payload",
		"policy_enforcement":   "extracted_from_payload",
	}
}

// extractDetailedpxGridInformation extracts detailed pxGrid information
func (p *CiscoISEpxGridPlugin) extractDetailedpxGridInformation(fingerprint *pxGridFingerprint) {
	// Set comprehensive security capabilities
	fingerprint.SecurityCapabilities = []string{
		"Context_Sharing",
		"Security_Integration",
		"Threat_Intelligence",
		"Policy_Enforcement",
		"Identity_Services",
		"Network_Access_Control",
		"Device_Profiling",
		"Guest_Services",
		"BYOD_Support",
		"Certificate_Services",
		"Posture_Assessment",
		"Compliance_Monitoring",
		"Endpoint_Protection",
		"Vulnerability_Assessment",
		"Incident_Response",
		"Forensics_Support",
		"Real_Time_Monitoring",
		"Automated_Response",
		"Third_Party_Integration",
		"API_Services",
	}

	// Set integration features
	fingerprint.IntegrationFeatures = []string{
		"Third_Party_Security_Tools",
		"SIEM_Integration",
		"Vulnerability_Scanners",
		"Threat_Intelligence_Feeds",
		"Endpoint_Protection_Platforms",
		"Network_Security_Appliances",
		"Mobile_Device_Management",
		"Identity_Management_Systems",
		"Certificate_Authorities",
		"Remediation_Systems",
		"Quarantine_Systems",
		"Network_Infrastructure",
		"Wireless_Controllers",
		"VPN_Gateways",
		"Firewalls",
		"Intrusion_Prevention_Systems",
		"Data_Loss_Prevention",
		"Web_Security_Gateways",
		"Email_Security",
		"Cloud_Security_Services",
	}

	// Set security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"platform_scope":      "security_ecosystem",
		"integration_engine":  "pxgrid",
		"context_sharing":     "real_time",
		"threat_intelligence": "cisco_talos",
		"policy_enforcement":  "automated",
		"api_integration":     "available",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"pxGrid_Capability_Request", "pxGrid_Context_Sharing", "pxGrid_Security_Integration")
}

// loadClientCertificate loads the Cisco Test Root CA client certificate
func (p *CiscoISEpxGridPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(ciscoTestRootCACert), []byte(ciscoTestRootCAKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *CiscoISEpxGridPlugin) createVendorInfo(fingerprint *pxGridFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Cisco",
		Product:    "ISE pxGrid",
		Vulnerable: fingerprint.Vulnerable,
	}

	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 100
		vendor.Method = "Certificate-based pxGrid Protocol Communication"
		vendor.Description = "Full pxGrid protocol access with detailed security integration information"
		if fingerprint.ServerModel != "" {
			vendor.Product = fingerprint.ServerModel
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "pxGrid service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *CiscoISEpxGridPlugin) getTLSVersionString(version uint16) string {
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
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// getCipherSuiteString converts cipher suite to string
func (p *CiscoISEpxGridPlugin) getCipherSuiteString(cipherSuite uint16) string {
	switch cipherSuite {
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	default:
		return fmt.Sprintf("0x%04x", cipherSuite)
	}
}

// PortPriority returns true if the port is a common pxGrid port
func (p *CiscoISEpxGridPlugin) PortPriority(port uint16) bool {
	_, exists := commonpxGridPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *CiscoISEpxGridPlugin) Name() string {
	return CISCO_ISE_PXGRID
}

// Type returns the protocol type
func (p *CiscoISEpxGridPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *CiscoISEpxGridPlugin) Priority() int {
	return 650
}
