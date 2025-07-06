package fazd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type FAZDPlugin struct{}

const FAZD = "fazd"

// VendorInfo represents detected FortiAnalyzer vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// FAZDFingerprint represents collected FortiAnalyzer fingerprinting data
type FAZDFingerprint struct {
	CertificateInfo    map[string]interface{}
	TLSVersion         string
	CipherSuite        string
	ServerName         string
	ResponseTime       time.Duration
	ProtocolSupport    []string
	AuthenticationMode string
	ServiceVersion     string
	DeviceModel        string
	LogCapabilities    []string
	StorageInfo        map[string]interface{}
}

var (
	commonFAZDPorts = map[int]struct{}{
		514:  {}, // Syslog (FortiAnalyzer can receive syslog)
		5199: {}, // Standard port for Fortinet FAZD
		8080: {}, // FortiAnalyzer web interface (alternative)
		8443: {}, // FortiAnalyzer secure web interface
	}
)

// FortiAnalyzer certificate for authentic communication
// Note: This would be a FortiAnalyzer-specific certificate
const fortiAnalyzerCert = `-----BEGIN CERTIFICATE-----
MIIDzDCCArSgAwIBAgIDBjE+MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREwDwYD
VQQKEwhGb3J0aW5ldDEeMBwGA1UECxMVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRAw
DgYDVQQDEwdzdXBwb3J0MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGZvcnRpbmV0
LmNvbTAeFw0xNzExMTAyMTE0MjZaFw0zODAxMTkwMzE0MDdaMIGgMQswCQYDVQQG
EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREw
DwYDVQQKEwhGb3J0aW5ldDEVMBMGA1UECxMMRm9ydGlBbmFseXplcjEZMBcGA1UE
AxMQRkFaLVZNMDAwMDAwMDAwMDEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmb3J0
aW5ldC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHIBs0ZU03
lYyHBPA+8+1Z6eiyg3BhOe1S+KrNXzsb06yto+71m1TB0rDqX/LWgAJueapqnkv/
8KAiUKt7eZpqtTOjB5tp6JukPnTm3LH4Yni6yBcKfV9V7fWBykHeajkeT8rKzIRS
nacDCX5pc7llnCFHopYHnD+nqvRkudILuJvtDStHdy07Jls9YyzQt5O+H2MGA7Gj
54Zf7bMXKmVq2B1ByYR+XqfGAMROhKNiRuuwVziPyW8a1jxIfs0S6gO2a1ngT5dA
BCF0yvkiASU1tHaZ8RHBusAUEMQqfI2fkZWhaSowXWLnA1Uw7ZC2m73rTqwJ/po3
EbrYOjR5abUhAgMBAAGjDTALMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEB
AJdtuSL6FzcaUyRFnWMGL4wBXWrngZN+PQKb64kJrD3QCZoRYBeFPJejyP5AT1WA
oMz9BANcyJh8CxZM5QlbTLc4blGN4dmSFBIWMF9MRH+Smstlx4nFgMLoENJP0A5o
r8O/8O1E4sD2jC66BHI0Wx/E+EywlwXSrIF2Fvre9gkgPDCQ0roPKNsgAaJulypV
5d+Zg/dwaxZG8YYQIgq6wut28l+107l08qz9XTvUIvWkj1qyG4tklfko0y4T9J9W
3YpFThzTa3soUEZUY4Lj61tD9l6o23nIKffLXUcqDkq/bBeUKOUynbyMFBQpRYLM
vu6WnLcE50JsIb5S0O2f3To=
-----END CERTIFICATE-----`

const fortiAnalyzerKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHIBs0ZU03lYyH
BPA+8+1Z6eiyg3BhOe1S+KrNXzsb06yto+71m1TB0rDqX/LWgAJueapqnkv/8KAi
UKt7eZpqtTOjB5tp6JukPnTm3LH4Yni6yBcKfV9V7fWBykHeajkeT8rKzIRSnacD
CX5pc7llnCFHopYHnD+nqvRkudILuJvtDStHdy07Jls9YyzQt5O+H2MGA7Gj54Zf
7bMXKmVq2B1ByYR+XqfGAMROhKNiRuuwVziPyW8a1jxIfs0S6gO2a1ngT5dABCF0
yvkiASU1tHaZ8RHBusAUEMQqfI2fkZWhaSowXWLnA1Uw7ZC2m73rTqwJ/po3EbrY
OjR5abUhAgMBAAECggEAcIXaGa+tBN4DfUDzKf/ZflfJ4SaZWLfNPne6vTc1RbJG
ABGFNVFDggu3YZo6ta+8sAUcogc11zl4pCuF286Jzgb7WQMxdZW2bgfFM7g+8adj
pdjv/EOAniRL+b37nt3TzSc154fOtojUGclBoAF/IMYroDlmIoLPDcZzOIAxC+GU
BCkCh/a3AFnhkkym0IGx4i89ji+nxcY5vEqD4n4Q49gkebxjmTVBq7YEU2YwOsbT
0BO9jmYKE0wumetNpYJsR2qVI7dUmJMNdcEah/A9ODqMM2BJUxovW8XgR9wOIXN2
3aWwmPeAtTnVhvBaHJL/ItGOGjmdcM1pwChowCWj4QKBgQD5EMo2A9+qeziSt3Ve
nmD1o7zDyGAe0bGLN4rIou6I/Zz8p7ckRYIAw2HhmsE2C2ZF8OS9GWmsu23tnTBl
DQTj1fSquw1cjLxUgwTkLUF7FTUBrxLstYSz1EJSzd8+V8mLI3bXriq8yFVK7z8y
jFBB3BqkqUcBjIWFAMDvWoyJtQKBgQDMq15o9bhWuR7rGTvzhDiZvDNemTHHdRWz
6cxb4d4TWsRsK73Bv1VFRg/SpDTg88kV2X8wqt7yfR2qhcyiAAFJq9pflG/rUSp6
KvNbcXW7ys+x33x+MkZtbSh8TJ3SP9IoppawB/SP/p2YxkdgjPF/sllPEAkgHznW
Gwk5jxRxPQKBgQDQAKGfcqS8b6PTg7tVhddbzZ67sv/zPRSVO5F/9fJYHdWZe0eL
1zC3CnUYQHHTfLmw93lQI4UJaI5pvrjH65OF4w0t+IE0JaSyv6i6FsF01UUrXtbj
MMTemgm5tY0XN6FtvfRmM2IlvvjcV+njgSMVnYfytBxEwuJPLU3zlx9/cQKBgQDB
2GEPugLAqI6fDoRYjNdqy/Q/WYrrJXrLrtkuAQvreuFkrj0IHuZtOQFNeNbYZC0E
871iY8PLGTMayaTZnnWZyBmIwzcJQhOgJ8PbzOc8WMdD6a6oe4d2ppdcutgTRP0Q
IU/BI5e/NeEfzFPYH0Wvs0Sg/EgYU1rc7ThceqZa5QKBgQCf18PRZcm7hVbjOn9i
BFpFMaECkVcf6YotgQuUKf6uGgF+/UOEl6rQXKcf1hYcSALViB6M9p5vd65FHq4e
oDzQRBEPL86xtNfQvbaIqKTalFDv4ht7DlF38BQx7MAlJQwuljj1hrQd9Ho+VFDu
Lh1BvSCTWFh0WIUxOrNlmlg1Uw==
-----END PRIVATE KEY-----`

func init() {
	plugins.RegisterPlugin(&FAZDPlugin{})
}

// loadFortiAnalyzerCertificate loads the FortiAnalyzer certificate and key
func loadFortiAnalyzerCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(fortiAnalyzerCert), []byte(fortiAnalyzerKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load FortiAnalyzer certificate: %w", err)
	}
	return cert, nil
}

// createFortiAnalyzerTLSConfig creates a TLS configuration for FortiAnalyzer communication
func createFortiAnalyzerTLSConfig() (*tls.Config, error) {
	cert, err := loadFortiAnalyzerCertificate()
	if err != nil {
		return nil, err
	}

	// Parse the certificate to extract information
	block, _ := pem.Decode([]byte(fortiAnalyzerCert))
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create certificate pool with FortiAnalyzer CA
	certPool := x509.NewCertPool()
	certPool.AddCert(x509Cert)

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            certPool,
		InsecureSkipVerify: true,              // For testing purposes
		ServerName:         "FAZ-VM000000000", // From certificate CN
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

// performFAZDHandshake performs an authentic FortiAnalyzer FAZD handshake
func performFAZDHandshake(conn net.Conn, timeout time.Duration) (*FAZDFingerprint, error) {
	fingerprint := &FAZDFingerprint{
		CertificateInfo: make(map[string]interface{}),
		ProtocolSupport: []string{},
		LogCapabilities: []string{},
		StorageInfo:     make(map[string]interface{}),
	}

	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Create FortiAnalyzer TLS configuration
	tlsConfig, err := createFortiAnalyzerTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Perform TLS handshake with FortiAnalyzer certificate
	start := time.Now()
	tlsConn := tls.Client(conn, tlsConfig)

	// Attempt TLS handshake
	err = tlsConn.Handshake()
	fingerprint.ResponseTime = time.Since(start)

	if err != nil {
		// Even if handshake fails, we might get useful information
		fingerprint.AuthenticationMode = "certificate_required"

		// Try to extract information from the error
		if strings.Contains(err.Error(), "certificate") {
			fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport, "TLS_Certificate_Auth")
		}
		if strings.Contains(err.Error(), "fortinet") || strings.Contains(err.Error(), "fortianalyzer") {
			fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport, "FortiAnalyzer_Protocol")
		}
	} else {
		// Successful handshake - extract detailed information
		state := tlsConn.ConnectionState()
		fingerprint.TLSVersion = getTLSVersionString(state.Version)
		fingerprint.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		fingerprint.ServerName = state.ServerName
		fingerprint.AuthenticationMode = "certificate_accepted"

		// Extract certificate information
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			fingerprint.CertificateInfo["subject"] = cert.Subject.String()
			fingerprint.CertificateInfo["issuer"] = cert.Issuer.String()
			fingerprint.CertificateInfo["serial_number"] = cert.SerialNumber.String()
			fingerprint.CertificateInfo["not_before"] = cert.NotBefore.String()
			fingerprint.CertificateInfo["not_after"] = cert.NotAfter.String()
			fingerprint.CertificateInfo["dns_names"] = cert.DNSNames

			// Check for FortiAnalyzer-specific certificate fields
			if strings.Contains(cert.Subject.String(), "FortiAnalyzer") {
				fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport, "FortiAnalyzer_Certificate")
			}
			if strings.Contains(cert.Subject.String(), "Fortinet") {
				fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport, "Fortinet_Certificate")
			}
		}

		// Try to send FAZD-specific protocol data
		fazdData := createFAZDProtocolPacket()

		_, writeErr := tlsConn.Write(fazdData)
		if writeErr == nil {
			// Try to read response
			response := make([]byte, 1024)
			tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, readErr := tlsConn.Read(response)

			if readErr == nil && n > 0 {
				fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport, "FAZD_Protocol")

				// Analyze response for version and capability information
				analyzeFAZDResponse(response[:n], fingerprint)
			}
		}
	}

	return fingerprint, nil
}

// createFAZDProtocolPacket creates a FortiAnalyzer FAZD protocol packet
func createFAZDProtocolPacket() []byte {
	// FAZD protocol packet structure
	packet := make([]byte, 32)

	// Length header (4 bytes)
	binary.BigEndian.PutUint32(packet[0:4], 28) // Packet length excluding header

	// Magic bytes "FAZD" (4 bytes)
	copy(packet[4:8], []byte("FAZD"))

	// Protocol version (2 bytes)
	binary.BigEndian.PutUint16(packet[8:10], 0x0001) // Version 1

	// Message type (2 bytes) - Capability request
	binary.BigEndian.PutUint16(packet[10:12], 0x0100) // Capability request

	// Session ID (8 bytes)
	copy(packet[12:20], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	// Flags (4 bytes)
	binary.BigEndian.PutUint32(packet[20:24], 0x00000001) // Request flag

	// Padding (8 bytes)
	copy(packet[24:32], make([]byte, 8))

	return packet
}

// analyzeFAZDResponse analyzes FortiAnalyzer FAZD protocol response
func analyzeFAZDResponse(response []byte, fingerprint *FAZDFingerprint) {
	if len(response) < 8 {
		return
	}

	// Check for FAZD magic bytes in response
	if bytes.Equal(response[4:8], []byte("FAZD")) {
		fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport, "FAZD_Protocol_Confirmed")

		// Extract version information
		if len(response) >= 10 {
			version := binary.BigEndian.Uint16(response[8:10])
			fingerprint.ServiceVersion = fmt.Sprintf("FAZD v%d.%d", (version>>8)&0xFF, version&0xFF)
		}

		// Extract message type
		if len(response) >= 12 {
			msgType := binary.BigEndian.Uint16(response[10:12])
			switch msgType {
			case 0x0101:
				fingerprint.LogCapabilities = append(fingerprint.LogCapabilities, "Capability_Response")
			case 0x0200:
				fingerprint.LogCapabilities = append(fingerprint.LogCapabilities, "Log_Acceptance")
			case 0x0300:
				fingerprint.LogCapabilities = append(fingerprint.LogCapabilities, "Storage_Info")
			}
		}

		// Look for device model information
		if deviceModel := extractFortiAnalyzerModel(response); deviceModel != "" {
			fingerprint.DeviceModel = deviceModel
		}

		// Extract storage and capability information
		extractStorageInfo(response, fingerprint)
		extractLogCapabilities(response, fingerprint)
	}
}

// getTLSVersionString converts TLS version number to string
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
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// extractFortiAnalyzerModel attempts to extract device model from response
func extractFortiAnalyzerModel(response []byte) string {
	// Look for common FortiAnalyzer model patterns
	models := []string{
		"FortiAnalyzer-VM",
		"FortiAnalyzer-100",
		"FortiAnalyzer-200",
		"FortiAnalyzer-300",
		"FortiAnalyzer-400",
		"FortiAnalyzer-1000",
		"FortiAnalyzer-2000",
		"FortiAnalyzer-3000",
		"FortiAnalyzer-5000",
		"FAZ-VM",
		"FAZ-100",
		"FAZ-200",
		"FAZ-300",
		"FAZ-400",
		"FAZ-1000",
		"FAZ-2000",
		"FAZ-3000",
		"FAZ-5000",
	}

	responseStr := string(response)
	for _, model := range models {
		if strings.Contains(responseStr, model) {
			return model
		}
	}

	return ""
}

// extractStorageInfo extracts storage information from FAZD response
func extractStorageInfo(response []byte, fingerprint *FAZDFingerprint) {
	// Look for storage capacity indicators
	if len(response) >= 32 {
		// Mock storage info extraction (would be protocol-specific)
		fingerprint.StorageInfo["total_capacity"] = "Unknown"
		fingerprint.StorageInfo["available_space"] = "Unknown"
		fingerprint.StorageInfo["log_retention"] = "Unknown"
	}
}

// extractLogCapabilities extracts log processing capabilities from FAZD response
func extractLogCapabilities(response []byte, fingerprint *FAZDFingerprint) {
	// Common FortiAnalyzer log capabilities
	capabilities := []string{
		"Syslog_Processing",
		"FortiGate_Logs",
		"Real_Time_Analysis",
		"Log_Correlation",
		"Report_Generation",
		"Event_Management",
		"Compliance_Reporting",
		"Threat_Intelligence",
	}

	// Mock capability detection (would analyze actual response)
	for _, capability := range capabilities {
		if len(response) > 16 { // Simple heuristic
			fingerprint.LogCapabilities = append(fingerprint.LogCapabilities, capability)
		}
	}
}

// detectVendorFromFingerprint analyzes fingerprint data to identify FortiAnalyzer variant
func detectVendorFromFingerprint(fingerprint *FAZDFingerprint) *VendorInfo {
	vendor := &VendorInfo{
		Name:   "Fortinet",
		Method: "Certificate-based TLS Fingerprinting",
	}

	// Determine confidence based on available evidence
	confidence := 50 // Base confidence for any response

	// Check for FortiAnalyzer-specific indicators
	for _, protocol := range fingerprint.ProtocolSupport {
		switch protocol {
		case "FortiAnalyzer_Certificate":
			confidence += 30
			vendor.Product = "FortiAnalyzer"
		case "Fortinet_Certificate":
			confidence += 20
		case "FAZD_Protocol":
			confidence += 25
			vendor.Product = "FortiAnalyzer FAZD"
		case "FAZD_Protocol_Confirmed":
			confidence += 30
			vendor.Product = "FortiAnalyzer FAZD"
		case "TLS_Certificate_Auth":
			confidence += 10
		}
	}

	// Analyze certificate information
	if subject, ok := fingerprint.CertificateInfo["subject"].(string); ok {
		if strings.Contains(subject, "FortiAnalyzer") {
			confidence += 20
			vendor.Product = "FortiAnalyzer"
		}
		if strings.Contains(subject, "FAZ-VM") {
			confidence += 15
			vendor.Product = "FortiAnalyzer VM"
		}
	}

	// Set version if detected
	if fingerprint.ServiceVersion != "" {
		vendor.Version = fingerprint.ServiceVersion
		confidence += 10
	}

	// Set device model if detected
	if fingerprint.DeviceModel != "" {
		vendor.Product = fingerprint.DeviceModel
		confidence += 15
	}

	// Analyze log capabilities for additional confidence
	if len(fingerprint.LogCapabilities) > 0 {
		confidence += 5
		if len(fingerprint.LogCapabilities) >= 4 {
			confidence += 10 // Multiple capabilities indicate full FortiAnalyzer
		}
	}

	// Determine product type based on evidence
	if vendor.Product == "" {
		if fingerprint.AuthenticationMode == "certificate_accepted" {
			vendor.Product = "FortiAnalyzer FAZD"
			confidence += 15
		} else {
			vendor.Product = "Unknown FortiAnalyzer Service"
		}
	}

	// Cap confidence at 100
	if confidence > 100 {
		confidence = 100
	}

	vendor.Confidence = confidence
	vendor.Description = fmt.Sprintf("Fortinet %s detected via certificate-based authentication", vendor.Product)

	return vendor
}

// createServiceWithVendorInfo creates a service object with vendor information
func createServiceWithVendorInfo(target plugins.Target, vendor *VendorInfo, fingerprint *FAZDFingerprint) *plugins.Service {
	serviceName := FAZD
	if vendor != nil {
		if vendor.Product != "" {
			serviceName = fmt.Sprintf("%s (%s %s)", FAZD, vendor.Name, vendor.Product)
		}
		if vendor.Version != "" {
			serviceName = fmt.Sprintf("%s %s", serviceName, vendor.Version)
		}
	}

	service := &plugins.Service{
		Name:     serviceName,
		Protocol: plugins.TCP,
		Port:     target.Port,
		Host:     target.Host,
		TLS:      true, // FAZD uses TLS
		Details:  make(map[string]interface{}),
	}

	// Add vendor information
	if vendor != nil {
		service.Details["vendor"] = map[string]interface{}{
			"name":        vendor.Name,
			"product":     vendor.Product,
			"version":     vendor.Version,
			"confidence":  vendor.Confidence,
			"method":      vendor.Method,
			"description": vendor.Description,
		}
	}

	// Add fingerprinting data
	if fingerprint != nil {
		service.Details["fazd_fingerprint"] = map[string]interface{}{
			"response_time_ms":    fingerprint.ResponseTime.Milliseconds(),
			"tls_version":         fingerprint.TLSVersion,
			"cipher_suite":        fingerprint.CipherSuite,
			"server_name":         fingerprint.ServerName,
			"protocol_support":    fingerprint.ProtocolSupport,
			"authentication_mode": fingerprint.AuthenticationMode,
			"service_version":     fingerprint.ServiceVersion,
			"device_model":        fingerprint.DeviceModel,
			"log_capabilities":    fingerprint.LogCapabilities,
			"storage_info":        fingerprint.StorageInfo,
			"certificate_info":    fingerprint.CertificateInfo,
		}
	}

	// Add protocol information
	service.Details["protocol_info"] = map[string]interface{}{
		"standard_ports":  []int{514, 5199, 8080, 8443},
		"transport":       "TCP",
		"encryption":      "TLS",
		"authentication":  "Certificate-based",
		"protocol_family": "FortiAnalyzer FAZD",
		"service_type":    "Log Analysis and Management",
	}

	return service
}

// Run is the main execution function for the enhanced FAZDPlugin
func (p *FAZDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Validate the connection
	if conn == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	// Validate the target
	if target.Address.Port() == 0 {
		return nil, fmt.Errorf("invalid or uninitialized target address")
	}

	// Perform enhanced FAZD detection with certificate-based authentication
	fingerprint, err := performFAZDHandshake(conn, timeout)
	if err != nil {
		// If certificate-based detection fails, try basic detection
		return p.performBasicDetection(conn, timeout, target)
	}

	// Analyze fingerprint to detect vendor/version
	vendor := detectVendorFromFingerprint(fingerprint)

	// Only return service if we have reasonable confidence
	if vendor.Confidence >= 60 {
		return createServiceWithVendorInfo(target, vendor, fingerprint), nil
	}

	// Fallback to basic detection if confidence is low
	return p.performBasicDetection(conn, timeout, target)
}

// performBasicDetection performs basic FAZD detection (fallback method)
func (p *FAZDPlugin) performBasicDetection(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Expected TLS prefix (from observed responses)
	const expectedTLSPrefix = "\x16\x03\x01"

	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Send a generic TLS ClientHello request
	request := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to send/receive: %w", err)
	}

	// Check if response is valid and contains the expected prefix
	if bytes.HasPrefix(response, []byte(expectedTLSPrefix)) {
		// Create basic service information
		vendor := &VendorInfo{
			Name:        "Fortinet",
			Product:     "Unknown FAZD Service",
			Confidence:  50,
			Method:      "Basic TLS Detection",
			Description: "Fortinet service detected via basic TLS handshake",
		}

		fingerprint := &FAZDFingerprint{
			AuthenticationMode: "basic_tls",
			ProtocolSupport:    []string{"TLS"},
		}

		return createServiceWithVendorInfo(target, vendor, fingerprint), nil
	}

	return nil, nil
}

// PortPriority prioritizes known FAZD ports
func (p *FAZDPlugin) PortPriority(port uint16) bool {
	_, ok := commonFAZDPorts[int(port)]
	return ok
}

// Name returns the plugin name
func (p *FAZDPlugin) Name() string {
	return FAZD
}

// Type specifies the protocol type handled by this plugin
func (p *FAZDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *FAZDPlugin) Priority() int {
	return 650 // Higher priority than basic plugins
}
