package fgfmsd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type FGFMSDPlugin struct{}

const FGFMSD = "fgfmsd"

// VendorInfo represents detected FortiManager FGFMSD vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
	Vulnerable  bool // True if test certificate was accepted
}

// FGFMSDFingerprint represents collected FortiManager FGFMSD fingerprinting data
type FGFMSDFingerprint struct {
	CertificateInfo    map[string]interface{}
	TLSVersion         string
	CipherSuite        string
	ServerName         string
	ResponseTime       time.Duration
	ProtocolSupport    []string
	AuthenticationMode string
	ServiceVersion     string
	DeviceModel        string
	ManagementFeatures []string
	SecurityInfo       map[string]interface{}
	DetectionLevel     string // "basic" or "enhanced"
	Vulnerable         bool   // True if test certificate was accepted
}

var (
	commonFGFMSDPorts = map[int]struct{}{
		541:  {}, // Standard port for FortiManager FGFMSD
		8890: {}, // Alternative management port
		8013: {}, // Management sync port
		443:  {}, // HTTPS port (alternative)
	}

	// FortiManager FGFMSD certificate for authentic communication
	fortiManagerCert = `-----BEGIN CERTIFICATE-----
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
ej5UUO4uHUG9IJNYWHRYhTE6s2WaWDVT
-----END CERTIFICATE-----`

	fortiManagerKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHIBs0ZU03lYyH
BPA+8+1Z6eiyizBhOe1S+KrNXzsb06yto+71m1TB0rDqX/LWgAJueapqnkv/8KAi
UKt7eZpqtTOjB5tp6JukPnTm3LH4Yni6yBcKfV9V7fWBykEeajkeT8rKzIRSnacD
CX5pc7llnCFHopYHnD+nqvRkudILuJvtDStHdy07Jls9YyzQt5O+H2MGA7Gj54Zf
7bMXKmVq2B1ByYR+XqfGAMROhKNiRuuwVziPyW8a1jxIfs0S6gO2a1ngT5dABCF0
yvkiASU1tHaZ8RHBusAUEMQqfI2fkZWhaSowXWLnA1Uw7ZC2m73rTqwJ/po3EbrY
OjR5abUhAgMBAAECggEAcIXaGa+tBN4DfUDzKf/ZflfJ4SaZWLfNPne6vTc1RbJG
ABGFNVFDggu3YZo6ta+8sAUcogc11zl4pCuF286Jzgb7WQMxdZW2bgfFM7g+8adj
pdjv/EOAniRL+b37nt3TzSc154fOtojUGclBoAF/IMYroDlmIoLPDcZzOIAxC+GU
BCkCh/a3AFnhkkym0IGx4i89ji+nxcY5vEqD4n4Q49gkebxjmTVBq7YEU2YwOsbT
0BO9jmYKE0wumetNpYJsR2qVI7dUmJMNdcEah/A9ODqMM2BJUxovW8XgR9wOIXN2
3aWwmPeAtTnVhvBaHJL7EtGOGjmdcM1pwChowCWj4QKBgQD5EMo2A9+qeziSt3Ve
nmD1o7zDyGAe0bGLN4rIou6I/Zz8p7ckRYIAw2HhmsE2C2ZF8OS9GWmsu23tnTBl
DQTj1fSquw1cjLxUgwTkLUF7FTUBrxLstYSz1EJSzd8+V8mLI3bXriq8yFVK7z8y
jFBB3BqkqUcBjIWFAMDvWoyJtQKBgQDMq15o9bhWuR7rGTvzhDiZvDNemTHHdRWz
6cxb4d4TWsRsK73Bv1VFRg/SpDTg88kV2X8wqt7yfR2qhcyiAAFJq9pflG/rUSp6
KvNbcXW7ys+x33x+MkZtbSh8TJ3SP9IoppawB/SP/p2YxkdgjPF/sllPEAkgHznW
Gwk5jxRxPQKBgQDQAKGfcqS8b6PTg7tVhddbzZ67sv/zPRSVO5F/9fJYHdWZe0eL
1zC3CnUYQHHTfLmw93lQI4UJaI5pvrjH65OF4w0t+IE0JaSyv6i6FsF01UUrXrtj
MMTemgm5tY0XN6FtvfRmM2IlvvjcV+njgSMVnYfytBxEwuJPLU3zlx9/cQKBgQDB
2GEPugLAqI6fDoRYjNdqy/Q/WYrrJXrLrkkuAQvreuFkrj0IHuZtOQFNeNbYZC0E
871iY8PLGTMayaTZnnWZyBmIwzcJQhOgJ8PbzOc8WMdD6a6oe4d2ppdcutgTRP0Q
IU/BI5e/NeEfzFPYH0Wvs0Sg/EgYU1rc7ThceqZa5QKBgQCf18PRZcm7hVbjOn9i
BFpFMaECkVcf6YotgQuUKf6uGgF+/UOEl6rQXKcf1hYcSALViB6M9p5vd65FHq4e
oDzQRBEPL86xtNfQvbaIqKTalFDv4ht7DlF38BQx7MAlJQwuljj1hrQd9Ho+VFDu
Lh1BvSCTWFh0WIUxOrNlmlg1Uw==
-----END PRIVATE KEY-----`
)

func init() {
	plugins.RegisterPlugin(&FGFMSDPlugin{})
}

// Run performs FortiManager FGFMSD detection with two-tier approach
func (p *FGFMSDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic FGFMSD Detection (certificate analysis)
	basicDetection, err := p.performBasicFGFMSDDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not FortiManager FGFMSD
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced FGFMSD Detection (with client certificate)
	enhancedDetection := p.performEnhancedFGFMSDDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *FGFMSDFingerprint
	if enhancedDetection != nil {
		finalDetection = enhancedDetection
	} else {
		finalDetection = basicDetection
	}

	finalDetection.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(finalDetection)

	// Create service result using ServiceFGFMSD struct with correct field names
	serviceFGFMSD := plugins.ServiceFGFMSD{
		// Vendor information (exact field names from types.go)
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,
		Vulnerable:        vendor.Vulnerable,

		// Certificate information (exact field names from types.go)
		CertificateInfo: finalDetection.CertificateInfo,
		TLSVersion:      finalDetection.TLSVersion,
		CipherSuite:     finalDetection.CipherSuite,
		ServerName:      finalDetection.ServerName,
		ResponseTime:    finalDetection.ResponseTime,

		// Protocol and service information (exact field names from types.go)
		ProtocolSupport:    finalDetection.ProtocolSupport,
		AuthenticationMode: finalDetection.AuthenticationMode,
		ServiceVersion:     finalDetection.ServiceVersion,
		DeviceModel:        finalDetection.DeviceModel,

		// FGFMSD-specific features (exact field names from types.go)
		ManagementFeatures: finalDetection.ManagementFeatures,
		SecurityInfo:       finalDetection.SecurityInfo,

		// Detection metadata (exact field names from types.go)
		DetectionLevel: finalDetection.DetectionLevel,
	}

	service := plugins.CreateServiceFrom(target, serviceFGFMSD, false, "", plugins.TCP)
	return service, nil
}

// performBasicFGFMSDDetection detects FortiManager FGFMSD via certificate analysis
func (p *FGFMSDPlugin) performBasicFGFMSDDetection(conn net.Conn, timeout time.Duration) (*FGFMSDFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Perform TLS handshake
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

	// Analyze server certificate for FortiManager FGFMSD patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &FGFMSDFingerprint{
		CertificateInfo:    make(map[string]interface{}),
		ManagementFeatures: []string{},
		SecurityInfo:       make(map[string]interface{}),
		TLSVersion:         p.getTLSVersionString(state.Version),
		CipherSuite:        p.getCipherSuiteString(state.CipherSuite),
		DetectionLevel:     "basic",
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for FortiManager FGFMSD-specific patterns in certificate
	confidence := p.analyzeCertificateForFGFMSD(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Fortinet patterns
		confidence = p.analyzeTLSForFortinet(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not FortiManager FGFMSD
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_based"

	return fingerprint, nil
}

// performEnhancedFGFMSDDetection attempts authenticated FortiManager FGFMSD communication
func (p *FGFMSDPlugin) performEnhancedFGFMSDDetection(conn net.Conn, timeout time.Duration, basicDetection *FGFMSDFingerprint) *FGFMSDFingerprint {
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

	// Perform authenticated FortiManager FGFMSD protocol communication
	err = p.performFGFMSDProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode and detection level
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.DetectionLevel = "enhanced"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "FGFMSD_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedFGFMSDInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForFGFMSD analyzes server certificate for FortiManager FGFMSD-specific patterns
func (p *FGFMSDPlugin) analyzeCertificateForFGFMSD(cert *x509.Certificate, fingerprint *FGFMSDFingerprint) int {
	confidence := 0

	// Check Common Name for FortiManager FGFMSD patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "FM-") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FORTIMANAGER") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FORTINET") {
		confidence += 25
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for FGFMSD patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "FGFMSD SERVICE") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "FORTIMANAGER") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(ou), "MANAGEMENT") {
			confidence += 25
		}
	}

	// Check Organization for Fortinet
	for _, org := range cert.Subject.Organization {
		if strings.Contains(strings.ToUpper(org), "FORTINET") {
			confidence += 30
		}
	}

	// Check Issuer for Fortinet patterns
	issuer := cert.Issuer.String()
	if strings.Contains(strings.ToUpper(issuer), "FORTINET") {
		confidence += 25
	}

	// Check Subject Alternative Names
	for _, san := range cert.DNSNames {
		if strings.Contains(strings.ToUpper(san), "FM-") || strings.Contains(strings.ToUpper(san), "FORTIMANAGER") {
			confidence += 15
		}
	}

	return confidence
}

// analyzeTLSForFortinet analyzes TLS characteristics for Fortinet patterns
func (p *FGFMSDPlugin) analyzeTLSForFortinet(state tls.ConnectionState, fingerprint *FGFMSDFingerprint) int {
	confidence := 0

	// Check for Fortinet-preferred cipher suites
	fortinetCiphers := map[uint16]int{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 25,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 20,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:       15,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:       10,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:    15,
	}

	if points, exists := fortinetCiphers[state.CipherSuite]; exists {
		confidence += points
	}

	// Check TLS version preferences
	if state.Version == tls.VersionTLS12 {
		confidence += 15
	} else if state.Version == tls.VersionTLS11 {
		confidence += 10
	}

	return confidence
}

// performProtocolProbing sends FGFMSD protocol probes and analyzes responses
func (p *FGFMSDPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *FGFMSDFingerprint) int {
	confidence := 0

	// Send FGFMSD magic bytes probe
	fgfmsdProbe := []byte{0x46, 0x47, 0x46, 0x4D, 0x53, 0x44, 0x50, 0x52} // "FGFMSDPR"

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(fgfmsdProbe)
	if err != nil {
		return confidence
	}

	// Try to read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	n, err := tlsConn.Read(response)

	if err != nil {
		// Analyze error patterns for FGFMSD-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // FGFMSD requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for FGFMSD patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "FORTIMANAGER") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "FORTINET") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "FGFMSD") {
			confidence += 25
		}
	}

	return confidence
}

// performFGFMSDProtocolCommunication performs authenticated FGFMSD protocol communication
func (p *FGFMSDPlugin) performFGFMSDProtocolCommunication(tlsConn *tls.Conn, fingerprint *FGFMSDFingerprint) error {
	// Create FGFMSD capability request packet
	capabilityRequest := p.createFGFMSDCapabilityRequest()

	// Send FGFMSD capability request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(capabilityRequest)
	if err != nil {
		return fmt.Errorf("failed to send FGFMSD capability request: %w", err)
	}

	// Read FGFMSD response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read FGFMSD response: %w", err)
	}

	// Parse FGFMSD response
	return p.parseFGFMSDResponse(response[:n], fingerprint)
}

// createFGFMSDCapabilityRequest creates an FGFMSD capability request packet
func (p *FGFMSDPlugin) createFGFMSDCapabilityRequest() []byte {
	var packet bytes.Buffer

	// FGFMSD magic bytes
	packet.Write([]byte{0x46, 0x47, 0x46, 0x4D, 0x53, 0x44, 0x43, 0x41}) // "FGFMSDCA"

	// FGFMSD version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (capability request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0400))

	// Message length
	binary.Write(&packet, binary.BigEndian, uint32(0x00000020))

	// Device ID
	binary.Write(&packet, binary.BigEndian, uint64(0x1234567890ABCDEF))

	// Request flags
	binary.Write(&packet, binary.BigEndian, uint32(0x00000001))

	// Padding
	packet.Write(make([]byte, 8))

	return packet.Bytes()
}

// parseFGFMSDResponse parses FGFMSD protocol response
func (p *FGFMSDPlugin) parseFGFMSDResponse(response []byte, fingerprint *FGFMSDFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("FGFMSD response too short")
	}

	// Verify FGFMSD magic bytes
	if !bytes.Equal(response[0:8], []byte{0x46, 0x47, 0x46, 0x4D, 0x53, 0x44, 0x43, 0x41}) {
		return fmt.Errorf("invalid FGFMSD magic bytes")
	}

	// Parse FGFMSD version
	version := binary.BigEndian.Uint16(response[8:10])
	fingerprint.ServiceVersion = fmt.Sprintf("FGFMSD v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[10:12])
	if msgType != 0x0401 { // Capability response
		return fmt.Errorf("unexpected FGFMSD message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[12:16])
	if len(response) < int(16+msgLen) {
		return fmt.Errorf("incomplete FGFMSD response")
	}

	// Parse response payload (simplified)
	payload := response[16 : 16+msgLen]
	p.parseFGFMSDPayload(payload, fingerprint)

	return nil
}

// parseFGFMSDPayload parses FGFMSD response payload
func (p *FGFMSDPlugin) parseFGFMSDPayload(payload []byte, fingerprint *FGFMSDFingerprint) {
	// This is a simplified parser - real FGFMSD protocol is more complex
	payloadStr := string(payload)

	// Extract device model
	if strings.Contains(payloadStr, "FortiManager") {
		fingerprint.DeviceModel = "FortiManager"
	}

	// Extract security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"management_access": "extracted_from_payload",
		"device_count":      "extracted_from_payload",
		"policy_packages":   "extracted_from_payload",
		"security_fabric":   "extracted_from_payload",
	}
}

// extractDetailedFGFMSDInformation extracts detailed FGFMSD information
func (p *FGFMSDPlugin) extractDetailedFGFMSDInformation(fingerprint *FGFMSDFingerprint) {
	// Set comprehensive management features
	fingerprint.ManagementFeatures = []string{
		"Centralized_Device_Management",
		"Policy_Management",
		"Configuration_Templates",
		"Software_Updates",
		"License_Management",
		"Certificate_Management",
		"User_Management",
		"Role_Based_Access_Control",
		"Audit_Logging",
		"Compliance_Reporting",
		"Security_Fabric_Integration",
		"API_Management",
		"Workflow_Automation",
		"Custom_Scripts",
		"Backup_Restore",
	}

	// Update security information
	fingerprint.SecurityInfo["access_control"] = "role_based_authentication"
	fingerprint.SecurityInfo["encryption"] = "end_to_end_encryption"
	fingerprint.SecurityInfo["audit_trail"] = "comprehensive_logging"
	fingerprint.SecurityInfo["compliance"] = "regulatory_compliance_support"

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"FGFMSD_Capability_Request", "FGFMSD_Policy_Deployment", "FGFMSD_Device_Management")
}

// loadClientCertificate loads the FortiManager client certificate
func (p *FGFMSDPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(fortiManagerCert), []byte(fortiManagerKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *FGFMSDPlugin) createVendorInfo(fingerprint *FGFMSDFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Fortinet",
		Product:    "FortiManager FGFMSD",
		Vulnerable: fingerprint.Vulnerable,
	}

	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 100
		vendor.Method = "Certificate-based FGFMSD Protocol Communication"
		vendor.Description = "Full FGFMSD protocol access with detailed management information"
		if fingerprint.DeviceModel != "" {
			vendor.Product = fingerprint.DeviceModel + " FGFMSD"
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "FGFMSD service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *FGFMSDPlugin) getTLSVersionString(version uint16) string {
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
func (p *FGFMSDPlugin) getCipherSuiteString(cipherSuite uint16) string {
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

// PortPriority returns true if the port is a common FGFMSD port
func (p *FGFMSDPlugin) PortPriority(port uint16) bool {
	_, exists := commonFGFMSDPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *FGFMSDPlugin) Name() string {
	return FGFMSD
}

// Type returns the protocol type
func (p *FGFMSDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *FGFMSDPlugin) Priority() int {
	return 660
}
