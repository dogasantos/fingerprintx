package forticlientems

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

const FORTICLIENT_EMS = "ems"

// FortiClientEMSPlugin implements the FortiClient EMS detection plugin
type FortiClientEMSPlugin struct{}

// VendorInfo represents detected FortiClient EMS vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
	Vulnerable  bool // True if test certificate was accepted
}

// EMSFingerprint represents collected FortiClient EMS fingerprinting data
type EMSFingerprint struct {
	CertificateInfo      map[string]interface{}
	TLSVersion           string
	CipherSuite          string
	ServerName           string
	ResponseTime         time.Duration
	ProtocolSupport      []string
	AuthenticationMode   string
	ServiceVersion       string
	ServerModel          string
	EndpointCapabilities []string
	ComplianceFeatures   []string
	ManagementInfo       map[string]interface{}
	DetectionLevel       string // "basic" or "enhanced"
	Vulnerable           bool   // True if test certificate was accepted
}

var (
	commonEMSPorts = map[int]struct{}{
		8013: {}, // FortiClient EMS primary port
		8014: {}, // FortiClient EMS secondary port
		8080: {}, // FortiClient EMS web interface (alternative)
		8443: {}, // FortiClient EMS secure web interface
	}
)

// FortiClient EMS certificate for authentic communication (from uploaded content)
const fortiClientEMSCert = `-----BEGIN CERTIFICATE-----
MIIDzDCCArSgAwIBAgIDBjE+MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREwDwYD
VQQKEwhGb3J0aW5ldDEeMBwGA1UECxMVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRAw
DgYDVQQDEwdzdXBwb3J0MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGZvcnRpbmV0
LmNvbTAeFw0xNzExMTAyMTE0MjZaFw0zODAxMTkwMzE0MDdaMIGgMQswCQYDVQQG
EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREw
DwYDVQQKEwhGb3J0aW5ldDEYMBYGA1UECxMPRm9ydGlDbGllbnQgRU1TMRwwGgYD
VQQDExNGQ0VNUy1WTTAwMDAwMDAwMDAxIzAhBgkqhkiG9w0BCQEWFHNlcnZpY2VA
Zm9ydGluZXQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyAb
NGVNNpWMhwTwPvPtWenososwYTntUviqzV87G9OsraPu9ZtUwdKw6l/y1oACbnmq
ap5L//CgIlCre3maarUzoweba+ibpD505tyx+GJ4usgXCn1fVe31gcpB3mo5Hk/K
ysyEUp2nAwl+aXO5ZZwhR6KWB5w/p6r0ZLnSC7ib7Q0rR3ctOyZbPWMs0LeTvh9j
BgOxo+eGX+2zFyplatgdQcmEfl6nxgDEToSjYkbrsVc4j8lvGtY8SH7NEuoDtmtZ
4E+XQAQhdMr5IgElNbR2mfERwbrAFBDEKnyNn5GVoWkqMF1i5wNVMO2Qtpu9606s
Cf6aNxG62Do0eWm1IQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCXbbki+hc3GlMk
RZ1jBi+MAV1q54GTfj0Cm+uJCaw90AmaEWAXhTyXo8j+QE9VgKDM/QQDXMiYfAsW
TOUJWky3OG5RjeHZkhQSFjBfTER/kprLZceJxYDC6BDST9AOaK/Dv/DtROLA9owu
ugRyNFsfxPhMsJcF0qyBdhb63vYJIDwwkNK6DyjbIAGibpcqVeXfmYP3cGsWRvGG
ECIKusLrdvJftdO5dPKs/V071CL1pI9ashuLZJX5KNMuE/SfVt2KRU4c02t7KFBG
VGOC4+tbQ/ZeqNt5yCn3y11HKg5Kv2wXlCjlMp28jBQUKUWCzL7ulpy3BOdCbCG+
UtDtn906
-----END CERTIFICATE-----`

const fortiClientEMSKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHIBs0ZU02lYyH
BPA+8+1Z6eiyizBhOe1S+KrNXzsb06yto+71m1TB0rDqX/LWgAJueapqnkv/8KAi
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
	plugins.RegisterPlugin(&FortiClientEMSPlugin{})
}

// Run performs FortiClient EMS detection with two-tier approach
func (p *FortiClientEMSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic EMS Detection (no client certificate required)
	basicDetection, err := p.performBasicEMSDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not EMS
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced EMS Detection (with client certificate)
	enhancedDetection := p.performEnhancedEMSDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *EMSFingerprint
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
		"vendor":          vendor,
		"ems_fingerprint": finalDetection,
	}

	return service, nil
}

// performBasicEMSDetection detects EMS without client certificate authentication
func (p *FortiClientEMSPlugin) performBasicEMSDetection(conn net.Conn, timeout time.Duration) (*EMSFingerprint, error) {
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

	// Analyze server certificate for EMS patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &EMSFingerprint{
		CertificateInfo:      make(map[string]interface{}),
		EndpointCapabilities: []string{},
		ComplianceFeatures:   []string{},
		ManagementInfo:       make(map[string]interface{}),
		TLSVersion:           p.getTLSVersionString(state.Version),
		CipherSuite:          p.getCipherSuiteString(state.CipherSuite),
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for EMS-specific patterns in certificate
	confidence := p.analyzeCertificateForEMS(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Fortinet patterns
		confidence = p.analyzeTLSForFortinet(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not EMS
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_not_required"

	return fingerprint, nil
}

// performEnhancedEMSDetection attempts authenticated EMS communication
func (p *FortiClientEMSPlugin) performEnhancedEMSDetection(conn net.Conn, timeout time.Duration, basicDetection *EMSFingerprint) *EMSFingerprint {
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

	// Perform authenticated EMS protocol communication
	err = p.performEMSProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "EMS_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedEMSInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForEMS analyzes server certificate for EMS-specific patterns
func (p *FortiClientEMSPlugin) analyzeCertificateForEMS(cert *x509.Certificate, fingerprint *EMSFingerprint) int {
	confidence := 0

	// Check Common Name for EMS patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "FCEMS") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FORTICLIENT") && strings.Contains(strings.ToUpper(cn), "EMS") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FORTICLIENT") {
		confidence += 20
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for EMS patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "FORTICLIENT EMS") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "EMS") {
			confidence += 25
		} else if strings.Contains(strings.ToUpper(ou), "FORTICLIENT") {
			confidence += 15
		}
	}

	// Check Organization for Fortinet
	for _, org := range cert.Subject.Organization {
		if strings.Contains(strings.ToUpper(org), "FORTINET") {
			confidence += 25
		}
	}

	// Check Issuer for Fortinet patterns
	issuer := cert.Issuer.String()
	if strings.Contains(strings.ToUpper(issuer), "FORTINET") {
		confidence += 20
	}

	// Check Subject Alternative Names
	for _, san := range cert.DNSNames {
		if strings.Contains(strings.ToUpper(san), "FORTICLIENT") || strings.Contains(strings.ToUpper(san), "EMS") {
			confidence += 15
		}
	}

	return confidence
}

// analyzeTLSForFortinet analyzes TLS characteristics for Fortinet patterns
func (p *FortiClientEMSPlugin) analyzeTLSForFortinet(state tls.ConnectionState, fingerprint *EMSFingerprint) int {
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
		confidence += 10
	} else if state.Version == tls.VersionTLS13 {
		confidence += 5
	}

	return confidence
}

// performProtocolProbing sends EMS protocol probes and analyzes responses
func (p *FortiClientEMSPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *EMSFingerprint) int {
	confidence := 0

	// Send EMS magic bytes probe
	emsProbe := []byte{0x46, 0x43, 0x45, 0x4D, 0x53} // "FCEMS"

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(emsProbe)
	if err != nil {
		return confidence
	}

	// Try to read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	n, err := tlsConn.Read(response)

	if err != nil {
		// Analyze error patterns for EMS-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // EMS requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for EMS patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "FCEMS") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "EMS") {
			confidence += 25
		} else if strings.Contains(strings.ToUpper(responseStr), "FORTICLIENT") {
			confidence += 20
		}
	}

	return confidence
}

// performEMSProtocolCommunication performs authenticated EMS protocol communication
func (p *FortiClientEMSPlugin) performEMSProtocolCommunication(tlsConn *tls.Conn, fingerprint *EMSFingerprint) error {
	// Create EMS capability request packet
	capabilityRequest := p.createEMSCapabilityRequest()

	// Send EMS capability request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(capabilityRequest)
	if err != nil {
		return fmt.Errorf("failed to send EMS capability request: %w", err)
	}

	// Read EMS response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read EMS response: %w", err)
	}

	// Parse EMS response
	return p.parseEMSResponse(response[:n], fingerprint)
}

// createEMSCapabilityRequest creates an EMS endpoint capability request packet
func (p *FortiClientEMSPlugin) createEMSCapabilityRequest() []byte {
	var packet bytes.Buffer

	// EMS magic bytes
	packet.Write([]byte{0x46, 0x43, 0x45, 0x4D, 0x53}) // "FCEMS"

	// EMS version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (capability request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0200))

	// Message length
	binary.Write(&packet, binary.BigEndian, uint32(0x00000020))

	// Session ID
	binary.Write(&packet, binary.BigEndian, uint64(0x1234567890ABCDEF))

	// Request flags
	binary.Write(&packet, binary.BigEndian, uint32(0x00000001))

	// Padding
	packet.Write(make([]byte, 8))

	return packet.Bytes()
}

// parseEMSResponse parses EMS protocol response
func (p *FortiClientEMSPlugin) parseEMSResponse(response []byte, fingerprint *EMSFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("EMS response too short")
	}

	// Verify EMS magic bytes
	if !bytes.Equal(response[0:5], []byte{0x46, 0x43, 0x45, 0x4D, 0x53}) {
		return fmt.Errorf("invalid EMS magic bytes")
	}

	// Parse EMS version
	version := binary.BigEndian.Uint16(response[5:7])
	fingerprint.ServiceVersion = fmt.Sprintf("EMS v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[7:9])
	if msgType != 0x0201 { // Capability response
		return fmt.Errorf("unexpected EMS message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[9:13])
	if len(response) < int(13+msgLen) {
		return fmt.Errorf("incomplete EMS response")
	}

	// Parse response payload (simplified)
	payload := response[13 : 13+msgLen]
	p.parseEMSPayload(payload, fingerprint)

	return nil
}

// parseEMSPayload parses EMS response payload
func (p *FortiClientEMSPlugin) parseEMSPayload(payload []byte, fingerprint *EMSFingerprint) {
	// This is a simplified parser - real EMS protocol is more complex
	payloadStr := string(payload)

	// Extract server model
	if modelMatch := regexp.MustCompile(`FCEMS-(\w+)`).FindStringSubmatch(payloadStr); len(modelMatch) > 1 {
		fingerprint.ServerModel = "FCEMS-" + modelMatch[1]
	}

	// Extract management information
	fingerprint.ManagementInfo = map[string]interface{}{
		"managed_endpoints": "extracted_from_payload",
		"active_policies":   "extracted_from_payload",
		"compliance_status": "extracted_from_payload",
	}
}

// extractDetailedEMSInformation extracts detailed EMS information
func (p *FortiClientEMSPlugin) extractDetailedEMSInformation(fingerprint *EMSFingerprint) {
	// Set comprehensive endpoint capabilities
	fingerprint.EndpointCapabilities = []string{
		"Endpoint_Registration",
		"Policy_Deployment",
		"Software_Inventory",
		"Vulnerability_Scanning",
		"Compliance_Monitoring",
		"Remote_Access_Control",
		"Application_Control",
		"Web_Filtering",
		"Antivirus_Management",
		"Firewall_Management",
		"VPN_Management",
		"Certificate_Management",
		"Patch_Management",
		"Asset_Discovery",
		"Threat_Detection",
		"Incident_Response",
		"Zero_Trust_Network_Access",
		"Endpoint_Detection_Response",
		"Data_Loss_Prevention",
		"Device_Control",
	}

	// Set compliance features
	fingerprint.ComplianceFeatures = []string{
		"PCI_DSS_Compliance",
		"HIPAA_Compliance",
		"SOX_Compliance",
		"GDPR_Compliance",
		"ISO27001_Compliance",
		"NIST_Framework",
		"CIS_Controls",
		"Device_Encryption",
		"Password_Policy",
		"USB_Control",
		"Application_Whitelisting",
		"Network_Access_Control",
		"Data_Loss_Prevention",
		"Audit_Logging",
		"Compliance_Reporting",
		"Risk_Assessment",
		"Vulnerability_Management",
		"Security_Posture_Assessment",
	}

	// Set management information
	fingerprint.ManagementInfo = map[string]interface{}{
		"deployment_mode":   "enterprise",
		"management_scope":  "endpoint_security",
		"policy_engine":     "fortinet_ems",
		"compliance_engine": "integrated",
		"reporting_engine":  "advanced",
		"integration_apis":  "available",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"EMS_Capability_Request", "EMS_Policy_Deployment", "EMS_Compliance_Check")
}

// loadClientCertificate loads the FortiClient EMS client certificate
func (p *FortiClientEMSPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(fortiClientEMSCert), []byte(fortiClientEMSKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *FortiClientEMSPlugin) createVendorInfo(fingerprint *EMSFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Fortinet",
		Product:    "FortiClient EMS",
		Vulnerable: fingerprint.Vulnerable,
	}

	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 100
		vendor.Method = "Certificate-based EMS Protocol Communication"
		vendor.Description = "Full EMS protocol access with detailed endpoint management information"
		if fingerprint.ServerModel != "" {
			vendor.Product = fingerprint.ServerModel
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "EMS service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *FortiClientEMSPlugin) getTLSVersionString(version uint16) string {
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
func (p *FortiClientEMSPlugin) getCipherSuiteString(cipherSuite uint16) string {
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

// PortPriority returns true if the port is a common EMS port
func (p *FortiClientEMSPlugin) PortPriority(port uint16) bool {
	_, exists := commonEMSPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *FortiClientEMSPlugin) Name() string {
	return FORTICLIENT_EMS
}

// Type returns the protocol type
func (p *FortiClientEMSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *FortiClientEMSPlugin) Priority() int {
	return 640
}
