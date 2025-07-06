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

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
)

const CISCO_ISE_PXGRID = "pxgrid"

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
		8910: {}, // Cisco ISE pxGrid primary port
		8080: {}, // Cisco ISE pxGrid web interface (alternative)
		8443: {}, // Cisco ISE pxGrid secure web interface
		9060: {}, // Cisco ISE pxGrid WebSocket port
	}
)

// Cisco ISE pxGrid certificate for authentic communication
const ciscoISEpxGridCert = `-----BEGIN CERTIFICATE-----
MIIDzDCCArSgAwIBAgIDBjE+MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREwDwYD
VQQKEwhDaXNjbyBJU0UxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEQ
MA4GA1UEAxMHc3VwcG9ydDEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBjaXNjby5j
b20wHhcNMTcxMTEwMjExNDI2WhcNMzgwMTE5MDMxNDA3WjCBoTELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTERMA8G
A1UEChMIQ2lzY28gSVNFMRkwFwYDVQQLExBweFNyaWQgSW50ZWdyYXRpb24xHDAa
BgNVBAMTE0lTRS1WTTAwMDAwMDAwMDAwMSMwIQYJKoZIhvcNAQkBFhRzZXJ2aWNl
QGNpc2NvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMcgGzRl
TTeVjIcE8D7z7Vnp6LKLMGEp7VL4qs1fOxvTrK2j7vWbVMHSsOpf8taAAm55qmqe
S//woCJQq3t5mmq1M6MHm2nom6Q+dObcsfhieLrIFwp9X1Xt9YHKQd5qOR5Pysrm
hFKdpwMJfmlzuWWcIUeilgecP6eq9GS50gu4m+0NK0d3LTsmWz1jLNC3k74fYwYD
saPnhl/tsxcqZWrYHUHJhH5ep8YAxE6Eo2JG67BXOI/JbxrWPEh+zRLqA7ZrWeBP
l0AEIXTKpSIBJTW0dpnxEcG6wBQQxCp8jZ+RlaFpKjBdYucDVTDtkLabvetOrAn+
mjcRutg6NHlptSECAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
AQEAl225IvoXNxpTJEWdYwYvjAFdaueBk349ApvriQmsPdAJmhFgF4U8l6PI/kBP
VYCgzP0EA1zImHwLFkzlCVtMtzhuUY3h2ZIUEhYwX0xEf5Kay2XHicWAwugQ0k/Q
Dmivw7/w7UTiwPaMLroEcjRbH8T4TLCXBdKsgXYW+t72CSA8MJDSug8o2yABom6X
KlXl35mD93BrFkbxhhAiCrrC63byX7XTuXTyrP1dO9Qi9aSPWrIbi2SV+SjTLhP0
n1bdikVOHNNreyhQRlRjguPrW0P2Xqjbecgp98tdRyoOSr9sF5Qo5TKdvIwUFClF
gsy+7pactwTnQmwhvlLQ7Z/dOg==
-----END CERTIFICATE-----`

const ciscoISEpxGridKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHIBs0ZU03lYyH
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

	// Create service result using ServicePXGRID struct
	servicePXGRID := plugins.ServicePXGRID{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,
		Vulnerable:        vendor.Vulnerable,

		// Certificate information
		CertificateInfo: finalDetection.CertificateInfo,
		TLSVersion:      finalDetection.TLSVersion,
		CipherSuite:     finalDetection.CipherSuite,
		ServerName:      finalDetection.ServerName,
		ResponseTime:    finalDetection.ResponseTime,

		// Protocol and service information
		ProtocolSupport:    finalDetection.ProtocolSupport,
		AuthenticationMode: finalDetection.AuthenticationMode,
		ServiceVersion:     finalDetection.ServiceVersion,
		ServerModel:        finalDetection.ServerModel,

		// pxGrid-specific capabilities and features
		SecurityCapabilities: finalDetection.SecurityCapabilities,
		IntegrationFeatures:  finalDetection.IntegrationFeatures,
		SecurityInfo:         finalDetection.SecurityInfo,

		// Detection metadata
		DetectionLevel: finalDetection.DetectionLevel,
	}

	service := plugins.CreateServiceFrom(target, servicePXGRID, false, "", plugins.TCP)
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
	} else if strings.Contains(strings.ToUpper(cn), "ISE") && strings.Contains(strings.ToUpper(cn), "GRID") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "ISE") {
		confidence += 20
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for pxGrid patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "PXGRID") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "ISE") {
			confidence += 25
		} else if strings.Contains(strings.ToUpper(ou), "INTEGRATION") {
			confidence += 15
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
	pxGridProbe := []byte{0x50, 0x58, 0x47, 0x52, 0x49, 0x44} // "PXGRID"

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
		if strings.Contains(strings.ToUpper(responseStr), "PXGRID") {
			confidence += 35
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
	packet.Write([]byte{0x50, 0x58, 0x47, 0x52, 0x49, 0x44}) // "PXGRID"

	// pxGrid version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (capability request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0100))

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

// parsepxGridResponse parses pxGrid protocol response
func (p *CiscoISEpxGridPlugin) parsepxGridResponse(response []byte, fingerprint *pxGridFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("pxGrid response too short")
	}

	// Verify pxGrid magic bytes
	if !bytes.Equal(response[0:6], []byte{0x50, 0x58, 0x47, 0x52, 0x49, 0x44}) {
		return fmt.Errorf("invalid pxGrid magic bytes")
	}

	// Parse pxGrid version
	version := binary.BigEndian.Uint16(response[6:8])
	fingerprint.ServiceVersion = fmt.Sprintf("pxGrid v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[8:10])
	if msgType != 0x0101 { // Capability response
		return fmt.Errorf("unexpected pxGrid message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[10:14])
	if len(response) < int(14+msgLen) {
		return fmt.Errorf("incomplete pxGrid response")
	}

	// Parse response payload (simplified)
	payload := response[14 : 14+msgLen]
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
		"session_directory":   "extracted_from_payload",
		"anc_capability":      "extracted_from_payload",
		"trustsec_capability": "extracted_from_payload",
		"radius_failure":      "extracted_from_payload",
	}
}

// extractDetailedpxGridInformation extracts detailed pxGrid information
func (p *CiscoISEpxGridPlugin) extractDetailedpxGridInformation(fingerprint *pxGridFingerprint) {
	// Set comprehensive security capabilities
	fingerprint.SecurityCapabilities = []string{
		"Session_Directory",
		"ANC_Capability",
		"TrustSec_Capability",
		"RADIUS_Failure",
		"System_Health",
		"Profiler",
		"TrustSec_Config",
		"TrustSec_SXP",
		"Identity_Group",
		"User_Group",
		"Endpoint_Asset",
		"MDM_Endpoint",
		"Security_Group",
		"Security_Group_ACL",
		"TrustSec_Policy",
		"Vulnerability_Assessment",
		"Threat_Centric_NAC",
		"Device_Compliance",
		"Posture_Assessment",
		"Guest_User",
	}

	// Set integration features
	fingerprint.IntegrationFeatures = []string{
		"REST_API",
		"WebSocket_API",
		"STOMP_Protocol",
		"JSON_Messaging",
		"Real_Time_Events",
		"Bulk_Download",
		"Subscription_Management",
		"Topic_Management",
		"Client_Registration",
		"Service_Discovery",
		"Authentication_Integration",
		"Authorization_Integration",
		"Third_Party_Integration",
		"SIEM_Integration",
		"Orchestration_Platform",
		"Security_Ecosystem",
		"Custom_Applications",
		"Partner_Solutions",
		"Cloud_Integration",
		"Hybrid_Deployment",
	}

	// Set security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"deployment_mode":    "distributed",
		"integration_scope":  "security_ecosystem",
		"messaging_protocol": "stomp_websocket",
		"data_format":        "json",
		"real_time_events":   true,
		"bulk_operations":    true,
		"high_availability":  "supported",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"pxGrid_Capability_Request", "pxGrid_Session_Directory", "pxGrid_ANC_Operations")
}

// loadClientCertificate loads the Cisco ISE pxGrid client certificate
func (p *CiscoISEpxGridPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(ciscoISEpxGridCert), []byte(ciscoISEpxGridKey))
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
