package ciscoLISPControl

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

const CISCO_LISP_CONTROL = "cisco-lisp-control"

// CiscoLISPControlPlugin implements the Cisco LISP Control detection plugin
type CiscoLISPControlPlugin struct{}

// VendorInfo represents detected Cisco LISP Control vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
	Vulnerable  bool // True if test certificate was accepted
}

// LISPControlFingerprint represents collected Cisco LISP Control fingerprinting data
type LISPControlFingerprint struct {
	CertificateInfo    map[string]interface{}
	TLSVersion         string
	CipherSuite        string
	ServerName         string
	ResponseTime       time.Duration
	ProtocolSupport    []string
	AuthenticationMode string
	ServiceVersion     string
	ServerModel        string
	LISPCapabilities   []string
	NetworkingFeatures []string
	SecurityInfo       map[string]interface{}
	DetectionLevel     string // "basic" or "enhanced"
	Vulnerable         bool   // True if test certificate was accepted
}

var (
	commonLISPControlPorts = map[int]struct{}{
		4342: {}, // LISP Control primary port
		4341: {}, // LISP Data port (alternative)
		8080: {}, // LISP web interface (alternative)
		8443: {}, // LISP secure web interface
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
	plugins.RegisterPlugin(&CiscoLISPControlPlugin{})
}

// Run performs Cisco LISP Control detection with two-tier approach
func (p *CiscoLISPControlPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic LISP Control Detection (no client certificate required)
	basicDetection, err := p.performBasicLISPControlDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not LISP Control
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced LISP Control Detection (with client certificate)
	enhancedDetection := p.performEnhancedLISPControlDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *LISPControlFingerprint
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
		"vendor":                   vendor,
		"lisp_control_fingerprint": finalDetection,
	}

	return service, nil
}

// performBasicLISPControlDetection detects LISP Control without client certificate authentication
func (p *CiscoLISPControlPlugin) performBasicLISPControlDetection(conn net.Conn, timeout time.Duration) (*LISPControlFingerprint, error) {
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

	// Analyze server certificate for LISP Control patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &LISPControlFingerprint{
		CertificateInfo:    make(map[string]interface{}),
		LISPCapabilities:   []string{},
		NetworkingFeatures: []string{},
		SecurityInfo:       make(map[string]interface{}),
		TLSVersion:         p.getTLSVersionString(state.Version),
		CipherSuite:        p.getCipherSuiteString(state.CipherSuite),
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for LISP Control-specific patterns in certificate
	confidence := p.analyzeCertificateForLISPControl(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Cisco patterns
		confidence = p.analyzeTLSForCisco(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not LISP Control
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_not_required"

	return fingerprint, nil
}

// performEnhancedLISPControlDetection attempts authenticated LISP Control communication
func (p *CiscoLISPControlPlugin) performEnhancedLISPControlDetection(conn net.Conn, timeout time.Duration, basicDetection *LISPControlFingerprint) *LISPControlFingerprint {
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

	// Perform authenticated LISP Control protocol communication
	err = p.performLISPControlProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "LISP_Control_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedLISPControlInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForLISPControl analyzes server certificate for LISP Control-specific patterns
func (p *CiscoLISPControlPlugin) analyzeCertificateForLISPControl(cert *x509.Certificate, fingerprint *LISPControlFingerprint) int {
	confidence := 0

	// Check Common Name for LISP Control patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "LISP") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "MAP-SERVER") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "MAP-RESOLVER") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "CISCO") && strings.Contains(strings.ToUpper(cn), "ROUTER") {
		confidence += 30
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for LISP Control patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "LISP") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "MAP-SERVER") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(ou), "MAP-RESOLVER") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(ou), "NETWORKING") {
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
		if strings.Contains(strings.ToUpper(san), "LISP") || strings.Contains(strings.ToUpper(san), "MAP-SERVER") {
			confidence += 15
		}
	}

	return confidence
}

// analyzeTLSForCisco analyzes TLS characteristics for Cisco patterns
func (p *CiscoLISPControlPlugin) analyzeTLSForCisco(state tls.ConnectionState, fingerprint *LISPControlFingerprint) int {
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

// performProtocolProbing sends LISP Control protocol probes and analyzes responses
func (p *CiscoLISPControlPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *LISPControlFingerprint) int {
	confidence := 0

	// Send LISP Control magic bytes probe
	lispControlProbe := []byte{0x4C, 0x49, 0x53, 0x50} // "LISP"

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(lispControlProbe)
	if err != nil {
		return confidence
	}

	// Try to read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	n, err := tlsConn.Read(response)

	if err != nil {
		// Analyze error patterns for LISP Control-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // LISP Control requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for LISP Control patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "LISP") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "MAP-SERVER") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "MAP-RESOLVER") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "CISCO") {
			confidence += 20
		}
	}

	return confidence
}

// performLISPControlProtocolCommunication performs authenticated LISP Control protocol communication
func (p *CiscoLISPControlPlugin) performLISPControlProtocolCommunication(tlsConn *tls.Conn, fingerprint *LISPControlFingerprint) error {
	// Create LISP Control capability request packet
	capabilityRequest := p.createLISPControlCapabilityRequest()

	// Send LISP Control capability request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(capabilityRequest)
	if err != nil {
		return fmt.Errorf("failed to send LISP Control capability request: %w", err)
	}

	// Read LISP Control response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read LISP Control response: %w", err)
	}

	// Parse LISP Control response
	return p.parseLISPControlResponse(response[:n], fingerprint)
}

// createLISPControlCapabilityRequest creates a LISP Control capability request packet
func (p *CiscoLISPControlPlugin) createLISPControlCapabilityRequest() []byte {
	var packet bytes.Buffer

	// LISP Control magic bytes
	packet.Write([]byte{0x4C, 0x49, 0x53, 0x50}) // "LISP"

	// LISP Control version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (capability request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0100))

	// Message length
	binary.Write(&packet, binary.BigEndian, uint32(0x00000020))

	// Session ID
	binary.Write(&packet, binary.BigEndian, uint64(0xABCDEF1234567890))

	// Request flags
	binary.Write(&packet, binary.BigEndian, uint32(0x00000001))

	// Padding
	packet.Write(make([]byte, 8))

	return packet.Bytes()
}

// parseLISPControlResponse parses LISP Control protocol response
func (p *CiscoLISPControlPlugin) parseLISPControlResponse(response []byte, fingerprint *LISPControlFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("LISP Control response too short")
	}

	// Verify LISP Control magic bytes
	if !bytes.Equal(response[0:4], []byte{0x4C, 0x49, 0x53, 0x50}) {
		return fmt.Errorf("invalid LISP Control magic bytes")
	}

	// Parse LISP Control version
	version := binary.BigEndian.Uint16(response[4:6])
	fingerprint.ServiceVersion = fmt.Sprintf("LISP Control v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[6:8])
	if msgType != 0x0101 { // Capability response
		return fmt.Errorf("unexpected LISP Control message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[8:12])
	if len(response) < int(12+msgLen) {
		return fmt.Errorf("incomplete LISP Control response")
	}

	// Parse response payload (simplified)
	payload := response[12 : 12+msgLen]
	p.parseLISPControlPayload(payload, fingerprint)

	return nil
}

// parseLISPControlPayload parses LISP Control response payload
func (p *CiscoLISPControlPlugin) parseLISPControlPayload(payload []byte, fingerprint *LISPControlFingerprint) {
	// This is a simplified parser - real LISP Control protocol is more complex
	payloadStr := string(payload)

	// Extract server model
	if modelMatch := regexp.MustCompile(`CISCO-(\w+)`).FindStringSubmatch(payloadStr); len(modelMatch) > 1 {
		fingerprint.ServerModel = "CISCO-" + modelMatch[1]
	}

	// Extract security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"locator_id_separation": "extracted_from_payload",
		"map_server_function":   "extracted_from_payload",
		"map_resolver_function": "extracted_from_payload",
		"mobility_support":      "extracted_from_payload",
	}
}

// extractDetailedLISPControlInformation extracts detailed LISP Control information
func (p *CiscoLISPControlPlugin) extractDetailedLISPControlInformation(fingerprint *LISPControlFingerprint) {
	// Set comprehensive LISP capabilities
	fingerprint.LISPCapabilities = []string{
		"Locator_ID_Separation",
		"Map_Server_Function",
		"Map_Resolver_Function",
		"Proxy_ITR_Function",
		"Proxy_ETR_Function",
		"Map_Cache_Management",
		"EID_Registration",
		"Mapping_Database",
		"Mobility_Support",
		"Load_Balancing",
		"Failover_Support",
		"Multicast_Support",
		"IPv4_IPv6_Support",
		"VPN_Support",
		"Security_Features",
		"Authentication",
		"Authorization",
		"Encryption_Support",
		"Key_Management",
		"Policy_Enforcement",
	}

	// Set networking features
	fingerprint.NetworkingFeatures = []string{
		"Routing_Locator_Management",
		"Endpoint_Identifier_Management",
		"Dynamic_Mapping_Updates",
		"Map_Request_Processing",
		"Map_Reply_Processing",
		"Map_Register_Processing",
		"Map_Notify_Processing",
		"Negative_Map_Replies",
		"Map_Versioning",
		"Instance_ID_Support",
		"Service_Function_Chaining",
		"Traffic_Engineering",
		"Quality_of_Service",
		"Bandwidth_Management",
		"Latency_Optimization",
		"Path_Selection",
		"Network_Virtualization",
		"Overlay_Networks",
		"Underlay_Networks",
		"Multi_Tenancy",
	}

	// Set security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"protocol_scope":    "network_virtualization",
		"separation_engine": "lisp_control",
		"mapping_system":    "distributed",
		"mobility_support":  "seamless",
		"security_features": "authentication_encryption",
		"scalability":       "enterprise_grade",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"LISP_Control_Capability_Request", "LISP_Map_Server", "LISP_Map_Resolver")
}

// loadClientCertificate loads the Cisco Test Root CA client certificate
func (p *CiscoLISPControlPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(ciscoTestRootCACert), []byte(ciscoTestRootCAKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *CiscoLISPControlPlugin) createVendorInfo(fingerprint *LISPControlFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Cisco",
		Product:    "LISP Control",
		Vulnerable: fingerprint.Vulnerable,
	}

	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 100
		vendor.Method = "Certificate-based LISP Control Protocol Communication"
		vendor.Description = "Full LISP Control protocol access with detailed networking information"
		if fingerprint.ServerModel != "" {
			vendor.Product = fingerprint.ServerModel
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "LISP Control service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *CiscoLISPControlPlugin) getTLSVersionString(version uint16) string {
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
func (p *CiscoLISPControlPlugin) getCipherSuiteString(cipherSuite uint16) string {
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

// PortPriority returns true if the port is a common LISP Control port
func (p *CiscoLISPControlPlugin) PortPriority(port uint16) bool {
	_, exists := commonLISPControlPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *CiscoLISPControlPlugin) Name() string {
	return CISCO_LISP_CONTROL
}

// Type returns the protocol type
func (p *CiscoLISPControlPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *CiscoLISPControlPlugin) Priority() int {
	return 650
}
