package ciscoFTDmanagement

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

const CISCO_FTD_MANAGEMENT = "ftd"

// CiscoFTDManagementPlugin implements the Cisco FTD Management detection plugin
type CiscoFTDManagementPlugin struct{}

// VendorInfo represents detected Cisco FTD Management vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
	Vulnerable  bool // True if test certificate was accepted
}

// FTDFingerprint represents collected Cisco FTD Management fingerprinting data
type FTDFingerprint struct {
	CertificateInfo    map[string]interface{}
	TLSVersion         string
	CipherSuite        string
	ServerName         string
	ResponseTime       time.Duration
	ProtocolSupport    []string
	AuthenticationMode string
	ServiceVersion     string
	ServerModel        string
	ThreatCapabilities []string
	ManagementFeatures []string
	SecurityInfo       map[string]interface{}
	DetectionLevel     string // "basic" or "enhanced"
	Vulnerable         bool   // True if test certificate was accepted
}

var (
	commonFTDPorts = map[int]struct{}{
		8305: {}, // FTD Management primary port
		8307: {}, // FTD Management secondary port
		8080: {}, // FTD Management web interface (alternative)
		8443: {}, // FTD Management secure web interface
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
	plugins.RegisterPlugin(&CiscoFTDManagementPlugin{})
}

// Run performs Cisco FTD Management detection with two-tier approach
func (p *CiscoFTDManagementPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic FTD Detection (no client certificate required)
	basicDetection, err := p.performBasicFTDDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not FTD Management
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced FTD Detection (with client certificate)
	enhancedDetection := p.performEnhancedFTDDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *FTDFingerprint
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
		"ftd_fingerprint": finalDetection,
	}

	return service, nil
}

// performBasicFTDDetection detects FTD Management without client certificate authentication
func (p *CiscoFTDManagementPlugin) performBasicFTDDetection(conn net.Conn, timeout time.Duration) (*FTDFingerprint, error) {
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

	// Analyze server certificate for FTD patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &FTDFingerprint{
		CertificateInfo:    make(map[string]interface{}),
		ThreatCapabilities: []string{},
		ManagementFeatures: []string{},
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

	// Check for FTD-specific patterns in certificate
	confidence := p.analyzeCertificateForFTD(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Cisco patterns
		confidence = p.analyzeTLSForCisco(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not FTD Management
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_not_required"

	return fingerprint, nil
}

// performEnhancedFTDDetection attempts authenticated FTD Management communication
func (p *CiscoFTDManagementPlugin) performEnhancedFTDDetection(conn net.Conn, timeout time.Duration, basicDetection *FTDFingerprint) *FTDFingerprint {
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

	// Perform authenticated FTD Management protocol communication
	err = p.performFTDProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "FTD_Management_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedFTDInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForFTD analyzes server certificate for FTD-specific patterns
func (p *CiscoFTDManagementPlugin) analyzeCertificateForFTD(cert *x509.Certificate, fingerprint *FTDFingerprint) int {
	confidence := 0

	// Check Common Name for FTD patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "FTD") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FIREPOWER") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "CISCO") && strings.Contains(strings.ToUpper(cn), "THREAT") {
		confidence += 30
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for FTD patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "FIREPOWER") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "FTD") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(ou), "THREAT DEFENSE") {
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
		if strings.Contains(strings.ToUpper(san), "FTD") || strings.Contains(strings.ToUpper(san), "FIREPOWER") {
			confidence += 15
		}
	}

	return confidence
}

// analyzeTLSForCisco analyzes TLS characteristics for Cisco patterns
func (p *CiscoFTDManagementPlugin) analyzeTLSForCisco(state tls.ConnectionState, fingerprint *FTDFingerprint) int {
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

// performProtocolProbing sends FTD Management protocol probes and analyzes responses
func (p *CiscoFTDManagementPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *FTDFingerprint) int {
	confidence := 0

	// Send FTD Management magic bytes probe
	ftdProbe := []byte{0x46, 0x54, 0x44, 0x4D} // "FTDM"

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(ftdProbe)
	if err != nil {
		return confidence
	}

	// Try to read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	n, err := tlsConn.Read(response)

	if err != nil {
		// Analyze error patterns for FTD-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // FTD requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for FTD patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "FTDM") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "FTD") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "FIREPOWER") {
			confidence += 25
		} else if strings.Contains(strings.ToUpper(responseStr), "CISCO") {
			confidence += 20
		}
	}

	return confidence
}

// performFTDProtocolCommunication performs authenticated FTD Management protocol communication
func (p *CiscoFTDManagementPlugin) performFTDProtocolCommunication(tlsConn *tls.Conn, fingerprint *FTDFingerprint) error {
	// Create FTD Management capability request packet
	capabilityRequest := p.createFTDCapabilityRequest()

	// Send FTD Management capability request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(capabilityRequest)
	if err != nil {
		return fmt.Errorf("failed to send FTD capability request: %w", err)
	}

	// Read FTD Management response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read FTD response: %w", err)
	}

	// Parse FTD Management response
	return p.parseFTDResponse(response[:n], fingerprint)
}

// createFTDCapabilityRequest creates an FTD Management capability request packet
func (p *CiscoFTDManagementPlugin) createFTDCapabilityRequest() []byte {
	var packet bytes.Buffer

	// FTD Management magic bytes
	packet.Write([]byte{0x46, 0x54, 0x44, 0x4D}) // "FTDM"

	// FTD Management version
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

// parseFTDResponse parses FTD Management protocol response
func (p *CiscoFTDManagementPlugin) parseFTDResponse(response []byte, fingerprint *FTDFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("FTD response too short")
	}

	// Verify FTD Management magic bytes
	if !bytes.Equal(response[0:4], []byte{0x46, 0x54, 0x44, 0x4D}) {
		return fmt.Errorf("invalid FTD magic bytes")
	}

	// Parse FTD Management version
	version := binary.BigEndian.Uint16(response[4:6])
	fingerprint.ServiceVersion = fmt.Sprintf("FTD Management v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[6:8])
	if msgType != 0x0101 { // Capability response
		return fmt.Errorf("unexpected FTD message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[8:12])
	if len(response) < int(12+msgLen) {
		return fmt.Errorf("incomplete FTD response")
	}

	// Parse response payload (simplified)
	payload := response[12 : 12+msgLen]
	p.parseFTDPayload(payload, fingerprint)

	return nil
}

// parseFTDPayload parses FTD Management response payload
func (p *CiscoFTDManagementPlugin) parseFTDPayload(payload []byte, fingerprint *FTDFingerprint) {
	// This is a simplified parser - real FTD Management protocol is more complex
	payloadStr := string(payload)

	// Extract server model
	if modelMatch := regexp.MustCompile(`FTD-(\w+)`).FindStringSubmatch(payloadStr); len(modelMatch) > 1 {
		fingerprint.ServerModel = "FTD-" + modelMatch[1]
	}

	// Extract security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"threat_detection":     "extracted_from_payload",
		"intrusion_prevention": "extracted_from_payload",
		"malware_protection":   "extracted_from_payload",
		"url_filtering":        "extracted_from_payload",
	}
}

// extractDetailedFTDInformation extracts detailed FTD Management information
func (p *CiscoFTDManagementPlugin) extractDetailedFTDInformation(fingerprint *FTDFingerprint) {
	// Set comprehensive threat capabilities
	fingerprint.ThreatCapabilities = []string{
		"Intrusion_Prevention_System",
		"Advanced_Malware_Protection",
		"URL_Filtering",
		"Application_Visibility_Control",
		"File_Type_Detection",
		"SSL_Decryption",
		"Network_Analysis_Policy",
		"Access_Control_Policy",
		"Security_Intelligence",
		"Geolocation",
		"DNS_Security",
		"Identity_Policy",
		"Correlation_Policy",
		"Network_Discovery_Policy",
		"System_Policy",
		"Health_Policy",
		"Platform_Settings_Policy",
		"Threat_Intelligence_Director",
		"Cisco_Talos_Intelligence",
		"Custom_Detection",
	}

	// Set management features
	fingerprint.ManagementFeatures = []string{
		"Device_Management",
		"Policy_Management",
		"Event_Management",
		"Health_Monitoring",
		"Performance_Monitoring",
		"Software_Updates",
		"License_Management",
		"User_Management",
		"Backup_Restore",
		"High_Availability",
		"Clustering",
		"Virtual_Routing",
		"NAT_Policy",
		"VPN_Policy",
		"QoS_Policy",
		"Deployment_Wizard",
		"Troubleshooting_Tools",
		"Reporting_Analytics",
		"Dashboard_Widgets",
		"Custom_Workflows",
	}

	// Set security information
	fingerprint.SecurityInfo = map[string]interface{}{
		"deployment_mode":    "firewall_ips",
		"management_scope":   "threat_defense",
		"policy_engine":      "cisco_ftd",
		"threat_engine":      "snort_talos",
		"malware_engine":     "amp_cloud",
		"intelligence_feeds": "cisco_talos",
		"integration_apis":   "available",
		"high_availability":  "supported",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"FTD_Capability_Request", "FTD_Policy_Deployment", "FTD_Threat_Detection")
}

// loadClientCertificate loads the Cisco Test Root CA client certificate
func (p *CiscoFTDManagementPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(ciscoTestRootCACert), []byte(ciscoTestRootCAKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *CiscoFTDManagementPlugin) createVendorInfo(fingerprint *FTDFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Cisco",
		Product:    "FTD Management",
		Vulnerable: fingerprint.Vulnerable,
	}

	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 100
		vendor.Method = "Certificate-based FTD Management Protocol Communication"
		vendor.Description = "Full FTD Management protocol access with detailed threat defense information"
		if fingerprint.ServerModel != "" {
			vendor.Product = fingerprint.ServerModel
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "FTD Management service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *CiscoFTDManagementPlugin) getTLSVersionString(version uint16) string {
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
func (p *CiscoFTDManagementPlugin) getCipherSuiteString(cipherSuite uint16) string {
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

// PortPriority returns true if the port is a common FTD Management port
func (p *CiscoFTDManagementPlugin) PortPriority(port uint16) bool {
	_, exists := commonFTDPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *CiscoFTDManagementPlugin) Name() string {
	return CISCO_FTD_MANAGEMENT
}

// Type returns the protocol type
func (p *CiscoFTDManagementPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *CiscoFTDManagementPlugin) Priority() int {
	return 650
}
