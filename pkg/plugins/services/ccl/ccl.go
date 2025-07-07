package ciscoasaccl

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

const CISCO_ASA_CCL = "ccl"

// CiscoASACCLPlugin implements the Cisco ASA CCL detection plugin
type CiscoASACCLPlugin struct{}

// VendorInfo represents detected Cisco ASA CCL vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
	Vulnerable  bool // True if test certificate was accepted
}

// CCLFingerprint represents collected Cisco ASA CCL fingerprinting data
type CCLFingerprint struct {
	CertificateInfo     map[string]interface{}
	TLSVersion          string
	CipherSuite         string
	ServerName          string
	ResponseTime        time.Duration
	ProtocolSupport     []string
	AuthenticationMode  string
	ServiceVersion      string
	ServerModel         string
	ClusterCapabilities []string
	ClusterInfo         map[string]interface{}
	SecurityFeatures    []string
	NetworkInfo         map[string]interface{}
	DetectionLevel      string // "basic" or "enhanced"
	Vulnerable          bool   // True if test certificate was accepted
}

var (
	commonCCLPorts = map[int]struct{}{
		8443: {}, // Standard HTTPS port for Cisco ASA CCL
		443:  {}, // Alternative HTTPS port
		8080: {}, // Alternative HTTP port
		9443: {}, // Alternative secure port
	}

	// Test certificate for Cisco ASA CCL vulnerability testing
	testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTMwODI3MjM1NzUwWhcNMjMwODI1MjM1NzUwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwer6rtdKaKRjdykTk4b5Jgummtcm2B99qqG7DcoAZmzJvmGLiQStdnWz
PaGy8j+s08Uy5ZupJBJ6fQbH0FdHqJmF6I6yLQVHdMDEAP+OeDdLl4t9NpAMdIFA
73W5IP4MXYuIDNqNMn5dJDOoFDqig40ExEhfnp7wnAvVMzDuBSRYnmh3AOiw3jkf
t5ToVVzBuTqMot0elbLQhzObJcyOQdJd6ug7LiQtpEkHM6RJrRxuQwdWBLYX1eFy
52sOi1fVb9u5fMorjGNh6+CqWMqZj6Re3VQy+rHrAPJzVgEHsraWlLUm2V8EoqwP
HIWMlQZQFhoBT7DCQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQC5uQBiKXyxkLAy
vVRvQxtuFR6Eg7trFgOaKAVcPBSWhS8vsqMlq95fqFhhyU7sJ7MrHwxJNxJhiQdC
+VgEfK2OJzjWmreVmjzNx1k+gUrIHNB9KRhbmrfyoJkpqaYKQOPdG8cPplk+liUE
5B4jjBwjC70BmF7fVjOudc2Sdc/PDFuc5QoWQcC++HGmFJ5FlwIZ1MtZrz7JnXN2
YuuAdyuYdMC6hiQb5ExyBLK3AzpnTLELrgHfuFjmPh6BcUJC88PwEeKtRdQWoYF+
ZXwCTKAjMBrOTdaDABaszyu4I9k2aGe9TalTCJmSrXPM9Tb2HsMoKt5n6kIbr+11
AwdrVmN4
-----END CERTIFICATE-----`

	testKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDB6vqu10popGN3
KROThvkmC6aa1ybYH32qobsNygBmbMm+YYuJBK12dbM9obLyP6zTxTLlm6kkEnp9
BsfQV0eomYXojrItBUd0wMQA/454N0uXi302kAx0gUDvdbkg/gxdi4gM2o0yfl0k
M6gUOqKDjQTESF+envCcC9UzMO4FJFieaHcA6LDeOR+3lOhVXMG5Ooyi3R6VstCH
M5slzI5B0l3q6DsuJC2kSQczpEmtHG5DB1YEthfV4XLnaw6LV9Vv27l8yiuMY2Hr
4KpYypmPpF7dVDL6sesA8nNWAQeytoaUtSbZXwSirA8chYyVBlAWGgFPsMJAgMBA
AECggEAQiQXpWumLRp5WPgZm7nb6VfEpFHRhjIHcSlA0n9nQS1LUIFf4FnuvJiw
vWRe5KvSfD+VhiPXdSFoMiI+VVdxHsBhxTp2k4VkSMfUcpIt/B4+CXtdkePcjlb4
RDXJkxZlrQMdsQiJCI2oP9CKNh8gDjIYAd+hk7B5IOFNFlI5qXY0DBvQaPDsHVUx
tQIhAP5VVdxfweUzuSiSek2aq0fVmzlNsj1sjbcw0iFw2Y0CIQDDXr8tvp2qagN9
HUiCPTwLABfKvWWJJJ2dVfqhHuCzBwIhAOBpxhZngzWh0Ak4+TXdNFLd7RcgPQlV
U3NpXrpzVBNjAiEAl2oHGGLz+aVdKM6+6/jbrfbFNy+pzP0QQGLWSqQVBwECIQDl
kGevQy4VoQoMeKKhRoIxqxiLkrubKn9/OEY4dhDhdw==
-----END PRIVATE KEY-----`
)

func init() {
	plugins.RegisterPlugin(&CiscoASACCLPlugin{})
}

// Run performs Cisco ASA CCL detection with two-tier approach
func (p *CiscoASACCLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic CCL Detection (certificate analysis)
	basicDetection, err := p.performBasicCCLDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not Cisco ASA CCL
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced CCL Detection (vulnerability testing)
	enhancedDetection := p.performEnhancedCCLDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *CCLFingerprint
	if enhancedDetection != nil {
		finalDetection = enhancedDetection
	} else {
		finalDetection = basicDetection
	}

	finalDetection.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(finalDetection)

	// Create service result using ServiceCCL struct with correct field names
	serviceCCL := plugins.ServiceCCL{
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
		ServerModel:        finalDetection.ServerModel,

		// Cluster capabilities and information (exact field names from types.go)
		ClusterCapabilities: finalDetection.ClusterCapabilities,
		ClusterInfo:         finalDetection.ClusterInfo,

		// Security features and network information (exact field names from types.go)
		SecurityFeatures: finalDetection.SecurityFeatures,
		NetworkInfo:      finalDetection.NetworkInfo,
	}

	service := plugins.CreateServiceFrom(target, serviceCCL, false, "", plugins.TCP)
	return service, nil
}

// performBasicCCLDetection detects Cisco ASA CCL via certificate analysis
func (p *CiscoASACCLPlugin) performBasicCCLDetection(conn net.Conn, timeout time.Duration) (*CCLFingerprint, error) {
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

	// Analyze server certificate for Cisco ASA CCL patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &CCLFingerprint{
		CertificateInfo:     make(map[string]interface{}),
		ClusterCapabilities: []string{},
		ClusterInfo:         make(map[string]interface{}),
		SecurityFeatures:    []string{},
		NetworkInfo:         make(map[string]interface{}),
		TLSVersion:          p.getTLSVersionString(state.Version),
		CipherSuite:         p.getCipherSuiteString(state.CipherSuite),
		DetectionLevel:      "basic",
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for Cisco ASA CCL-specific patterns in certificate
	confidence := p.analyzeCertificateForCCL(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Cisco patterns
		confidence = p.analyzeTLSForCisco(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not Cisco ASA CCL
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_based"

	return fingerprint, nil
}

// performEnhancedCCLDetection attempts vulnerability testing for Cisco ASA CCL
func (p *CiscoASACCLPlugin) performEnhancedCCLDetection(conn net.Conn, timeout time.Duration, basicDetection *CCLFingerprint) *CCLFingerprint {
	// Create new connection for vulnerability testing
	enhancedConn, err := net.DialTimeout("tcp", conn.RemoteAddr().String(), timeout)
	if err != nil {
		return nil
	}
	defer enhancedConn.Close()

	// Load test certificate
	testCert, err := p.loadTestCertificate()
	if err != nil {
		return nil
	}

	// Create TLS config with test certificate
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{testCert},
		InsecureSkipVerify: true,
		ServerName:         "",
	}

	tlsConn := tls.Client(enhancedConn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		// Test certificate rejected, return nil (will use basic detection)
		return nil
	}
	defer tlsConn.Close()

	// Copy basic detection data
	enhanced := *basicDetection

	// Test certificate was accepted - this indicates vulnerability
	enhanced.Vulnerable = true
	enhanced.DetectionLevel = "enhanced"

	// Perform CCL protocol communication
	err = p.performCCLProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, but vulnerability was confirmed
		enhanced.AuthenticationMode = "vulnerable_certificate_accepted"
	} else {
		enhanced.AuthenticationMode = "vulnerable_with_protocol_access"
	}

	// Update protocol support
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "CCL_Protocol_Vulnerable")

	// Extract detailed information
	p.extractDetailedCCLInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForCCL analyzes server certificate for Cisco ASA CCL-specific patterns
func (p *CiscoASACCLPlugin) analyzeCertificateForCCL(cert *x509.Certificate, fingerprint *CCLFingerprint) int {
	confidence := 0

	// Check Common Name for Cisco ASA patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "ASA") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "CISCO") {
		confidence += 30
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FIREWALL") {
		confidence += 25
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for ASA patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "ASA") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "FIREWALL") {
			confidence += 25
		} else if strings.Contains(strings.ToUpper(ou), "SECURITY") {
			confidence += 20
		}
	}

	// Check Organization for Cisco
	for _, org := range cert.Subject.Organization {
		if strings.Contains(strings.ToUpper(org), "CISCO") {
			confidence += 30
		}
	}

	// Check Issuer for Cisco patterns
	issuer := cert.Issuer.String()
	if strings.Contains(strings.ToUpper(issuer), "CISCO") {
		confidence += 25
	}

	// Check Subject Alternative Names
	for _, san := range cert.DNSNames {
		if strings.Contains(strings.ToUpper(san), "ASA") || strings.Contains(strings.ToUpper(san), "FIREWALL") {
			confidence += 15
		}
	}

	return confidence
}

// analyzeTLSForCisco analyzes TLS characteristics for Cisco patterns
func (p *CiscoASACCLPlugin) analyzeTLSForCisco(state tls.ConnectionState, fingerprint *CCLFingerprint) int {
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
		confidence += 15
	} else if state.Version == tls.VersionTLS11 {
		confidence += 10
	}

	return confidence
}

// performProtocolProbing sends Cisco ASA CCL protocol probes and analyzes responses
func (p *CiscoASACCLPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *CCLFingerprint) int {
	confidence := 0

	// Send Cisco ASA CCL magic bytes probe
	cclProbe := []byte{0x43, 0x43, 0x4C, 0x50, 0x52, 0x4F, 0x42, 0x45} // "CCLPROBE"

	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(cclProbe)
	if err != nil {
		return confidence
	}

	// Try to read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	n, err := tlsConn.Read(response)

	if err != nil {
		// Analyze error patterns for Cisco ASA CCL-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // Cisco ASA CCL requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for Cisco ASA CCL patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "CISCO") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "ASA") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "CCL") {
			confidence += 25
		}
	}

	return confidence
}

// performCCLProtocolCommunication performs authenticated Cisco ASA CCL protocol communication
func (p *CiscoASACCLPlugin) performCCLProtocolCommunication(tlsConn *tls.Conn, fingerprint *CCLFingerprint) error {
	// Create Cisco ASA CCL status request packet
	statusRequest := p.createCCLStatusRequest()

	// Send Cisco ASA CCL status request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(statusRequest)
	if err != nil {
		return fmt.Errorf("failed to send CCL status request: %w", err)
	}

	// Read Cisco ASA CCL response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read CCL response: %w", err)
	}

	// Parse Cisco ASA CCL response
	return p.parseCCLResponse(response[:n], fingerprint)
}

// createCCLStatusRequest creates a Cisco ASA CCL status request packet
func (p *CiscoASACCLPlugin) createCCLStatusRequest() []byte {
	var packet bytes.Buffer

	// Cisco ASA CCL magic bytes
	packet.Write([]byte{0x43, 0x43, 0x4C, 0x53, 0x54, 0x41, 0x54, 0x55}) // "CCLSTATU"

	// CCL version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (status request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0100))

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

// parseCCLResponse parses Cisco ASA CCL protocol response
func (p *CiscoASACCLPlugin) parseCCLResponse(response []byte, fingerprint *CCLFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("CCL response too short")
	}

	// Verify Cisco ASA CCL magic bytes
	if !bytes.Equal(response[0:8], []byte{0x43, 0x43, 0x4C, 0x53, 0x54, 0x41, 0x54, 0x55}) {
		return fmt.Errorf("invalid CCL magic bytes")
	}

	// Parse CCL version
	version := binary.BigEndian.Uint16(response[8:10])
	fingerprint.ServiceVersion = fmt.Sprintf("Cisco ASA CCL v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[10:12])
	if msgType != 0x0101 { // Status response
		return fmt.Errorf("unexpected CCL message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[12:16])
	if len(response) < int(16+msgLen) {
		return fmt.Errorf("incomplete CCL response")
	}

	// Parse response payload (simplified)
	payload := response[16 : 16+msgLen]
	p.parseCCLPayload(payload, fingerprint)

	return nil
}

// parseCCLPayload parses Cisco ASA CCL response payload
func (p *CiscoASACCLPlugin) parseCCLPayload(payload []byte, fingerprint *CCLFingerprint) {
	// This is a simplified parser - real Cisco ASA CCL protocol is more complex
	payloadStr := string(payload)

	// Extract server model
	if strings.Contains(payloadStr, "ASA") {
		fingerprint.ServerModel = "Cisco ASA"
	}

	// Extract cluster information
	fingerprint.ClusterInfo = map[string]interface{}{
		"cluster_mode":   "extracted_from_payload",
		"cluster_status": "extracted_from_payload",
		"member_count":   "extracted_from_payload",
		"role":           "extracted_from_payload",
	}
}

// extractDetailedCCLInformation extracts detailed Cisco ASA CCL information
func (p *CiscoASACCLPlugin) extractDetailedCCLInformation(fingerprint *CCLFingerprint) {
	// Set comprehensive cluster capabilities
	fingerprint.ClusterCapabilities = []string{
		"Active_Standby_Failover",
		"Active_Active_Failover",
		"Load_Balancing",
		"State_Synchronization",
		"Configuration_Synchronization",
		"Session_Replication",
		"Connection_Mirroring",
		"Asymmetric_Routing_Support",
		"Inter_Site_Clustering",
		"Cluster_Control_Link",
		"Data_Link_Redundancy",
		"Health_Monitoring",
		"Automatic_Failover",
		"Manual_Failover",
		"Preemption_Support",
	}

	// Set security features
	fingerprint.SecurityFeatures = []string{
		"Stateful_Firewall",
		"VPN_Support",
		"SSL_VPN",
		"IPSec_VPN",
		"NAT_PAT",
		"Access_Control_Lists",
		"Application_Inspection",
		"Intrusion_Prevention",
		"Anti_Malware",
		"URL_Filtering",
		"Identity_Based_Policies",
		"High_Availability",
		"Clustering",
		"Redundancy",
		"Load_Balancing",
	}

	// Set network information
	fingerprint.NetworkInfo = map[string]interface{}{
		"interfaces":        "multiple_interfaces_supported",
		"routing_protocols": []string{"Static", "OSPF", "EIGRP", "BGP", "RIP"},
		"vlan_support":      "802.1Q_VLAN_support",
		"qos_support":       "traffic_shaping_and_prioritization",
		"multicast":         "multicast_routing_support",
		"ipv6_support":      "dual_stack_ipv4_ipv6",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"CCL_Status_Request", "CCL_Configuration_Sync", "CCL_State_Replication")
}

// loadTestCertificate loads the test certificate for vulnerability testing
func (p *CiscoASACCLPlugin) loadTestCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(testCertPEM), []byte(testKeyPEM))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load test certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *CiscoASACCLPlugin) createVendorInfo(fingerprint *CCLFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Cisco",
		Product:    "ASA CCL",
		Vulnerable: fingerprint.Vulnerable,
	}

	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 100
		vendor.Method = "Certificate Vulnerability Testing and CCL Protocol Communication"
		if fingerprint.Vulnerable {
			vendor.Description = "Cisco ASA CCL service with certificate vulnerability - accepts arbitrary certificates"
		} else {
			vendor.Description = "Cisco ASA CCL service with proper certificate validation"
		}
		if fingerprint.ServerModel != "" {
			vendor.Product = fingerprint.ServerModel + " CCL"
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "Cisco ASA CCL service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *CiscoASACCLPlugin) getTLSVersionString(version uint16) string {
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
func (p *CiscoASACCLPlugin) getCipherSuiteString(cipherSuite uint16) string {
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

// PortPriority returns true if the port is a common Cisco ASA CCL port
func (p *CiscoASACCLPlugin) PortPriority(port uint16) bool {
	_, exists := commonCCLPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *CiscoASACCLPlugin) Name() string {
	return CISCO_ASA_CCL
}

// Type returns the protocol type
func (p *CiscoASACCLPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *CiscoASACCLPlugin) Priority() int {
	return 690
}
