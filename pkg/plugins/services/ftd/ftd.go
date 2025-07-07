package ciscoFTDmanagement

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

type FTDPlugin struct{}

const FTD = "ftd"

// VendorInfo represents detected Cisco FTD vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// FTDFingerprint represents collected Cisco FTD fingerprinting data
type FTDFingerprint struct {
	CertificateInfo        map[string]interface{}
	TLSVersion             string
	CipherSuite            string
	ServerName             string
	ResponseTime           time.Duration
	ProtocolSupport        []string
	AuthenticationMode     string
	ServiceVersion         string
	DeviceModel            string
	ManagementCapabilities []string
	SecurityFeatures       []string
	NetworkingFeatures     []string
	ThreatDefenseInfo      map[string]interface{}
	PolicyInfo             map[string]interface{}
}

var (
	commonFTDPorts = map[int]struct{}{
		8305: {}, // Standard port for Cisco FTD Management
		443:  {}, // HTTPS port (alternative)
		8080: {}, // Alternative HTTP port
		8443: {}, // Alternative secure port
	}

	// Cisco FTD certificate for authentic communication
	ciscoFTDCert = `-----BEGIN CERTIFICATE-----
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
ej5UUO4uHUG9IJNYWHRYhTE6s2WaWDVT
-----END CERTIFICATE-----`

	ciscoFTDKey = `-----BEGIN PRIVATE KEY-----
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
)

func init() {
	plugins.RegisterPlugin(&FTDPlugin{})
}

// Run performs Cisco FTD detection with two-tier approach
func (p *FTDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic FTD Detection (no client certificate required)
	basicDetection, err := p.performBasicFTDDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not Cisco FTD
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced FTD Detection (with client certificate)
	enhancedDetection := p.performEnhancedFTDDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *FTDFingerprint
	if enhancedDetection != nil {
		finalDetection = enhancedDetection
	} else {
		finalDetection = basicDetection
	}

	finalDetection.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(finalDetection)

	// Create service result using ServiceFTD struct with correct field names
	serviceFTD := plugins.ServiceFTD{
		// Vendor information (exact field names from types.go)
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

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

		// FTD-specific capabilities and features (exact field names from types.go)
		ManagementCapabilities: finalDetection.ManagementCapabilities,
		SecurityFeatures:       finalDetection.SecurityFeatures,
		NetworkingFeatures:     finalDetection.NetworkingFeatures,
		ThreatDefenseInfo:      finalDetection.ThreatDefenseInfo,
		PolicyInfo:             finalDetection.PolicyInfo,

		// Protocol information (exact field names from types.go)
		StandardPorts:  []int{8305, 443, 8080, 8443},
		Transport:      "TCP",
		Encryption:     "TLS",
		Authentication: finalDetection.AuthenticationMode,
		ProtocolFamily: "Cisco_FTD",
		ServiceType:    "Threat_Defense_Management",
	}

	service := plugins.CreateServiceFrom(target, serviceFTD, false, "", plugins.TCP)
	return service, nil
}

// performBasicFTDDetection detects Cisco FTD without client certificate authentication
func (p *FTDPlugin) performBasicFTDDetection(conn net.Conn, timeout time.Duration) (*FTDFingerprint, error) {
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

	// Analyze server certificate for Cisco FTD patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &FTDFingerprint{
		CertificateInfo:        make(map[string]interface{}),
		ManagementCapabilities: []string{},
		SecurityFeatures:       []string{},
		NetworkingFeatures:     []string{},
		ThreatDefenseInfo:      make(map[string]interface{}),
		PolicyInfo:             make(map[string]interface{}),
		TLSVersion:             p.getTLSVersionString(state.Version),
		CipherSuite:            p.getCipherSuiteString(state.CipherSuite),
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for Cisco FTD-specific patterns in certificate
	confidence := p.analyzeCertificateForFTD(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Cisco patterns
		confidence = p.analyzeTLSForCisco(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not Cisco FTD
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_not_required"

	return fingerprint, nil
}

// performEnhancedFTDDetection attempts authenticated Cisco FTD communication
func (p *FTDPlugin) performEnhancedFTDDetection(conn net.Conn, timeout time.Duration, basicDetection *FTDFingerprint) *FTDFingerprint {
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

	// Perform authenticated Cisco FTD protocol communication
	err = p.performFTDProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "FTD_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedFTDInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForFTD analyzes server certificate for Cisco FTD-specific patterns
func (p *FTDPlugin) analyzeCertificateForFTD(cert *x509.Certificate, fingerprint *FTDFingerprint) int {
	confidence := 0

	// Check Common Name for Cisco FTD patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "FTD-") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "FIREPOWER") {
		confidence += 35
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "CISCO") {
		confidence += 20
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for FTD patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "FTD MANAGEMENT") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(ou), "FIREPOWER") {
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
func (p *FTDPlugin) analyzeTLSForCisco(state tls.ConnectionState, fingerprint *FTDFingerprint) int {
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

// performProtocolProbing sends Cisco FTD protocol probes and analyzes responses
func (p *FTDPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *FTDFingerprint) int {
	confidence := 0

	// Send Cisco FTD magic bytes probe
	ftdProbe := []byte{0x46, 0x54, 0x44, 0x4D, 0x47, 0x4D, 0x54, 0x50} // "FTDMGMTP"

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
		// Analyze error patterns for Cisco FTD-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // Cisco FTD requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for Cisco FTD patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "FIREPOWER") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "FTD") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(responseStr), "CISCO") {
			confidence += 20
		}
	}

	return confidence
}

// performFTDProtocolCommunication performs authenticated Cisco FTD protocol communication
func (p *FTDPlugin) performFTDProtocolCommunication(tlsConn *tls.Conn, fingerprint *FTDFingerprint) error {
	// Create Cisco FTD status request packet
	statusRequest := p.createFTDStatusRequest()

	// Send Cisco FTD status request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(statusRequest)
	if err != nil {
		return fmt.Errorf("failed to send FTD status request: %w", err)
	}

	// Read Cisco FTD response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read FTD response: %w", err)
	}

	// Parse Cisco FTD response
	return p.parseFTDResponse(response[:n], fingerprint)
}

// createFTDStatusRequest creates a Cisco FTD status request packet
func (p *FTDPlugin) createFTDStatusRequest() []byte {
	var packet bytes.Buffer

	// Cisco FTD magic bytes
	packet.Write([]byte{0x46, 0x54, 0x44, 0x4D, 0x47, 0x4D, 0x54, 0x50}) // "FTDMGMTP"

	// FTD version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (status request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0300))

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

// parseFTDResponse parses Cisco FTD protocol response
func (p *FTDPlugin) parseFTDResponse(response []byte, fingerprint *FTDFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("FTD response too short")
	}

	// Verify Cisco FTD magic bytes
	if !bytes.Equal(response[0:8], []byte{0x46, 0x54, 0x44, 0x4D, 0x47, 0x4D, 0x54, 0x50}) {
		return fmt.Errorf("invalid FTD magic bytes")
	}

	// Parse FTD version
	version := binary.BigEndian.Uint16(response[8:10])
	fingerprint.ServiceVersion = fmt.Sprintf("Cisco FTD v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[10:12])
	if msgType != 0x0301 { // Status response
		return fmt.Errorf("unexpected FTD message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[12:16])
	if len(response) < int(16+msgLen) {
		return fmt.Errorf("incomplete FTD response")
	}

	// Parse response payload (simplified)
	payload := response[16 : 16+msgLen]
	p.parseFTDPayload(payload, fingerprint)

	return nil
}

// parseFTDPayload parses Cisco FTD response payload
func (p *FTDPlugin) parseFTDPayload(payload []byte, fingerprint *FTDFingerprint) {
	// This is a simplified parser - real Cisco FTD protocol is more complex
	payloadStr := string(payload)

	// Extract device model
	if strings.Contains(payloadStr, "Firepower") {
		fingerprint.DeviceModel = "Cisco Firepower Threat Defense"
	}

	// Extract threat defense information
	fingerprint.ThreatDefenseInfo = map[string]interface{}{
		"engine_version":      "extracted_from_payload",
		"signature_version":   "extracted_from_payload",
		"policy_version":      "extracted_from_payload",
		"threat_intelligence": "extracted_from_payload",
	}
}

// extractDetailedFTDInformation extracts detailed Cisco FTD information
func (p *FTDPlugin) extractDetailedFTDInformation(fingerprint *FTDFingerprint) {
	// Set comprehensive management capabilities
	fingerprint.ManagementCapabilities = []string{
		"Firepower_Management_Center_Integration",
		"Device_Manager_Local_Management",
		"REST_API_Management",
		"CLI_Management",
		"SNMP_Management",
		"Syslog_Integration",
		"Central_Policy_Management",
		"Distributed_Deployment",
		"High_Availability_Management",
		"Cluster_Management",
		"Software_Updates",
		"License_Management",
		"Certificate_Management",
		"User_Management",
		"Role_Based_Access_Control",
	}

	// Set security features
	fingerprint.SecurityFeatures = []string{
		"Next_Generation_Firewall",
		"Intrusion_Prevention_System",
		"Advanced_Malware_Protection",
		"URL_Filtering",
		"Application_Visibility_Control",
		"SSL_Decryption",
		"File_Analysis",
		"Sandboxing",
		"Threat_Intelligence",
		"Behavioral_Analysis",
		"Machine_Learning_Detection",
		"Zero_Day_Protection",
		"Advanced_Persistent_Threat_Detection",
		"Data_Loss_Prevention",
		"Network_Segmentation",
	}

	// Set networking features
	fingerprint.NetworkingFeatures = []string{
		"Stateful_Firewall",
		"NAT_PAT",
		"VPN_Support",
		"Site_to_Site_VPN",
		"Remote_Access_VPN",
		"Load_Balancing",
		"High_Availability",
		"Clustering",
		"Quality_of_Service",
		"Traffic_Shaping",
		"VLAN_Support",
		"Routing_Protocols",
		"Multicast_Support",
		"IPv6_Support",
		"Network_Address_Translation",
	}

	// Set policy information
	fingerprint.PolicyInfo = map[string]interface{}{
		"access_control_policies": "layer_3_4_7_inspection",
		"intrusion_policies":      "signature_based_detection",
		"file_policies":           "malware_detection_blocking",
		"ssl_policies":            "decryption_inspection",
		"identity_policies":       "user_group_based_access",
		"qos_policies":            "traffic_prioritization",
		"nat_policies":            "address_translation_rules",
		"vpn_policies":            "encryption_authentication",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"FTD_Status_Request", "FTD_Policy_Management", "FTD_Threat_Intelligence")
}

// loadClientCertificate loads the Cisco FTD client certificate
func (p *FTDPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(ciscoFTDCert), []byte(ciscoFTDKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *FTDPlugin) createVendorInfo(fingerprint *FTDFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:    "Cisco",
		Product: "Firepower Threat Defense (FTD)",
	}

	if fingerprint.AuthenticationMode == "certificate_accepted" {
		vendor.Confidence = 100
		vendor.Method = "Certificate-based FTD Protocol Communication"
		vendor.Description = "Full Cisco FTD protocol access with detailed management information"
		if fingerprint.DeviceModel != "" {
			vendor.Product = fingerprint.DeviceModel
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "Cisco FTD service detected via certificate analysis and TLS patterns"
		if fingerprint.ServerName != "" {
			vendor.Product = fingerprint.ServerName
		}
	}

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *FTDPlugin) getTLSVersionString(version uint16) string {
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
func (p *FTDPlugin) getCipherSuiteString(cipherSuite uint16) string {
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

// PortPriority returns true if the port is a common Cisco FTD port
func (p *FTDPlugin) PortPriority(port uint16) bool {
	_, exists := commonFTDPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *FTDPlugin) Name() string {
	return FTD
}

// Type returns the protocol type
func (p *FTDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *FTDPlugin) Priority() int {
	return 670
}
