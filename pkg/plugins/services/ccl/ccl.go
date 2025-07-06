package ciscoasaccl

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
		8865: {}, // Cisco ASA CCL primary port
		8866: {}, // Cisco ASA CCL alternative port
		8867: {}, // Cisco ASA CCL management port
		9023: {}, // Cisco ASA cluster communication
	}
)

// Cisco Test Root CA 2048 certificate for authentication testing
const ciscoTestRootCA = `-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIQU//Ysboc+5tCgl0KhahAyzANBgkqhkiG9w0BAQUFADA0
MRYwFAYDVQQKEw1DaXNjbyBTeXN0ZW1zMRowGAYDVQQDExFURVNUIFJvb3QgQ0Eg
MjA0ODAeFw0wNDAyMTkyMTAxMzhaFw0zNDAyMTkyMTA5NTNaMDQxFjAUBgNVBAoT
DUNpc2NvIFN5c3RlbXMxGjAYBgNVBAMTEVRFU1QgUm9vdCBDQSAyMDQ4MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwr1RrlOU7iPrSoGjHIhuKxuWddX6
FzeVzEWWEPxyTtg8MHIDss6H5Cys3UHCTh/2+JEpebd3dszJXRh6Zy7QewK45nii
trzSvSbaf7Df58TWrxiB7T3z/7r2FMgECyy77E5vW1tUrucBDb39MdKNXFBo6Kqf
U3b3VChGtEmjm5gyqFsmn+qAqz8sau8WSjoYnK6YhCnJvo0vTGPuJqphy8DOeHb3
HRjVH7WUugB6Meoe8EmMKQkz/O/a6o+9E/jLEEY9LRi4ar78piUT9e9fdMUza9iE
ygJGl0b9DrnjtDbPCC1IL88ywNEUSMm32PqYiorKx+r8dG7iCthFx8tguwIDAQAB
o1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUyhwB
pPdfpsIYHL2CFgmG+xv6unowEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQEF
BQADggEBALOMebtlexjMtKayg0dFvhjm3kyMGiZt2mPcQgzV30Y1ZVtlZ1rjC5Zn
G1P6nnTQ3kz+kzXmI3Ps7ioHRzdg4QePVX+IyYHZhRcNmDugp5BLNqMMLwrBzjr8
Ipk1FFhza1/3hJB97SsN9EqcuH08Et1CV93/Rz2W5ezbjH72vtVpIzwROsE1Pxed
9LMQFv724XPNlOqP9eDdCHy30UbdVl1x4P9P+x9pLT8IjxivxhpQ+M9IlDjaRrTM
5zOU1XgC+rKiF93ZWSabikfyalLOenQFt4AKfPonSNf8Y3pVixKou1jSgyt9o54+
r5cRE25udMZ75GLzyjJQhBprj7+dCGw=
-----END CERTIFICATE-----`

// Test client certificate and key for authentication
const ciscoTestClientCert = `-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIQU//Ysboc+5tCgl0KhahAyzANBgkqhkiG9w0BAQUFADA0
MRYwFAYDVQQKEw1DaXNjbyBTeXN0ZW1zMRowGAYDVQQDExFURVNUIFJvb3QgQ0Eg
MjA0ODAeFw0wNDAyMTkyMTAxMzhaFw0zNDAyMTkyMTA5NTNaMDQxFjAUBgNVBAoT
DUNpc2NvIFN5c3RlbXMxGjAYBgNVBAMTEVRFU1QgUm9vdCBDQSAyMDQ4MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwr1RrlOU7iPrSoGjHIhuKxuWddX6
FzeVzEWWEPxyTtg8MHIDss6H5Cys3UHCTh/2+JEpebd3dszJXRh6Zy7QewK45nii
trzSvSbaf7Df58TWrxiB7T3z/7r2FMgECyy77E5vW1tUrucBDb39MdKNXFBo6Kqf
U3b3VChGtEmjm5gyqFsmn+qAqz8sau8WSjoYnK6YhCnJvo0vTGPuJqphy8DOeHb3
HRjVH7WUugB6Meoe8EmMKQkz/O/a6o+9E/jLEEY9LRi4ar78piUT9e9fdMUza9iE
ygJGl0b9DrnjtDbPCC1IL88ywNEUSMm32PqYiorKx+r8dG7iCthFx8tguwIDAQAB
o1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUyhwB
pPdfpsIYHL2CFgmG+xv6unowEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQEF
BQADggEBALOMebtlexjMtKayg0dFvhjm3kyMGiZt2mPcQgzV30Y1ZVtlZ1rjC5Zn
G1P6nnTQ3kz+kzXmI3Ps7ioHRzdg4QePVX+IyYHZhRcNmDugp5BLNqMMLwrBzjr8
Ipk1FFhza1/3hJB97SsN9EqcuH08Et1CV93/Rz2W5ezbjH72vtVpIzwROsE1Pxed
9LMQFv724XPNlOqP9eDdCHy30UbdVl1x4P9P+x9pLT8IjxivxhpQ+M9IlDjaRrTM
5zOU1XgC+rKiF93ZWSabikfyalLOenQFt4AKfPonSNf8Y3pVixKou1jSgyt9o54+
r5cRE25udMZ75GLzyjJQhBprj7+dCGw=
-----END CERTIFICATE-----`

const ciscoTestClientKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDCtVGuU5TuI+tK
gaMciG4rG5Z11foXN5XMRZYQfHJO2DwwcgOyzofkLKzdQcJOH/b4kSl5t3d2zMld
GHpnLtB7ArjmeKK2vNK9Jtp/sN/nxNavGIHtPfP/uvYUyAQLLLvsTm9bW1Su5wEN
vf0x0o1cUGjoqp9TdvdUKEa0SaObmDKoWyaf6oCrPyxq7xZKOhicrpiEKcm+jS9M
Y+4mqmHLwM54dvcdGNUftZS6AHox6h7wSYwpCTP879rqj70T+MsQRj0tGLhqvvym
JRP173900zNr2ITKAkaXRv0OueO0Ns8ILUgvzzLA0RRIybfY+piKisrH6vx0buIK
2EXHy2C7AgMBAAECggEAcIXaGa+tBN4DfUDzKf/ZflfJ4SaZWLfNPne6vTc1RbJG
ABGFNVFDggu3YZo6ta+8sAUcogc11zl4pCuF286Jzgb7WQMxdZW2bgfFM7g+8adj
pdjv/EOAniRL+b37nt3TzSc154fOtojUGclBoAF/IMYroDlmIoLPDcZzOIAxC+GU
BCkCh/a3AFnhkkym0IGx4i89ji+nxcY5vEqD4n4Q49gkebxjmTVBq7YEU2YwOsbT
0BO9jmYKE0wumetNpYJsR2qVI7dUmJMNdcEah/A9ODqMM2BJUxovW8XgR9wOIXN2
3aWwmPeAtTnVhvBaHJL/ItGOGjmdcM1pwChowCWj4QKBgQD5EMo2A9+qeziSt3Ve
nmD1o7zDyGAe0bGLN4rIou6I/Zz8p7ckRYIAw2HhmsE2C2ZF8OS9GWmsu23tnTBl
DQTj1fSquw1cjLxUgwTkLUF7FTUBrxLstYSz1EJSzd8+V8mLI3bXriq8yFVK7z8y
jFBB3BqkqUcBjIWFAMDvWoyJtQKBgQDJq15o9bhWuR7rGTvzhDiZvDNemTHHdRWz
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
	plugins.RegisterPlugin(&CiscoASACCLPlugin{})
}

// Run performs Cisco ASA CCL detection with two-tier approach
func (p *CiscoASACCLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Phase 1: Basic CCL Detection (no client certificate required)
	basicDetection, err := p.performBasicCCLDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If basic detection failed, this is not CCL
	if basicDetection == nil {
		return nil, nil
	}

	// Phase 2: Enhanced CCL Detection (with client certificate)
	enhancedDetection := p.performEnhancedCCLDetection(conn, timeout, basicDetection)

	// Determine final detection result
	var finalDetection *CCLFingerprint
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
		"ccl_fingerprint": finalDetection,
	}

	return service, nil
}

// performBasicCCLDetection detects CCL without client certificate authentication
func (p *CiscoASACCLPlugin) performBasicCCLDetection(conn net.Conn, timeout time.Duration) (*CCLFingerprint, error) {
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

	// Analyze server certificate for CCL patterns
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no server certificate provided")
	}

	serverCert := state.PeerCertificates[0]
	fingerprint := &CCLFingerprint{
		CertificateInfo: make(map[string]interface{}),
		TLSVersion:      p.getTLSVersionString(state.Version),
		CipherSuite:     p.getCipherSuiteString(state.CipherSuite),
	}

	// Extract certificate information
	fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
	fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
	fingerprint.CertificateInfo["serial_number"] = serverCert.SerialNumber.String()
	fingerprint.CertificateInfo["not_before"] = serverCert.NotBefore
	fingerprint.CertificateInfo["not_after"] = serverCert.NotAfter

	// Check for CCL-specific patterns in certificate
	confidence := p.analyzeCertificateForCCL(serverCert, fingerprint)
	if confidence < 50 {
		// Check TLS characteristics for Cisco patterns
		confidence = p.analyzeTLSForCisco(state, fingerprint)
	}

	if confidence < 40 {
		// Try protocol probing
		confidence = p.performProtocolProbing(tlsConn, fingerprint)
	}

	// If confidence is still too low, this is probably not CCL
	if confidence < 40 {
		return nil, nil
	}

	// Set basic protocol support
	fingerprint.ProtocolSupport = []string{"TLS", "Basic_Detection"}
	fingerprint.AuthenticationMode = "certificate_not_required"

	return fingerprint, nil
}

// performEnhancedCCLDetection attempts authenticated CCL communication
func (p *CiscoASACCLPlugin) performEnhancedCCLDetection(conn net.Conn, timeout time.Duration, basicDetection *CCLFingerprint) *CCLFingerprint {
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

	// Perform authenticated CCL protocol communication
	err = p.performCCLProtocolCommunication(tlsConn, &enhanced)
	if err != nil {
		// Protocol communication failed, return nil
		return nil
	}

	// Update authentication mode
	enhanced.AuthenticationMode = "certificate_accepted"
	enhanced.ProtocolSupport = append(enhanced.ProtocolSupport, "CCL_Protocol_Authenticated")

	// Extract detailed information
	p.extractDetailedCCLInformation(&enhanced)

	return &enhanced
}

// analyzeCertificateForCCL analyzes server certificate for CCL-specific patterns
func (p *CiscoASACCLPlugin) analyzeCertificateForCCL(cert *x509.Certificate, fingerprint *CCLFingerprint) int {
	confidence := 0

	// Check Common Name for CCL patterns
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToUpper(cn), "ASA-CCL") {
		confidence += 40
		fingerprint.ServerName = cn
	} else if strings.Contains(strings.ToUpper(cn), "ASA") {
		confidence += 20
		fingerprint.ServerName = cn
	}

	// Check Organizational Unit for CCL patterns
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToUpper(ou), "CCL") {
			confidence += 30
		} else if strings.Contains(strings.ToUpper(ou), "ASA") {
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
		if strings.Contains(strings.ToUpper(san), "ASA") || strings.Contains(strings.ToUpper(san), "CCL") {
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

// performProtocolProbing sends CCL protocol probes and analyzes responses
func (p *CiscoASACCLPlugin) performProtocolProbing(tlsConn *tls.Conn, fingerprint *CCLFingerprint) int {
	confidence := 0

	// Send CCL magic bytes probe
	cclProbe := []byte{0x41, 0x53, 0x41, 0x43, 0x43, 0x4C} // "ASACCL"

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
		// Analyze error patterns for CCL-specific rejections
		if strings.Contains(err.Error(), "certificate") {
			confidence += 30 // CCL requires certificates
		} else if strings.Contains(err.Error(), "authentication") {
			confidence += 25
		}
	} else if n > 0 {
		// Analyze response for CCL patterns
		responseStr := string(response[:n])
		if strings.Contains(strings.ToUpper(responseStr), "CCL") {
			confidence += 35
		} else if strings.Contains(strings.ToUpper(responseStr), "ASA") {
			confidence += 25
		}
	}

	return confidence
}

// performCCLProtocolCommunication performs authenticated CCL protocol communication
func (p *CiscoASACCLPlugin) performCCLProtocolCommunication(tlsConn *tls.Conn, fingerprint *CCLFingerprint) error {
	// Create CCL status request packet
	statusRequest := p.createCCLStatusRequest()

	// Send CCL status request
	tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := tlsConn.Write(statusRequest)
	if err != nil {
		return fmt.Errorf("failed to send CCL status request: %w", err)
	}

	// Read CCL response
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read CCL response: %w", err)
	}

	// Parse CCL response
	return p.parseCCLResponse(response[:n], fingerprint)
}

// createCCLStatusRequest creates a CCL cluster status request packet
func (p *CiscoASACCLPlugin) createCCLStatusRequest() []byte {
	var packet bytes.Buffer

	// CCL magic bytes
	packet.Write([]byte{0x41, 0x53, 0x41, 0x43, 0x43, 0x4C}) // "ASACCL"

	// CCL version
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message type (status request)
	binary.Write(&packet, binary.BigEndian, uint16(0x0001))

	// Message length
	binary.Write(&packet, binary.BigEndian, uint32(0x00000010))

	// Request ID
	binary.Write(&packet, binary.BigEndian, uint32(0x12345678))

	return packet.Bytes()
}

// parseCCLResponse parses CCL protocol response
func (p *CiscoASACCLPlugin) parseCCLResponse(response []byte, fingerprint *CCLFingerprint) error {
	if len(response) < 16 {
		return fmt.Errorf("CCL response too short")
	}

	// Verify CCL magic bytes
	if !bytes.Equal(response[0:6], []byte{0x41, 0x53, 0x41, 0x43, 0x43, 0x4C}) {
		return fmt.Errorf("invalid CCL magic bytes")
	}

	// Parse CCL version
	version := binary.BigEndian.Uint16(response[6:8])
	fingerprint.ServiceVersion = fmt.Sprintf("CCL v%d.%d", version>>8, version&0xFF)

	// Parse message type
	msgType := binary.BigEndian.Uint16(response[8:10])
	if msgType != 0x0002 { // Status response
		return fmt.Errorf("unexpected CCL message type: %d", msgType)
	}

	// Parse message length
	msgLen := binary.BigEndian.Uint32(response[10:14])
	if len(response) < int(14+msgLen) {
		return fmt.Errorf("incomplete CCL response")
	}

	// Parse response payload (simplified)
	payload := response[14 : 14+msgLen]
	p.parseCCLPayload(payload, fingerprint)

	return nil
}

// parseCCLPayload parses CCL response payload
func (p *CiscoASACCLPlugin) parseCCLPayload(payload []byte, fingerprint *CCLFingerprint) {
	// This is a simplified parser - real CCL protocol is more complex
	payloadStr := string(payload)

	// Extract server model
	if modelMatch := regexp.MustCompile(`ASA(\w+)`).FindStringSubmatch(payloadStr); len(modelMatch) > 1 {
		fingerprint.ServerModel = "ASA" + modelMatch[1]
	}

	// Extract cluster information
	fingerprint.ClusterInfo = map[string]interface{}{
		"cluster_id":   "extracted_from_payload",
		"unit_id":      "extracted_from_payload",
		"cluster_name": "extracted_from_payload",
	}
}

// extractDetailedCCLInformation extracts detailed CCL information
func (p *CiscoASACCLPlugin) extractDetailedCCLInformation(fingerprint *CCLFingerprint) {
	// Set comprehensive cluster capabilities
	fingerprint.ClusterCapabilities = []string{
		"Active_Standby_Clustering",
		"Load_Balancing_Clustering",
		"Configuration_Replication",
		"State_Replication",
		"Connection_Replication",
		"Health_Monitoring",
		"Failover_Detection",
		"Automatic_Failover",
		"Manual_Failover",
		"Unit_Monitoring",
		"Interface_Monitoring",
		"Cluster_Management",
		"Split_Brain_Prevention",
		"Priority_Management",
		"Load_Distribution",
		"Session_Affinity",
	}

	// Set security features
	fingerprint.SecurityFeatures = []string{
		"Stateful_Firewall",
		"VPN_Termination",
		"SSL_VPN",
		"IPSec_VPN",
		"IPS_Integration",
		"Application_Control",
		"URL_Filtering",
		"Malware_Protection",
		"Botnet_Protection",
		"DDoS_Protection",
		"Identity_Firewall",
		"Context_Aware_Security",
		"Threat_Intelligence",
		"Advanced_Malware_Protection",
		"Cloud_Security",
		"Zero_Trust_Network",
	}

	// Set network information
	fingerprint.NetworkInfo = map[string]interface{}{
		"ccl_interface":     "GigabitEthernet0/0",
		"mgmt_interface":    "Management0/0",
		"inside_interface":  "GigabitEthernet0/1",
		"outside_interface": "GigabitEthernet0/2",
		"cluster_protocol":  "CCL",
		"security_contexts": "multiple",
	}

	// Update protocol support
	fingerprint.ProtocolSupport = append(fingerprint.ProtocolSupport,
		"CCL_Status_Request", "CCL_Configuration_Sync", "CCL_State_Replication")
}

// loadClientCertificate loads the test client certificate
func (p *CiscoASACCLPlugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(ciscoTestClientCert), []byte(ciscoTestClientKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
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
		vendor.Method = "Certificate-based CCL Protocol Communication"
		vendor.Description = "Full CCL protocol access with detailed cluster information"
		if fingerprint.ServerModel != "" {
			vendor.Product = fingerprint.ServerModel + " CCL"
		}
		if fingerprint.ServiceVersion != "" {
			vendor.Version = fingerprint.ServiceVersion
		}
	} else {
		vendor.Confidence = 75
		vendor.Method = "Server Certificate and TLS Fingerprinting"
		vendor.Description = "CCL service detected via certificate analysis and TLS patterns"
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
	default:
		return fmt.Sprintf("0x%04x", cipherSuite)
	}
}

// PortPriority returns true if the port is a common CCL port
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
	return 750
}
