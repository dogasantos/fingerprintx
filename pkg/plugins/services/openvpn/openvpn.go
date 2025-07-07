package openvpn

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

const OPENVPN = "openvpn"

type Plugin struct{}

// VendorInfo represents detected vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// OpenVPNFingerprint represents collected UDP-based fingerprinting data (NO TIMING)
type OpenVPNFingerprint struct {
	ResponseSize     int
	HandshakePattern string
	ResetBehavior    string
	PacketStructure  string
	SupportsAuth     bool    // Whether tls-auth/tls-crypt is detected
	OpcodeSequence   []uint8 // Sequence of opcodes observed
	StandardPort     int
	Transport        string
	Encryption       string
	Authentication   []string
	Compression      []string
	SessionID        string
	DetectionMethod  string
}

var (
	commonOpenVPNPorts = map[int]struct{}{
		1194: {}, // Standard OpenVPN port
	}

	// Known OpenVPN vendor patterns
	vendorPatterns = map[string]VendorInfo{
		"openvpn_community": {
			Name:        "OpenVPN",
			Product:     "OpenVPN Community Edition",
			Confidence:  85,
			Method:      "UDP Content Analysis",
			Description: "Open source OpenVPN server",
		},
		"openvpn_access_server": {
			Name:        "OpenVPN",
			Product:     "OpenVPN Access Server",
			Confidence:  90,
			Method:      "UDP Content Analysis",
			Description: "Commercial OpenVPN Access Server",
		},
		"pfsense_openvpn": {
			Name:        "pfSense",
			Product:     "pfSense OpenVPN",
			Confidence:  80,
			Method:      "UDP Content Analysis",
			Description: "pfSense integrated OpenVPN server",
		},
		"mikrotik_openvpn": {
			Name:        "MikroTik",
			Product:     "RouterOS OpenVPN",
			Confidence:  75,
			Method:      "UDP Content Analysis",
			Description: "MikroTik RouterOS OpenVPN implementation",
		},
		"fortinet_openvpn": {
			Name:        "Fortinet",
			Product:     "FortiGate SSL VPN",
			Confidence:  70,
			Method:      "UDP Content Analysis",
			Description: "Fortinet FortiGate SSL VPN with OpenVPN compatibility",
		},
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run performs OpenVPN detection using content-based analysis only (NO TIMING)
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Perform OpenVPN UDP fingerprinting (content-based only)
	fingerprint, err := p.performContentBasedDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	if fingerprint == nil {
		return nil, nil // Not OpenVPN
	}

	// Set additional fingerprint data (NO TIMING)
	fingerprint.StandardPort = 1194
	fingerprint.Transport = "UDP"

	// Create vendor information
	vendor := p.createVendorInfo(fingerprint)

	// Create service result using ServiceOpenVPN struct with exact field names
	serviceOpenVPN := plugins.ServiceOpenVPN{
		// Vendor information (exact field names from types.go)
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// UDP fingerprint data (exact field names from types.go) - NO TIMING FIELDS
		ResponseSize:     fingerprint.ResponseSize,
		HandshakePattern: fingerprint.HandshakePattern,
		ResetBehavior:    fingerprint.ResetBehavior,
		PacketStructure:  fingerprint.PacketStructure,
		SupportsAuth:     fingerprint.SupportsAuth,
		OpcodeSequence:   fingerprint.OpcodeSequence,

		// Protocol information (exact field names from types.go)
		StandardPort:   fingerprint.StandardPort,
		Transport:      fingerprint.Transport,
		Encryption:     fingerprint.Encryption,
		Authentication: fingerprint.Authentication,
		Compression:    fingerprint.Compression,
		SessionID:      fingerprint.SessionID,
	}

	service := plugins.CreateServiceFrom(target, serviceOpenVPN, false, "", plugins.UDP)
	return service, nil
}

// performContentBasedDetection performs OpenVPN detection based purely on content (NO TIMING)
func (p *Plugin) performContentBasedDetection(conn net.Conn, timeout time.Duration) (*OpenVPNFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	fingerprint := &OpenVPNFingerprint{
		OpcodeSequence: []uint8{},
		Authentication: []string{},
		Compression:    []string{},
	}

	// Method 1: Standard OpenVPN handshake (content-based)
	confidence := p.tryStandardHandshake(conn, fingerprint)
	if confidence >= 25 {
		fingerprint.DetectionMethod = "Standard_Handshake"
		return fingerprint, nil
	}

	// Method 2: Alternative OpenVPN packets (content-based)
	confidence = p.tryAlternativePackets(conn, fingerprint)
	if confidence >= 25 {
		fingerprint.DetectionMethod = "Alternative_Packets"
		return fingerprint, nil
	}

	// Method 3: Simple UDP probe on port 1194 (content-based)
	confidence = p.trySimpleUDPProbe(conn, fingerprint)
	if confidence >= 20 {
		fingerprint.DetectionMethod = "Simple_UDP_Probe"
		return fingerprint, nil
	}

	// Method 4: Port-based detection (last resort)
	confidence = p.tryPortBasedDetection(conn, fingerprint)
	if confidence >= 15 {
		fingerprint.DetectionMethod = "Port_Based"
		return fingerprint, nil
	}

	return nil, nil // Not confident enough
}

// tryStandardHandshake attempts standard OpenVPN handshake (content-based)
func (p *Plugin) tryStandardHandshake(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Create OpenVPN client hello packet
	clientHello := p.createOpenVPNClientHello()

	// Send client hello
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(clientHello)
	if err != nil {
		return confidence
	}

	// Read server response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		return confidence
	}

	fingerprint.ResponseSize = n

	// Analyze OpenVPN response (content-based only)
	confidence += p.analyzeOpenVPNResponse(response[:n], fingerprint)

	return confidence
}

// tryAlternativePackets tries different OpenVPN packet types (content-based)
func (p *Plugin) tryAlternativePackets(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Try different OpenVPN packet types
	packets := [][]byte{
		p.createOpenVPNResetPacket(),
		p.createOpenVPNAuthPacket(),
		p.createOpenVPNAckPacket(),
	}

	for _, packet := range packets {
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err := conn.Write(packet)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		response := make([]byte, 1500)
		n, err := conn.Read(response)
		if err != nil {
			continue
		}

		// Analyze response content
		packetConfidence := p.analyzeOpenVPNResponse(response[:n], fingerprint)
		if packetConfidence > confidence {
			confidence = packetConfidence
			fingerprint.ResponseSize = n
		}
	}

	return confidence
}

// trySimpleUDPProbe tries simple UDP probe (content-based)
func (p *Plugin) trySimpleUDPProbe(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Check if we're on port 1194
	remoteAddr := conn.RemoteAddr().String()
	if !strings.Contains(remoteAddr, ":1194") {
		return confidence
	}

	// Send simple UDP probe
	probe := []byte("OpenVPN")
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Write(probe)
	if err != nil {
		return confidence
	}

	// Read any response
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		return confidence
	}

	fingerprint.ResponseSize = n

	// Any response on port 1194 gets some confidence
	confidence += 20
	fingerprint.PacketStructure = "UDP_Response_Port_1194"

	// Analyze response for OpenVPN patterns
	confidence += p.analyzeResponseContent(response[:n], fingerprint)

	return confidence
}

// tryPortBasedDetection tries port-based detection (content-based)
func (p *Plugin) tryPortBasedDetection(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Check if we're on port 1194
	remoteAddr := conn.RemoteAddr().String()
	if !strings.Contains(remoteAddr, ":1194") {
		return confidence
	}

	// Send any UDP packet
	probe := []byte{0x00, 0x01, 0x02, 0x03}
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Write(probe)
	if err != nil {
		return confidence
	}

	// Read any response
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		confidence += 15
		fingerprint.ResponseSize = n
		fingerprint.PacketStructure = "Port_1194_UDP_Service"
	}

	return confidence
}

// analyzeOpenVPNResponse analyzes response for OpenVPN patterns (content-based)
func (p *Plugin) analyzeOpenVPNResponse(response []byte, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	if len(response) < 1 {
		return confidence
	}

	// Check for OpenVPN packet structure
	if len(response) >= 1 {
		opcode := response[0] >> 3
		fingerprint.OpcodeSequence = append(fingerprint.OpcodeSequence, opcode)

		// OpenVPN opcodes: 1=P_CONTROL_HARD_RESET_SERVER_V1, 2=P_CONTROL_HARD_RESET_CLIENT_V1, etc.
		if opcode >= 1 && opcode <= 10 {
			confidence += 40
			fingerprint.HandshakePattern = fmt.Sprintf("OpenVPN_Opcode_%d", opcode)

			// Check for session ID
			if len(response) >= 9 {
				sessionID := response[1:9]
				fingerprint.SessionID = fmt.Sprintf("%x", sessionID)
				confidence += 20
			}

			// Check for packet ID
			if len(response) >= 13 {
				confidence += 15
				fingerprint.PacketStructure = "OpenVPN_Control_Packet"
			}
		}
	}

	// Analyze response content for OpenVPN patterns
	confidence += p.analyzeResponseContent(response, fingerprint)

	return confidence
}

// analyzeResponseContent analyzes response content for OpenVPN patterns (content-based)
func (p *Plugin) analyzeResponseContent(response []byte, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Convert to string for pattern matching
	responseStr := strings.ToLower(string(response))

	// Check for OpenVPN-specific patterns
	if strings.Contains(responseStr, "openvpn") {
		confidence += 30
		fingerprint.PacketStructure += "_OpenVPN_String"
	}

	if strings.Contains(responseStr, "tls-auth") || strings.Contains(responseStr, "tls-crypt") {
		confidence += 25
		fingerprint.SupportsAuth = true
		fingerprint.Authentication = append(fingerprint.Authentication, "TLS-Auth")
	}

	if strings.Contains(responseStr, "ssl") || strings.Contains(responseStr, "tls") {
		confidence += 15
		fingerprint.Encryption = "TLS"
	}

	// Check for compression indicators
	if strings.Contains(responseStr, "lzo") {
		confidence += 10
		fingerprint.Compression = append(fingerprint.Compression, "LZO")
	}

	if strings.Contains(responseStr, "lz4") {
		confidence += 10
		fingerprint.Compression = append(fingerprint.Compression, "LZ4")
	}

	// Check for version indicators
	if strings.Contains(responseStr, "2.4") || strings.Contains(responseStr, "2.5") || strings.Contains(responseStr, "2.6") {
		confidence += 15
	}

	// Check for error messages that indicate OpenVPN
	if strings.Contains(responseStr, "bad packet") || strings.Contains(responseStr, "auth failed") {
		confidence += 20
	}

	return confidence
}

// createOpenVPNClientHello creates an OpenVPN client hello packet
func (p *Plugin) createOpenVPNClientHello() []byte {
	packet := make([]byte, 14)

	// Opcode (P_CONTROL_HARD_RESET_CLIENT_V1) and key ID
	packet[0] = (2 << 3) | 0 // Opcode 2, Key ID 0

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 1

	// Net time (optional, set to 0)
	packet[13] = 0

	return packet
}

// createOpenVPNResetPacket creates an OpenVPN reset packet
func (p *Plugin) createOpenVPNResetPacket() []byte {
	packet := make([]byte, 14)

	// Opcode (P_CONTROL_HARD_RESET_CLIENT_V2) and key ID
	packet[0] = (3 << 3) | 0 // Opcode 3, Key ID 0

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 2

	// Net time
	packet[13] = 0

	return packet
}

// createOpenVPNAuthPacket creates an OpenVPN auth packet
func (p *Plugin) createOpenVPNAuthPacket() []byte {
	packet := make([]byte, 20)

	// Opcode with auth flag
	packet[0] = (2 << 3) | 1 // Opcode 2, Key ID 1 (indicates auth)

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 1

	// Auth data (simplified)
	rand.Read(packet[13:20])

	return packet
}

// createOpenVPNAckPacket creates an OpenVPN ACK packet
func (p *Plugin) createOpenVPNAckPacket() []byte {
	packet := make([]byte, 14)

	// Opcode (P_ACK_V1) and key ID
	packet[0] = (5 << 3) | 0 // Opcode 5, Key ID 0

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 0

	// Net time
	packet[13] = 0

	return packet
}

// createVendorInfo creates vendor information based on fingerprinting results (content-based)
func (p *Plugin) createVendorInfo(fingerprint *OpenVPNFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "OpenVPN",
		Product:    "OpenVPN Server",
		Confidence: 60,
		Method:     "UDP Content Analysis",
	}

	// Analyze patterns for vendor detection (content-based)
	if strings.Contains(fingerprint.PacketStructure, "Access_Server") {
		vendor = vendorPatterns["openvpn_access_server"]
	} else if strings.Contains(fingerprint.PacketStructure, "pfSense") {
		vendor = vendorPatterns["pfsense_openvpn"]
	} else if strings.Contains(fingerprint.PacketStructure, "MikroTik") {
		vendor = vendorPatterns["mikrotik_openvpn"]
	} else if fingerprint.SupportsAuth {
		vendor = vendorPatterns["openvpn_community"]
	}

	// Enhance confidence based on fingerprint quality (content-based)
	if len(fingerprint.OpcodeSequence) > 2 {
		vendor.Confidence += 10
	}
	if fingerprint.SupportsAuth {
		vendor.Confidence += 5
	}
	if fingerprint.ResponseSize > 50 {
		vendor.Confidence += 5
	}

	// Set version based on opcode patterns (content-based)
	if len(fingerprint.OpcodeSequence) > 0 {
		if fingerprint.OpcodeSequence[0] >= 3 {
			vendor.Version = "OpenVPN 2.4+"
		} else {
			vendor.Version = "OpenVPN 2.0-2.3"
		}
	}

	// Update method based on detection method
	vendor.Method = fmt.Sprintf("UDP Content Analysis (%s)", fingerprint.DetectionMethod)

	return vendor
}

// PortPriority returns true if the port is a common OpenVPN port
func (p *Plugin) PortPriority(port uint16) bool {
	_, exists := commonOpenVPNPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return OPENVPN
}

// Type returns the protocol type
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the plugin priority
func (p *Plugin) Priority() int {
	return 580
}
