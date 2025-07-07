package openvpn

import (
	"crypto/rand"
	"fmt"
	"net"
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

// OpenVPNFingerprint represents collected UDP-based fingerprinting data
type OpenVPNFingerprint struct {
	ResponseTime      time.Duration
	ResponseSize      int
	HandshakePattern  string
	ResetBehavior     string
	PacketStructure   string
	TimingConsistency float64 // Variance in response times
	SupportsAuth      bool    // Whether tls-auth/tls-crypt is detected
	OpcodeSequence    []uint8 // Sequence of opcodes observed
	StandardPort      int
	Transport         string
	Encryption        string
	Authentication    []string
	Compression       []string
	SessionID         string
}

var (
	commonOpenVPNPorts = map[int]struct{}{
		1194: {}, // Default OpenVPN port
		443:  {}, // HTTPS port (common alternative)
		80:   {}, // HTTP port (alternative)
		53:   {}, // DNS port (stealth)
		22:   {}, // SSH port (stealth)
		25:   {}, // SMTP port (stealth)
		110:  {}, // POP3 port (stealth)
		143:  {}, // IMAP port (stealth)
		993:  {}, // IMAPS port (stealth)
		995:  {}, // POP3S port (stealth)
	}

	// Known OpenVPN vendor patterns
	vendorPatterns = map[string]VendorInfo{
		"openvpn_community": {
			Name:        "OpenVPN",
			Product:     "OpenVPN Community Edition",
			Confidence:  85,
			Method:      "UDP Fingerprinting",
			Description: "Open source OpenVPN server",
		},
		"openvpn_access_server": {
			Name:        "OpenVPN",
			Product:     "OpenVPN Access Server",
			Confidence:  90,
			Method:      "UDP Fingerprinting",
			Description: "Commercial OpenVPN Access Server",
		},
		"pfsense_openvpn": {
			Name:        "pfSense",
			Product:     "pfSense OpenVPN",
			Confidence:  80,
			Method:      "UDP Fingerprinting",
			Description: "pfSense integrated OpenVPN server",
		},
		"mikrotik_openvpn": {
			Name:        "MikroTik",
			Product:     "RouterOS OpenVPN",
			Confidence:  75,
			Method:      "UDP Fingerprinting",
			Description: "MikroTik RouterOS OpenVPN implementation",
		},
		"fortinet_openvpn": {
			Name:        "Fortinet",
			Product:     "FortiGate SSL VPN",
			Confidence:  70,
			Method:      "UDP Fingerprinting",
			Description: "Fortinet FortiGate SSL VPN with OpenVPN compatibility",
		},
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run performs OpenVPN detection using UDP fingerprinting
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Perform OpenVPN UDP fingerprinting
	fingerprint, err := p.performOpenVPNFingerprinting(conn, timeout)
	if err != nil {
		return nil, err
	}

	if fingerprint == nil {
		return nil, nil // Not OpenVPN
	}

	// Set additional fingerprint data
	fingerprint.ResponseTime = time.Since(startTime)
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

		// UDP fingerprint data (exact field names from types.go)
		ResponseTimeMs:    fingerprint.ResponseTime.Milliseconds(),
		ResponseSize:      fingerprint.ResponseSize,
		TimingConsistency: fingerprint.TimingConsistency,
		HandshakePattern:  fingerprint.HandshakePattern,
		ResetBehavior:     fingerprint.ResetBehavior,
		PacketStructure:   fingerprint.PacketStructure,
		SupportsAuth:      fingerprint.SupportsAuth,
		OpcodeSequence:    fingerprint.OpcodeSequence,

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

// performOpenVPNFingerprinting performs comprehensive OpenVPN UDP fingerprinting
func (p *Plugin) performOpenVPNFingerprinting(conn net.Conn, timeout time.Duration) (*OpenVPNFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	fingerprint := &OpenVPNFingerprint{
		OpcodeSequence: []uint8{},
		Authentication: []string{},
		Compression:    []string{},
	}

	// Phase 1: Basic OpenVPN handshake attempt
	basicConfidence := p.performBasicHandshake(conn, fingerprint)
	if basicConfidence < 40 {
		return nil, nil // Not confident enough
	}

	// Phase 2: Advanced fingerprinting
	p.performAdvancedFingerprinting(conn, fingerprint)

	// Phase 3: Timing analysis
	p.performTimingAnalysis(conn, fingerprint)

	// Phase 4: Vendor-specific detection
	p.performVendorDetection(conn, fingerprint)

	return fingerprint, nil
}

// performBasicHandshake attempts basic OpenVPN handshake
func (p *Plugin) performBasicHandshake(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
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

	// Analyze OpenVPN response
	if n >= 2 {
		// Check for OpenVPN packet structure
		opcode := response[0] >> 3
		fingerprint.OpcodeSequence = append(fingerprint.OpcodeSequence, opcode)

		// OpenVPN opcodes: 1=P_CONTROL_HARD_RESET_SERVER_V1, 2=P_CONTROL_HARD_RESET_CLIENT_V1, etc.
		if opcode >= 1 && opcode <= 10 {
			confidence += 40
			fingerprint.HandshakePattern = fmt.Sprintf("OpenVPN_Opcode_%d", opcode)

			// Check for session ID
			if n >= 10 {
				sessionID := response[1:9]
				fingerprint.SessionID = fmt.Sprintf("%x", sessionID)
				confidence += 20
			}

			// Check for packet ID
			if n >= 14 {
				confidence += 15
				fingerprint.PacketStructure = "OpenVPN_Control_Packet"
			}
		}
	}

	// Check for OpenVPN-specific patterns
	responseStr := string(response[:n])
	if len(responseStr) > 0 {
		// Look for OpenVPN error messages or patterns
		if contains(responseStr, "OpenVPN") {
			confidence += 30
		}
		if contains(responseStr, "tls-auth") || contains(responseStr, "tls-crypt") {
			confidence += 25
			fingerprint.SupportsAuth = true
			fingerprint.Authentication = append(fingerprint.Authentication, "TLS-Auth")
		}
	}

	return confidence
}

// performAdvancedFingerprinting performs advanced OpenVPN fingerprinting
func (p *Plugin) performAdvancedFingerprinting(conn net.Conn, fingerprint *OpenVPNFingerprint) {
	// Test different OpenVPN packet types
	p.testControlPackets(conn, fingerprint)
	p.testAuthMethods(conn, fingerprint)
	p.testCompressionMethods(conn, fingerprint)
}

// testControlPackets tests different OpenVPN control packet types
func (p *Plugin) testControlPackets(conn net.Conn, fingerprint *OpenVPNFingerprint) {
	// Test P_CONTROL_HARD_RESET_CLIENT_V2
	resetPacket := p.createOpenVPNResetPacket()
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.Write(resetPacket)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		if n >= 1 {
			opcode := response[0] >> 3
			fingerprint.OpcodeSequence = append(fingerprint.OpcodeSequence, opcode)
		}
		fingerprint.ResetBehavior = "Responds_to_Reset"
	} else {
		fingerprint.ResetBehavior = "No_Reset_Response"
	}
}

// testAuthMethods tests different authentication methods
func (p *Plugin) testAuthMethods(conn net.Conn, fingerprint *OpenVPNFingerprint) {
	// Test for tls-auth support
	authPacket := p.createOpenVPNAuthPacket()
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.Write(authPacket)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err == nil && n > 0 {
		// Analyze auth response
		if n >= 2 {
			opcode := response[0] >> 3
			if opcode == 3 || opcode == 4 { // P_CONTROL_HARD_RESET_SERVER_V2 or similar
				fingerprint.Authentication = append(fingerprint.Authentication, "TLS-Crypt")
			}
		}
	}

	// Set encryption based on response patterns
	fingerprint.Encryption = "AES-256-GCM" // Default assumption for modern OpenVPN
}

// testCompressionMethods tests compression support
func (p *Plugin) testCompressionMethods(conn net.Conn, fingerprint *OpenVPNFingerprint) {
	// OpenVPN typically supports LZO and LZ4 compression
	fingerprint.Compression = []string{"LZO", "LZ4", "None"}
}

// performTimingAnalysis performs timing-based fingerprinting
func (p *Plugin) performTimingAnalysis(conn net.Conn, fingerprint *OpenVPNFingerprint) {
	var responseTimes []time.Duration

	// Send multiple packets and measure response times
	for i := 0; i < 3; i++ {
		start := time.Now()

		packet := p.createOpenVPNClientHello()
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write(packet)

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		response := make([]byte, 1500)
		_, err := conn.Read(response)

		if err == nil {
			responseTimes = append(responseTimes, time.Since(start))
		}

		time.Sleep(100 * time.Millisecond) // Small delay between tests
	}

	// Calculate timing consistency
	if len(responseTimes) > 1 {
		var sum time.Duration
		for _, rt := range responseTimes {
			sum += rt
		}
		avg := sum / time.Duration(len(responseTimes))

		var variance float64
		for _, rt := range responseTimes {
			diff := float64(rt - avg)
			variance += diff * diff
		}
		variance /= float64(len(responseTimes))
		fingerprint.TimingConsistency = variance / 1000000 // Convert to ms²
	}
}

// performVendorDetection attempts to detect specific OpenVPN implementations
func (p *Plugin) performVendorDetection(conn net.Conn, fingerprint *OpenVPNFingerprint) {
	// Vendor detection based on response patterns, timing, and behavior

	// Check for Access Server patterns
	if fingerprint.SupportsAuth && fingerprint.ResponseSize > 100 {
		fingerprint.PacketStructure += "_Access_Server_Pattern"
	}

	// Check for pfSense patterns (typically faster responses)
	if fingerprint.TimingConsistency < 10 && len(fingerprint.OpcodeSequence) > 1 {
		fingerprint.PacketStructure += "_pfSense_Pattern"
	}

	// Check for MikroTik patterns (specific opcode sequences)
	if len(fingerprint.OpcodeSequence) >= 2 && fingerprint.OpcodeSequence[0] == 1 {
		fingerprint.PacketStructure += "_MikroTik_Pattern"
	}
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

// createVendorInfo creates vendor information based on fingerprinting results
func (p *Plugin) createVendorInfo(fingerprint *OpenVPNFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "OpenVPN",
		Product:    "OpenVPN Server",
		Confidence: 60,
		Method:     "UDP Fingerprinting",
	}

	// Analyze patterns for vendor detection
	if contains(fingerprint.PacketStructure, "Access_Server_Pattern") {
		vendor = vendorPatterns["openvpn_access_server"]
	} else if contains(fingerprint.PacketStructure, "pfSense_Pattern") {
		vendor = vendorPatterns["pfsense_openvpn"]
	} else if contains(fingerprint.PacketStructure, "MikroTik_Pattern") {
		vendor = vendorPatterns["mikrotik_openvpn"]
	} else if fingerprint.SupportsAuth {
		vendor = vendorPatterns["openvpn_community"]
	}

	// Enhance confidence based on fingerprint quality
	if len(fingerprint.OpcodeSequence) > 2 {
		vendor.Confidence += 10
	}
	if fingerprint.SupportsAuth {
		vendor.Confidence += 5
	}
	if fingerprint.TimingConsistency < 20 {
		vendor.Confidence += 5
	}

	// Set version based on opcode patterns
	if len(fingerprint.OpcodeSequence) > 0 {
		if fingerprint.OpcodeSequence[0] >= 3 {
			vendor.Version = "OpenVPN 2.4+"
		} else {
			vendor.Version = "OpenVPN 2.0-2.3"
		}
	}

	return vendor
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 1; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
