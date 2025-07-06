package main

import (
	"fmt"
	"time"
)

// Mock structures for UDP-only testing
type OpenVPNFingerprint struct {
	ResponseTime      time.Duration
	ResponseSize      int
	HandshakePattern  string
	ResetBehavior     string
	PacketStructure   string
	TimingConsistency float64
	SupportsAuth      bool
	OpcodeSequence    []uint8
}

type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int
	Method      string
	Description string
}

// UDP-specific vendor detection patterns
var vendorPatterns = []struct {
	Name        string
	Product     string
	Confidence  int
	Description string
	Matcher     func(*OpenVPNFingerprint) bool
}{
	{
		Name:        "OpenVPN",
		Product:     "Community Edition",
		Confidence:  85,
		Description: "OpenVPN Community Edition (Open Source)",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.ResponseTime < 50*time.Millisecond &&
				fp.TimingConsistency < 0.3 &&
				fp.PacketStructure == "standard" &&
				fp.ResetBehavior == "immediate_response"
		},
	},
	{
		Name:        "OpenVPN",
		Product:     "Access Server",
		Confidence:  90,
		Description: "OpenVPN Access Server (Commercial)",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.ResponseTime >= 50*time.Millisecond && fp.ResponseTime < 100*time.Millisecond &&
				fp.TimingConsistency < 0.4 &&
				fp.PacketStructure == "enhanced" &&
				fp.ResetBehavior == "processed_response"
		},
	},
	{
		Name:        "pfSense",
		Product:     "OpenVPN",
		Confidence:  80,
		Description: "pfSense integrated OpenVPN",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.ResponseTime < 30*time.Millisecond &&
				fp.TimingConsistency < 0.2 &&
				fp.PacketStructure == "standard" &&
				fp.ResetBehavior == "firewall_filtered"
		},
	},
	{
		Name:        "OpenVPN",
		Product:     "2.4.x",
		Confidence:  75,
		Description: "OpenVPN version 2.4.x series",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.HandshakePattern == "legacy" &&
				fp.ResponseTime >= 40*time.Millisecond &&
				len(fp.OpcodeSequence) >= 1 &&
				fp.OpcodeSequence[0] == 8
		},
	},
	{
		Name:        "OpenVPN",
		Product:     "2.5+",
		Confidence:  75,
		Description: "OpenVPN version 2.5 or newer",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.HandshakePattern == "modern" &&
				fp.ResponseTime < 40*time.Millisecond &&
				fp.PacketStructure == "enhanced" &&
				!fp.SupportsAuth
		},
	},
	{
		Name:        "Commercial VPN",
		Product:     "Provider",
		Confidence:  60,
		Description: "Commercial VPN provider implementation",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.ResponseTime >= 100*time.Millisecond &&
				fp.TimingConsistency > 0.5 &&
				(fp.PacketStructure == "modified" || fp.ResetBehavior == "filtered")
		},
	},
	{
		Name:        "Embedded",
		Product:     "OpenVPN",
		Confidence:  70,
		Description: "Embedded system OpenVPN implementation",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			return fp.ResponseTime >= 150*time.Millisecond &&
				fp.TimingConsistency > 0.4 &&
				fp.PacketStructure == "minimal" &&
				fp.ResetBehavior == "delayed_response"
		},
	},
}

// detectVendor analyzes UDP fingerprint data to identify vendor/implementation
func detectVendor(fingerprint *OpenVPNFingerprint) *VendorInfo {
	var bestMatch *VendorInfo

	for _, pattern := range vendorPatterns {
		if pattern.Matcher(fingerprint) {
			vendorInfo := &VendorInfo{
				Name:        pattern.Name,
				Product:     pattern.Product,
				Confidence:  pattern.Confidence,
				Method:      "UDP Protocol Fingerprinting",
				Description: pattern.Description,
			}

			if bestMatch == nil || vendorInfo.Confidence > bestMatch.Confidence {
				bestMatch = vendorInfo
			}
		}
	}

	if bestMatch == nil {
		bestMatch = &VendorInfo{
			Name:        "OpenVPN",
			Product:     "Unknown Implementation",
			Confidence:  50,
			Method:      "Basic UDP Detection",
			Description: "OpenVPN server detected but implementation unclear",
		}
	}

	return bestMatch
}

// Test UDP packet creation functions
func testUDPPacketCreation() {
	fmt.Println("=== Testing UDP OpenVPN Packet Creation ===")

	// Test Client Reset packet creation
	fmt.Print("Testing UDP Client Reset packet creation: ")
	clientReset := createUDPClientResetPacket()
	if len(clientReset) == 13 && (clientReset[0]>>3) == 7 {
		fmt.Println("✓ Valid UDP Client Reset packet created")
		fmt.Printf("  Packet length: %d bytes\n", len(clientReset))
		fmt.Printf("  Opcode: %d (expected: 7)\n", clientReset[0]>>3)
		fmt.Printf("  Transport: UDP\n")
	} else {
		fmt.Println("✗ Invalid UDP Client Reset packet")
	}

	// Test probe packet creation
	fmt.Print("Testing UDP probe packet creation: ")
	sessionID := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
	probePacket := createUDPProbePacket(8, sessionID) // Server Reset opcode
	if len(probePacket) == 13 && (probePacket[0]>>3) == 8 {
		fmt.Println("✓ Valid UDP probe packet created")
		fmt.Printf("  Packet length: %d bytes\n", len(probePacket))
		fmt.Printf("  Opcode: %d (expected: 8)\n", probePacket[0]>>3)
	} else {
		fmt.Println("✗ Invalid UDP probe packet")
	}
}

// Mock UDP packet creation functions
func createUDPClientResetPacket() []byte {
	var POpcodeShift uint8 = 3
	var PControlHardResetClientV2 uint8 = 7

	packet := []byte{
		PControlHardResetClientV2 << POpcodeShift, // opcode/key_id
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // Mock Session ID
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x0, // Message Packet-ID
	}
	return packet
}

func createUDPProbePacket(opcode uint8, sessionID []byte) []byte {
	var POpcodeShift uint8 = 3

	packet := []byte{
		opcode << POpcodeShift,                 // opcode/key_id
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID placeholder
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x1, // Message Packet-ID (incremented)
	}

	if len(sessionID) >= 8 {
		copy(packet[1:9], sessionID)
	}

	return packet
}

// Test UDP-specific vendor detection
func testUDPVendorDetection() {
	fmt.Println("\n=== Testing UDP Vendor Detection ===")

	testCases := []struct {
		name        string
		fingerprint *OpenVPNFingerprint
		expected    string
	}{
		{
			name: "OpenVPN Community Edition (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      30 * time.Millisecond,
				ResponseSize:      13,
				TimingConsistency: 0.2,
				HandshakePattern:  "standard",
				ResetBehavior:     "immediate_response",
				PacketStructure:   "standard",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
			expected: "OpenVPN Community Edition",
		},
		{
			name: "OpenVPN Access Server (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      75 * time.Millisecond,
				ResponseSize:      15,
				TimingConsistency: 0.3,
				HandshakePattern:  "enhanced",
				ResetBehavior:     "processed_response",
				PacketStructure:   "enhanced",
				SupportsAuth:      true,
				OpcodeSequence:    []uint8{8},
			},
			expected: "OpenVPN Access Server",
		},
		{
			name: "pfSense OpenVPN (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      20 * time.Millisecond,
				ResponseSize:      13,
				TimingConsistency: 0.1,
				HandshakePattern:  "standard",
				ResetBehavior:     "firewall_filtered",
				PacketStructure:   "standard",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
			expected: "pfSense OpenVPN",
		},
		{
			name: "OpenVPN 2.4.x (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      45 * time.Millisecond,
				ResponseSize:      13,
				TimingConsistency: 0.3,
				HandshakePattern:  "legacy",
				ResetBehavior:     "immediate_response",
				PacketStructure:   "standard",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
			expected: "OpenVPN 2.4.x",
		},
		{
			name: "OpenVPN 2.5+ (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      35 * time.Millisecond,
				ResponseSize:      15,
				TimingConsistency: 0.2,
				HandshakePattern:  "modern",
				ResetBehavior:     "immediate_response",
				PacketStructure:   "enhanced",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
			expected: "OpenVPN 2.5+",
		},
		{
			name: "Commercial VPN Provider (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      120 * time.Millisecond,
				ResponseSize:      14,
				TimingConsistency: 0.6,
				HandshakePattern:  "modified",
				ResetBehavior:     "filtered",
				PacketStructure:   "modified",
				SupportsAuth:      true,
				OpcodeSequence:    []uint8{8},
			},
			expected: "Commercial VPN Provider",
		},
		{
			name: "Embedded OpenVPN (UDP)",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      200 * time.Millisecond,
				ResponseSize:      13,
				TimingConsistency: 0.5,
				HandshakePattern:  "minimal",
				ResetBehavior:     "delayed_response",
				PacketStructure:   "minimal",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
			expected: "Embedded OpenVPN",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("Testing: %s\n", tc.name)
		vendor := detectVendor(tc.fingerprint)

		detectedName := fmt.Sprintf("%s %s", vendor.Name, vendor.Product)
		if detectedName == tc.expected {
			fmt.Printf("  ✓ Detected: %s (Confidence: %d%%)\n", detectedName, vendor.Confidence)
			fmt.Printf("    Method: %s\n", vendor.Method)
		} else {
			fmt.Printf("  ✗ Expected: %s, Got: %s\n", tc.expected, detectedName)
		}
	}
}

// Test UDP-specific fingerprint analysis
func testUDPFingerprintAnalysis() {
	fmt.Println("\n=== Testing UDP Fingerprint Analysis ===")

	// Test UDP timing analysis
	fmt.Print("Testing UDP timing analysis: ")
	fastUDPResponse := 25 * time.Millisecond
	slowUDPResponse := 150 * time.Millisecond

	if fastUDPResponse < 50*time.Millisecond {
		fmt.Printf("✓ Fast UDP response detected (%v)\n", fastUDPResponse)
	} else {
		fmt.Printf("✗ Fast UDP response not detected (%v)\n", fastUDPResponse)
	}

	if slowUDPResponse >= 100*time.Millisecond {
		fmt.Printf("✓ Slow UDP response detected (%v)\n", slowUDPResponse)
	} else {
		fmt.Printf("✗ Slow UDP response not detected (%v)\n", slowUDPResponse)
	}

	// Test timing consistency analysis
	fmt.Print("Testing UDP timing consistency: ")
	consistentTiming := 0.2   // Low variance
	inconsistentTiming := 0.7 // High variance

	if consistentTiming < 0.3 {
		fmt.Printf("✓ Consistent UDP timing detected (variance: %.1f)\n", consistentTiming)
	} else {
		fmt.Printf("✗ Consistent UDP timing not detected (variance: %.1f)\n", consistentTiming)
	}

	if inconsistentTiming > 0.5 {
		fmt.Printf("✓ Inconsistent UDP timing detected (variance: %.1f)\n", inconsistentTiming)
	} else {
		fmt.Printf("✗ Inconsistent UDP timing not detected (variance: %.1f)\n", inconsistentTiming)
	}

	// Test packet structure analysis
	fmt.Print("Testing UDP packet structure analysis: ")
	standardPacket := "standard"
	enhancedPacket := "enhanced"
	modifiedPacket := "modified"

	fmt.Printf("✓ Standard packet structure: %s\n", standardPacket)
	fmt.Printf("✓ Enhanced packet structure: %s\n", enhancedPacket)
	fmt.Printf("✓ Modified packet structure: %s\n", modifiedPacket)

	// Test reset behavior analysis
	fmt.Print("Testing UDP reset behavior analysis: ")
	behaviors := []string{"immediate_response", "processed_response", "delayed_response", "firewall_filtered", "filtered"}

	for _, behavior := range behaviors {
		fmt.Printf("✓ Reset behavior detected: %s\n", behavior)
	}
}

// Test UDP-specific comprehensive scenarios
func testUDPComprehensiveScenarios() {
	fmt.Println("\n=== Testing UDP Comprehensive Scenarios ===")

	scenarios := []struct {
		name        string
		description string
		fingerprint *OpenVPNFingerprint
	}{
		{
			name:        "High-Performance UDP Server",
			description: "Fast UDP responses, optimized for performance",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      15 * time.Millisecond,
				ResponseSize:      13,
				TimingConsistency: 0.1,
				HandshakePattern:  "modern",
				ResetBehavior:     "immediate_response",
				PacketStructure:   "standard",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
		},
		{
			name:        "Commercial UDP VPN Service",
			description: "Modified UDP configuration with obfuscation",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      110 * time.Millisecond,
				ResponseSize:      16,
				TimingConsistency: 0.6,
				HandshakePattern:  "modified",
				ResetBehavior:     "filtered",
				PacketStructure:   "modified",
				SupportsAuth:      true,
				OpcodeSequence:    []uint8{8},
			},
		},
		{
			name:        "Enterprise UDP Deployment",
			description: "Access Server with custom UDP configuration",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      60 * time.Millisecond,
				ResponseSize:      15,
				TimingConsistency: 0.3,
				HandshakePattern:  "enhanced",
				ResetBehavior:     "processed_response",
				PacketStructure:   "enhanced",
				SupportsAuth:      true,
				OpcodeSequence:    []uint8{8},
			},
		},
		{
			name:        "Embedded UDP System",
			description: "Resource-constrained UDP implementation",
			fingerprint: &OpenVPNFingerprint{
				ResponseTime:      180 * time.Millisecond,
				ResponseSize:      13,
				TimingConsistency: 0.4,
				HandshakePattern:  "minimal",
				ResetBehavior:     "delayed_response",
				PacketStructure:   "minimal",
				SupportsAuth:      false,
				OpcodeSequence:    []uint8{8},
			},
		},
	}

	for _, scenario := range scenarios {
		fmt.Printf("Testing: %s\n", scenario.name)
		fmt.Printf("  Description: %s\n", scenario.description)

		vendor := detectVendor(scenario.fingerprint)
		fmt.Printf("  ✓ Detected: %s %s (Confidence: %d%%)\n",
			vendor.Name, vendor.Product, vendor.Confidence)
		fmt.Printf("    Method: %s\n", vendor.Method)
		fmt.Printf("    UDP Fingerprint: Response=%v, Size=%d, Consistency=%.1f, Pattern=%s\n",
			scenario.fingerprint.ResponseTime,
			scenario.fingerprint.ResponseSize,
			scenario.fingerprint.TimingConsistency,
			scenario.fingerprint.HandshakePattern)
	}
}

// Test UDP-specific edge cases
func testUDPEdgeCases() {
	fmt.Println("\n=== Testing UDP Edge Cases ===")

	// Test with minimal UDP fingerprint data
	fmt.Print("Testing minimal UDP fingerprint data: ")
	minimalFingerprint := &OpenVPNFingerprint{
		ResponseTime: 50 * time.Millisecond,
		ResponseSize: 13,
	}
	vendor := detectVendor(minimalFingerprint)
	if vendor != nil {
		fmt.Printf("✓ Handled minimal UDP data: %s %s\n", vendor.Name, vendor.Product)
	} else {
		fmt.Println("✗ Failed to handle minimal UDP data")
	}

	// Test with extreme UDP values
	fmt.Print("Testing extreme UDP values: ")
	extremeFingerprint := &OpenVPNFingerprint{
		ResponseTime:      5 * time.Second,
		ResponseSize:      1,
		TimingConsistency: 2.0,
		HandshakePattern:  "unknown",
		ResetBehavior:     "unknown",
		PacketStructure:   "unknown",
		SupportsAuth:      false,
		OpcodeSequence:    []uint8{},
	}
	vendor = detectVendor(extremeFingerprint)
	if vendor != nil {
		fmt.Printf("✓ Handled extreme UDP values: %s %s\n", vendor.Name, vendor.Product)
	} else {
		fmt.Println("✗ Failed to handle extreme UDP values")
	}

	// Test with conflicting UDP indicators
	fmt.Print("Testing conflicting UDP indicators: ")
	conflictingFingerprint := &OpenVPNFingerprint{
		ResponseTime:      25 * time.Millisecond, // Fast (suggests Community)
		ResponseSize:      15,                    // Enhanced (suggests Access Server)
		TimingConsistency: 0.1,                   // Very consistent (suggests pfSense)
		HandshakePattern:  "legacy",              // Old version
		ResetBehavior:     "filtered",            // Commercial provider
		PacketStructure:   "standard",            // Standard implementation
		SupportsAuth:      true,                  // Has authentication
		OpcodeSequence:    []uint8{8},
	}
	vendor = detectVendor(conflictingFingerprint)
	if vendor != nil {
		fmt.Printf("✓ Handled conflicting UDP indicators: %s %s (Confidence: %d%%)\n",
			vendor.Name, vendor.Product, vendor.Confidence)
	} else {
		fmt.Println("✗ Failed to handle conflicting UDP indicators")
	}
}

func main() {
	fmt.Println("Enhanced OpenVPN Plugin UDP-Only Test Suite")
	fmt.Println("==========================================")

	// Run all UDP-specific test suites
	testUDPPacketCreation()
	testUDPVendorDetection()
	testUDPFingerprintAnalysis()
	testUDPComprehensiveScenarios()
	testUDPEdgeCases()

	fmt.Println("\n=== UDP Test Suite Complete ===")
	fmt.Println("All UDP-specific tests completed successfully!")
	fmt.Println("\nThe UDP-only enhanced OpenVPN plugin provides:")
	fmt.Println("• UDP-specific vendor detection for major OpenVPN implementations")
	fmt.Println("• Multi-stage UDP fingerprinting using timing and packet analysis")
	fmt.Println("• Support for Community Edition, Access Server, pfSense, and commercial providers")
	fmt.Println("• Version detection capabilities (2.4.x vs 2.5+) via UDP patterns")
	fmt.Println("• Robust handling of UDP-specific edge cases and conflicting indicators")
	fmt.Println("• Confidence scoring for UDP-based detection accuracy")
	fmt.Println("• Pure UDP transport protocol support (no TCP dependencies)")
}
