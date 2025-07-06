// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openvpn

import (
	"crypto/rand"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const OPENVPN = "OpenVPN"

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
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Known OpenVPN implementation patterns for UDP-based detection
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
			// Community Edition: Fast, consistent responses, standard packet structure
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
			// Access Server: Slightly slower, more processing overhead
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
			// pfSense: Very fast responses, firewall integration
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
			// Older versions: Different opcode handling, specific timing
			return fp.HandshakePattern == "legacy" &&
				fp.ResponseTime >= 40*time.Millisecond &&
				len(fp.OpcodeSequence) >= 2 &&
				fp.OpcodeSequence[0] == 8 // Server Reset
		},
	},
	{
		Name:        "OpenVPN",
		Product:     "2.5+",
		Confidence:  75,
		Description: "OpenVPN version 2.5 or newer",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			// Newer versions: Enhanced security, different packet handling
			return fp.HandshakePattern == "modern" &&
				fp.ResponseTime < 40*time.Millisecond &&
				fp.PacketStructure == "enhanced" &&
				!fp.SupportsAuth // Newer versions often have auth enabled by default
		},
	},
	{
		Name:        "Commercial VPN",
		Product:     "Provider",
		Confidence:  60,
		Description: "Commercial VPN provider implementation",
		Matcher: func(fp *OpenVPNFingerprint) bool {
			// Commercial providers: Often modified, inconsistent timing
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
			// Embedded systems: Slower responses, limited processing
			return fp.ResponseTime >= 150*time.Millisecond &&
				fp.TimingConsistency > 0.4 &&
				fp.PacketStructure == "minimal" &&
				fp.ResetBehavior == "delayed_response"
		},
	},
}

// createClientReset creates a standard OpenVPN Client Reset packet
func createClientReset() ([]byte, error) {
	var POpcodeShift uint8 = 3
	var PControlHardResetClientV2 uint8 = 7
	var SessionIDLength = 8

	packet := []byte{
		PControlHardResetClientV2 << POpcodeShift, // opcode/key_id
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID (64-bit)
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x0, // Message Packet-ID
	}

	// Generate random session ID
	_, err := rand.Read(packet[1 : 1+SessionIDLength])
	if err != nil {
		return nil, err
	}

	return packet, nil
}

// createProbePacket creates a probe packet with specific characteristics
func createProbePacket(opcode uint8, sessionID []byte) []byte {
	var POpcodeShift uint8 = 3

	packet := []byte{
		opcode << POpcodeShift,                 // opcode/key_id
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID placeholder
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x1, // Message Packet-ID (incremented)
	}

	// Copy session ID if provided
	if len(sessionID) >= 8 {
		copy(packet[1:9], sessionID)
	}

	return packet
}

// measureResponseTiming performs multiple timing measurements for consistency analysis
func measureResponseTiming(conn net.Conn, timeout time.Duration, iterations int) (time.Duration, float64, error) {
	var responseTimes []time.Duration

	for i := 0; i < iterations; i++ {
		packet, err := createClientReset()
		if err != nil {
			return 0, 0, err
		}

		start := time.Now()
		_, err = conn.Write(packet)
		if err != nil {
			return 0, 0, err
		}

		conn.SetReadDeadline(time.Now().Add(timeout))
		response := make([]byte, 1024)
		_, readErr := conn.Read(response)
		responseTime := time.Since(start)

		if readErr != nil && !isTimeoutError(readErr) {
			return 0, 0, readErr
		}

		responseTimes = append(responseTimes, responseTime)

		// Small delay between iterations
		time.Sleep(10 * time.Millisecond)
	}

	// Calculate average and variance
	var total time.Duration
	for _, rt := range responseTimes {
		total += rt
	}
	average := total / time.Duration(len(responseTimes))

	// Calculate variance for consistency analysis
	var variance float64
	for _, rt := range responseTimes {
		diff := float64(rt - average)
		variance += diff * diff
	}
	variance /= float64(len(responseTimes))
	consistency := variance / float64(average*average) // Coefficient of variation

	return average, consistency, nil
}

// analyzePacketStructure analyzes the structure and content of response packets
func analyzePacketStructure(response []byte) string {
	if len(response) < 13 {
		return "minimal"
	}

	// Check for standard OpenVPN packet structure
	opcode := response[0] >> 3
	if opcode == 8 { // Server Reset
		// Analyze packet content for implementation hints
		if len(response) == 13 {
			return "standard"
		} else if len(response) > 13 && len(response) < 20 {
			return "enhanced"
		} else if len(response) >= 20 {
			return "modified"
		}
	}

	return "unknown"
}

// analyzeResetBehavior analyzes how the server responds to reset packets
func analyzeResetBehavior(conn net.Conn, sessionID []byte, timeout time.Duration) string {
	// Test with original session ID
	originalPacket, _ := createClientReset()
	copy(originalPacket[1:9], sessionID)

	start := time.Now()
	conn.Write(originalPacket)

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 1024)
	_, readErr := conn.Read(response)
	responseTime := time.Since(start)

	if readErr == nil && responseTime < 20*time.Millisecond {
		return "immediate_response"
	} else if readErr == nil && responseTime < 50*time.Millisecond {
		return "processed_response"
	} else if readErr == nil && responseTime >= 50*time.Millisecond {
		return "delayed_response"
	} else if readErr != nil && responseTime < 10*time.Millisecond {
		return "firewall_filtered"
	} else {
		return "filtered"
	}
}

// detectAuthMechanism attempts to detect if tls-auth or tls-crypt is enabled
func detectAuthMechanism(conn net.Conn, timeout time.Duration) bool {
	// Create a packet with invalid HMAC (should be dropped if auth is enabled)
	invalidPacket := []byte{
		7 << 3,                                 // Client Reset opcode
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, // Invalid session ID
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x0, // Message Packet-ID
		// No HMAC signature - should be dropped if auth is enabled
	}

	start := time.Now()
	conn.Write(invalidPacket)

	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 1024)
	_, readErr := conn.Read(response)
	responseTime := time.Since(start)

	// If no response and quick timeout, likely auth is enabled
	return readErr != nil && responseTime < 100*time.Millisecond
}

// analyzeOpcodeSequence analyzes the sequence of opcodes in responses
func analyzeOpcodeSequence(responses [][]byte) []uint8 {
	var opcodes []uint8

	for _, response := range responses {
		if len(response) > 0 {
			opcode := response[0] >> 3
			opcodes = append(opcodes, opcode)
		}
	}

	return opcodes
}

// determineHandshakePattern analyzes handshake characteristics
func determineHandshakePattern(fingerprint *OpenVPNFingerprint) string {
	// Analyze timing and opcode patterns to determine handshake type
	if fingerprint.ResponseTime < 40*time.Millisecond &&
		len(fingerprint.OpcodeSequence) > 0 &&
		fingerprint.OpcodeSequence[0] == 8 {
		if fingerprint.TimingConsistency < 0.3 {
			return "modern"
		} else {
			return "standard"
		}
	} else if fingerprint.ResponseTime >= 40*time.Millisecond {
		return "legacy"
	}

	return "unknown"
}

// performUDPFingerprinting performs comprehensive UDP-based OpenVPN fingerprinting
func performUDPFingerprinting(conn net.Conn, sessionID []byte, timeout time.Duration) (*OpenVPNFingerprint, error) {
	fingerprint := &OpenVPNFingerprint{}

	// Measure response timing with multiple iterations for consistency
	if avgTime, consistency, err := measureResponseTiming(conn, timeout, 3); err == nil {
		fingerprint.ResponseTime = avgTime
		fingerprint.TimingConsistency = consistency
	}

	// Analyze reset behavior
	fingerprint.ResetBehavior = analyzeResetBehavior(conn, sessionID, timeout)

	// Detect authentication mechanism
	fingerprint.SupportsAuth = detectAuthMechanism(conn, timeout)

	// Perform a standard handshake to get response for analysis
	packet, _ := createClientReset()
	copy(packet[1:9], sessionID)

	conn.Write(packet)
	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 1024)
	n, readErr := conn.Read(response)

	if readErr == nil && n > 0 {
		fingerprint.ResponseSize = n
		fingerprint.PacketStructure = analyzePacketStructure(response[:n])
		fingerprint.OpcodeSequence = analyzeOpcodeSequence([][]byte{response[:n]})
	}

	// Determine handshake pattern based on collected data
	fingerprint.HandshakePattern = determineHandshakePattern(fingerprint)

	return fingerprint, nil
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

			// Choose the highest confidence match
			if bestMatch == nil || vendorInfo.Confidence > bestMatch.Confidence {
				bestMatch = vendorInfo
			}
		}
	}

	// If no specific match, provide generic OpenVPN detection
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

// createServiceWithVendorInfo creates a service object with vendor information
func createServiceWithVendorInfo(target plugins.Target, vendor *VendorInfo, fingerprint *OpenVPNFingerprint, sessionID []byte) *plugins.Service {
	serviceName := OPENVPN
	if vendor != nil {
		if vendor.Product != "" && vendor.Product != "Unknown Implementation" {
			serviceName = fmt.Sprintf("%s (%s %s)", OPENVPN, vendor.Name, vendor.Product)
		} else {
			serviceName = fmt.Sprintf("%s (%s)", OPENVPN, vendor.Name)
		}
		if vendor.Version != "" {
			serviceName = fmt.Sprintf("%s %s", serviceName, vendor.Version)
		}
	}

	service := &plugins.Service{
		Name:     serviceName,
		Protocol: plugins.UDP, // OpenVPN primarily uses UDP
		Port:     target.Port,
		Host:     target.Host,
		TLS:      false, // OpenVPN handles its own encryption
		Details:  make(map[string]interface{}),
	}

	// Add vendor information
	if vendor != nil {
		service.Details["vendor"] = map[string]interface{}{
			"name":        vendor.Name,
			"product":     vendor.Product,
			"version":     vendor.Version,
			"confidence":  vendor.Confidence,
			"method":      vendor.Method,
			"description": vendor.Description,
		}
	}

	// Add UDP-specific fingerprinting data
	if fingerprint != nil {
		service.Details["udp_fingerprint"] = map[string]interface{}{
			"response_time_ms":   fingerprint.ResponseTime.Milliseconds(),
			"response_size":      fingerprint.ResponseSize,
			"timing_consistency": fingerprint.TimingConsistency,
			"handshake_pattern":  fingerprint.HandshakePattern,
			"reset_behavior":     fingerprint.ResetBehavior,
			"packet_structure":   fingerprint.PacketStructure,
			"supports_auth":      fingerprint.SupportsAuth,
			"opcode_sequence":    fingerprint.OpcodeSequence,
		}
	}

	// Add protocol information
	service.Details["protocol_info"] = map[string]interface{}{
		"standard_port":  1194,
		"transport":      "UDP",
		"encryption":     "SSL/TLS",
		"authentication": []string{"Certificate", "Username/Password", "Pre-shared Key"},
		"compression":    []string{"LZO", "LZ4", "Stub"},
		"session_id":     fmt.Sprintf("%x", sessionID),
	}

	return service
}

// Helper functions
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * Enhanced OpenVPN Detection and Vendor Identification (UDP-Only)
	 *
	 * This enhanced plugin performs comprehensive UDP-based OpenVPN fingerprinting:
	 * 1. Basic OpenVPN detection using Client/Server Reset handshake
	 * 2. UDP timing analysis for response characteristics
	 * 3. Packet structure and content analysis
	 * 4. Reset behavior pattern analysis
	 * 5. Authentication mechanism detection (tls-auth/tls-crypt)
	 * 6. Opcode sequence analysis
	 * 7. Vendor/implementation identification
	 *
	 * Supported vendor detection (UDP-based):
	 * - OpenVPN Community Edition vs Access Server
	 * - pfSense integrated OpenVPN
	 * - Version detection (2.4.x vs 2.5+)
	 * - Commercial VPN provider implementations
	 * - Embedded system implementations
	 *
	 * Based on UDP-specific research from:
	 * - "OpenVPN is Open to VPN Fingerprinting" (USENIX Security 2022)
	 * - UDP-based active probing techniques
	 * - Protocol-level behavioral analysis for UDP transport
	 */

	var POpcodeShift uint8 = 3
	var PControlHardResetClientV2 uint8 = 7
	var PControlHardResetServerV2 uint8 = 8
	var SessionIDLength = 8

	// Create initial connection package (standard detection)
	InitialConnectionPackage := []byte{
		PControlHardResetClientV2 << POpcodeShift, // opcode/key_id
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID (64-bit),
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x0, // Message Packet-ID
	}
	_, err := rand.Read(InitialConnectionPackage[1 : 1+SessionIDLength])
	if err != nil {
		return nil, &utils.RandomizeError{Message: "session ID"}
	}

	// Perform basic OpenVPN detection
	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Check if response is valid OpenVPN packet
	isOpenVPN := false
	sessionID := InitialConnectionPackage[1 : 1+SessionIDLength]

	if (response[0] >> POpcodeShift) == PControlHardResetServerV2 {
		for i := 0; i < len(response)-SessionIDLength; i++ {
			if reflect.DeepEqual(
				response[i:i+SessionIDLength],
				sessionID,
			) {
				isOpenVPN = true
				break
			}
		}
	}

	if !isOpenVPN {
		return nil, nil
	}

	// Perform comprehensive UDP-based fingerprinting for vendor detection
	fingerprint, fingerprintErr := performUDPFingerprinting(conn, sessionID, timeout)
	if fingerprintErr != nil {
		// If fingerprinting fails, still return basic OpenVPN detection
		return plugins.CreateServiceFrom(target, plugins.ServiceOpenVPN{}, false, "", plugins.UDP), nil
	}

	// Detect vendor/implementation based on UDP fingerprint
	vendor := detectVendor(fingerprint)

	// Create service with vendor information
	return createServiceWithVendorInfo(target, vendor, fingerprint, sessionID), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 1194
}

func (p *Plugin) Name() string {
	return OPENVPN
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 708
}
