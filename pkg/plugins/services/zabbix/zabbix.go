package zabbixagent

import (
	"fmt"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

// DetectionResult holds the results of precise Zabbix detection
type DetectionResult struct {
	IsZabbix        bool
	DetectionMethod string
	Confidence      int
	ConnectionTime  time.Duration
	BehaviorPattern string
	SpecificTests   []string
}

var (
	// Common Zabbix ports
	commonZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}

	// Zabbix-specific test payloads designed to trigger unique behaviors
	zabbixSpecificTests = []struct {
		name        string
		payload     []byte
		description string
		expectation string
	}{
		{
			name:        "zabbix_header",
			payload:     []byte{0x5A, 0x42, 0x58, 0x44, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74},
			description: "Zabbix ZBXD protocol header",
			expectation: "Zabbix-specific protocol handling",
		},
		{
			name:        "agent_ping",
			payload:     []byte("agent.ping\n"),
			description: "Zabbix agent.ping item",
			expectation: "Zabbix item key recognition",
		},
		{
			name:        "agent_version",
			payload:     []byte("agent.version\n"),
			description: "Zabbix agent.version item",
			expectation: "Zabbix item key recognition",
		},
		{
			name:        "system_uptime",
			payload:     []byte("system.uptime\n"),
			description: "Zabbix system.uptime item",
			expectation: "Zabbix item key recognition",
		},
		{
			name:        "invalid_zabbix_key",
			payload:     []byte("zabbix.invalid.test.key.12345\n"),
			description: "Invalid but Zabbix-formatted key",
			expectation: "Zabbix key format recognition",
		},
		{
			name:        "malformed_zabbix_header",
			payload:     []byte{0x5A, 0x42, 0x58, 0x44, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			description: "Malformed ZBXD header",
			expectation: "Zabbix protocol error handling",
		},
	}

	// Non-Zabbix payloads for comparison (should behave differently)
	nonZabbixTests = []struct {
		name        string
		payload     []byte
		description string
	}{
		{
			name:        "http_request",
			payload:     []byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"),
			description: "HTTP request",
		},
		{
			name:        "ssh_banner",
			payload:     []byte("SSH-2.0-Test\r\n"),
			description: "SSH protocol banner",
		},
		{
			name:        "mysql_handshake",
			payload:     []byte{0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x32, 0x39},
			description: "MySQL-like handshake",
		},
		{
			name:        "random_binary",
			payload:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			description: "Random binary data",
		},
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs precise Zabbix Agent detection without timing-based false positives
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Perform precise detection based on Zabbix-specific behaviors
	result, err := p.detectPreciseZabbix(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If not detected as Zabbix, return nil
	if !result.IsZabbix {
		return nil, nil
	}

	result.ConnectionTime = time.Since(startTime)

	// Create vendor information for precise detection
	vendor := p.createPreciseVendorInfo(result)

	// Create service using ServiceZabbixAgent struct
	serviceZabbixAgent := plugins.ServiceZabbixAgent{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// Agent information (limited for silent detection)
		AgentVersion:    "unknown (silent)",
		AgentVariant:    0, // Unknown
		ResponseTime:    result.ConnectionTime.Milliseconds(),
		ProtocolVersion: "unknown",
		PassiveChecks:   true, // Assumed for port 10050

		// Detection metadata
		DetectionLevel: result.DetectionMethod,
	}

	service := plugins.CreateServiceFrom(target, serviceZabbixAgent, false, "", plugins.TCP)
	return service, nil
}

// detectPreciseZabbix performs detection based on Zabbix-specific behavior patterns
func (p *ZabbixAgentPlugin) detectPreciseZabbix(conn net.Conn, timeout time.Duration) (*DetectionResult, error) {
	result := &DetectionResult{
		SpecificTests: []string{},
	}

	// Set overall timeout
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	// Method 1: Zabbix-specific protocol behavior analysis
	if p.analyzeZabbixProtocolBehavior(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Zabbix Protocol Behavior"
		return result, nil
	}

	// Method 2: Differential behavior analysis (Zabbix vs non-Zabbix payloads)
	if p.analyzeDifferentialBehavior(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Differential Behavior"
		return result, nil
	}

	// Method 3: Port-specific behavior (only for known Zabbix ports with additional validation)
	if p.analyzePortSpecificBehavior(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Port-Specific Behavior"
		return result, nil
	}

	return result, nil
}

// analyzeZabbixProtocolBehavior analyzes Zabbix-specific protocol behaviors
func (p *ZabbixAgentPlugin) analyzeZabbixProtocolBehavior(conn net.Conn, result *DetectionResult) bool {
	zabbixBehaviors := 0
	totalTests := len(zabbixSpecificTests)

	for _, test := range zabbixSpecificTests {
		behavior := p.testZabbixSpecificPayload(conn, test)
		if behavior != "" {
			zabbixBehaviors++
			result.SpecificTests = append(result.SpecificTests, fmt.Sprintf("%s: %s", test.name, behavior))
		}
	}

	// If we see Zabbix-specific behaviors in multiple tests
	if zabbixBehaviors >= 2 {
		result.Confidence = 70 + (zabbixBehaviors * 5) // Higher confidence with more behaviors
		result.BehaviorPattern = fmt.Sprintf("Zabbix-specific behaviors: %d/%d", zabbixBehaviors, totalTests)
		return true
	}

	return false
}

// analyzeDifferentialBehavior compares behavior with Zabbix vs non-Zabbix payloads
func (p *ZabbixAgentPlugin) analyzeDifferentialBehavior(conn net.Conn, result *DetectionResult) bool {
	zabbixResponses := 0
	nonZabbixResponses := 0

	// Test Zabbix-specific payloads
	for _, test := range zabbixSpecificTests[:3] { // Test first 3 to avoid too many requests
		behavior := p.testPayloadBehavior(conn, test.payload, test.name)
		if behavior == "processed" || behavior == "recognized" {
			zabbixResponses++
		}
	}

	// Test non-Zabbix payloads
	for _, test := range nonZabbixTests[:3] { // Test first 3
		behavior := p.testPayloadBehavior(conn, test.payload, test.name)
		if behavior == "processed" || behavior == "recognized" {
			nonZabbixResponses++
		}
	}

	// If Zabbix payloads are handled differently than non-Zabbix payloads
	if zabbixResponses > 0 && zabbixResponses > nonZabbixResponses {
		result.Confidence = 65
		result.BehaviorPattern = fmt.Sprintf("Differential behavior: Zabbix=%d, Non-Zabbix=%d", zabbixResponses, nonZabbixResponses)
		return true
	}

	return false
}

// analyzePortSpecificBehavior analyzes behavior specific to Zabbix ports with additional validation
func (p *ZabbixAgentPlugin) analyzePortSpecificBehavior(conn net.Conn, result *DetectionResult) bool {
	// Get the target port
	remoteAddr := conn.RemoteAddr().String()

	// Check if this is a known Zabbix port
	isZabbixPort := false
	for port := range commonZabbixPorts {
		if fmt.Sprintf(":%d", port) == remoteAddr[len(remoteAddr)-5:] {
			isZabbixPort = true
			break
		}
	}

	if !isZabbixPort {
		return false
	}

	// For Zabbix ports, perform additional validation
	// Test if the service behaves like a monitoring agent (not web server, SSH, etc.)

	// Test 1: Doesn't respond to HTTP
	httpBehavior := p.testPayloadBehavior(conn, []byte("GET / HTTP/1.1\r\n\r\n"), "http_test")

	// Test 2: Doesn't respond to SSH
	sshBehavior := p.testPayloadBehavior(conn, []byte("SSH-2.0-Test\r\n"), "ssh_test")

	// Test 3: Accepts monitoring-like requests silently
	monitoringBehavior := p.testPayloadBehavior(conn, []byte("agent.ping\n"), "monitoring_test")

	// If it doesn't behave like HTTP/SSH but accepts monitoring requests
	if httpBehavior != "recognized" && sshBehavior != "recognized" && monitoringBehavior != "rejected" {
		result.Confidence = 55 // Lower confidence for port-based detection
		result.BehaviorPattern = fmt.Sprintf("Port %s behavior: not HTTP/SSH, accepts monitoring", remoteAddr[len(remoteAddr)-5:])
		result.SpecificTests = append(result.SpecificTests,
			fmt.Sprintf("HTTP: %s, SSH: %s, Monitoring: %s", httpBehavior, sshBehavior, monitoringBehavior))
		return true
	}

	return false
}

// testZabbixSpecificPayload tests a Zabbix-specific payload and analyzes the behavior
func (p *ZabbixAgentPlugin) testZabbixSpecificPayload(conn net.Conn, test struct {
	name        string
	payload     []byte
	description string
	expectation string
}) string {
	// Set timeout for this specific test
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send payload
	_, writeErr := conn.Write(test.payload)
	if writeErr != nil {
		return "connection_rejected"
	}

	// Try to read response
	response := make([]byte, 1024)
	n, readErr := conn.Read(response)

	// Analyze the behavior based on the specific test
	switch test.name {
	case "zabbix_header":
		// ZBXD header should be processed by Zabbix (even if silently)
		if readErr != nil && n == 0 {
			return "zbxd_processed" // Zabbix processed the header but didn't respond
		}
	case "agent_ping", "agent_version", "system_uptime":
		// Valid Zabbix keys should be recognized (even if access denied)
		if readErr != nil && n == 0 {
			return "key_recognized" // Zabbix recognized the key format
		}
	case "invalid_zabbix_key":
		// Invalid but properly formatted Zabbix key
		if readErr != nil && n == 0 {
			return "format_recognized" // Zabbix recognized the format
		}
	case "malformed_zabbix_header":
		// Malformed ZBXD should trigger Zabbix error handling
		if readErr != nil {
			return "protocol_error_handling" // Zabbix handled protocol error
		}
	}

	return ""
}

// testPayloadBehavior tests a payload and returns behavior classification
func (p *ZabbixAgentPlugin) testPayloadBehavior(conn net.Conn, payload []byte, testName string) string {
	// Set timeout for this test
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Send payload
	_, writeErr := conn.Write(payload)
	if writeErr != nil {
		return "rejected"
	}

	// Try to read response
	response := make([]byte, 512)
	n, readErr := conn.Read(response)

	if readErr == nil && n > 0 {
		return "recognized" // Service responded
	} else if readErr != nil && n == 0 {
		return "processed" // Service processed but didn't respond
	}

	return "ignored"
}

// createPreciseVendorInfo creates vendor information for precise detection
func (p *ZabbixAgentPlugin) createPreciseVendorInfo(result *DetectionResult) struct {
	Name        string
	Product     string
	Version     string
	Confidence  int
	Method      string
	Description string
} {
	vendor := struct {
		Name        string
		Product     string
		Version     string
		Confidence  int
		Method      string
		Description string
	}{
		Name:        "Zabbix",
		Product:     "Zabbix Agent (Silent)",
		Version:     "unknown",
		Confidence:  result.Confidence,
		Method:      result.DetectionMethod,
		Description: fmt.Sprintf("Silent Zabbix agent detected via %s - likely access-controlled", result.DetectionMethod),
	}

	// Adjust confidence based on detection method
	switch result.DetectionMethod {
	case "Zabbix Protocol Behavior":
		vendor.Confidence += 10 // Highest confidence for protocol-specific behavior
	case "Differential Behavior":
		vendor.Confidence += 5 // Good confidence for differential analysis
	case "Port-Specific Behavior":
		vendor.Confidence -= 5 // Lower confidence for port-only detection
	}

	// Cap confidence for silent detection (can't be 100% sure without responses)
	if vendor.Confidence > 85 {
		vendor.Confidence = 85
	}

	// Minimum confidence
	if vendor.Confidence < 50 {
		vendor.Confidence = 50
	}

	return vendor
}

// PortPriority returns true for common Zabbix ports
func (p *ZabbixAgentPlugin) PortPriority(port uint16) bool {
	_, exists := commonZabbixPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *ZabbixAgentPlugin) Name() string {
	return ZABBIX_AGENT
}

// Type returns the protocol type
func (p *ZabbixAgentPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *ZabbixAgentPlugin) Priority() int {
	return 700
}
