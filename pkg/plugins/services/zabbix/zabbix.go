package zabbixagent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

// DetectionResult holds the results of strict Zabbix detection
type DetectionResult struct {
	IsZabbix        bool
	DetectionMethod string
	Confidence      int
	Evidence        []string
	AgentVersion    string
	ProtocolVersion string
}

var (
	// ONLY standard Zabbix ports - no exceptions
	standardZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs STRICT Zabbix Agent detection - only returns match if 100% certain
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// STRICT REQUIREMENT 1: Must be on standard Zabbix port
	port := int(target.Address.Port())
	if _, isZabbixPort := standardZabbixPorts[port]; !isZabbixPort {
		return nil, nil // Not on Zabbix port = definitely not Zabbix
	}

	startTime := time.Now()

	// Perform strict detection requiring definitive Zabbix evidence
	result, err := p.detectStrictZabbix(conn, timeout)
	if err != nil {
		return nil, err
	}

	// STRICT REQUIREMENT 2: Must have definitive Zabbix evidence
	if !result.IsZabbix || result.Confidence < 95 {
		return nil, nil // Not 100% certain = no detection
	}

	responseTime := time.Since(startTime)

	// Create vendor information for confirmed Zabbix detection
	vendor := p.createConfirmedVendorInfo(result)

	// Create service using ServiceZabbixAgent struct
	serviceZabbixAgent := plugins.ServiceZabbixAgent{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// Agent information
		AgentVersion:    result.AgentVersion,
		AgentVariant:    p.determineAgentVariant(result.AgentVersion),
		ResponseTime:    responseTime.Milliseconds(),
		ProtocolVersion: result.ProtocolVersion,
		PassiveChecks:   port == 10050,
		ActiveChecks:    port == 10051,

		// Detection metadata
		DetectionLevel: result.DetectionMethod,
	}

	service := plugins.CreateServiceFrom(target, serviceZabbixAgent, false, "", plugins.TCP)
	return service, nil
}

// detectStrictZabbix performs STRICT detection requiring definitive Zabbix evidence
func (p *ZabbixAgentPlugin) detectStrictZabbix(conn net.Conn, timeout time.Duration) (*DetectionResult, error) {
	result := &DetectionResult{
		Evidence: []string{},
	}

	// Set overall timeout
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	// Method 1: Try to get actual Zabbix responses (highest confidence)
	if p.tryGetZabbixResponses(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Zabbix Protocol Response"
		result.Confidence = 99 // Near certain with actual responses
		return result, nil
	}

	// Method 2: Detect Zabbix protocol errors (high confidence)
	if p.detectZabbixProtocolErrors(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Zabbix Protocol Error"
		result.Confidence = 95 // High confidence with protocol errors
		return result, nil
	}

	// Method 3: Detect Zabbix-specific protocol handling (medium-high confidence)
	if p.detectZabbixProtocolHandling(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Zabbix Protocol Handling"
		result.Confidence = 90 // Good confidence with protocol handling
		return result, nil
	}

	// If none of the strict methods work, it's not Zabbix
	return result, nil
}

// tryGetZabbixResponses attempts to get actual Zabbix responses
func (p *ZabbixAgentPlugin) tryGetZabbixResponses(conn net.Conn, result *DetectionResult) bool {
	// Test items that might work even without authentication
	testItems := []string{
		"agent.ping",
		"agent.version",
		"agent.hostname",
		"system.uptime",
	}

	for _, item := range testItems {
		response, err := p.sendZabbixRequest(conn, item)
		if err != nil {
			continue
		}

		// Check for actual Zabbix responses
		if p.isValidZabbixResponse(response, item, result) {
			return true
		}
	}

	return false
}

// detectZabbixProtocolErrors looks for Zabbix-specific error messages
func (p *ZabbixAgentPlugin) detectZabbixProtocolErrors(conn net.Conn, result *DetectionResult) bool {
	// Send requests that should trigger Zabbix-specific errors
	errorTests := []struct {
		item     string
		expected []string
	}{
		{
			item: "invalid.zabbix.key.test.12345",
			expected: []string{
				"ZBX_NOTSUPPORTED",
				"Unsupported item key",
				"NOTSUPPORTED",
			},
		},
		{
			item: "system.run[invalid_command_test_12345]",
			expected: []string{
				"ZBX_NOTSUPPORTED",
				"Remote commands are not enabled",
				"NOTSUPPORTED",
			},
		},
	}

	for _, test := range errorTests {
		response, err := p.sendZabbixRequest(conn, test.item)
		if err != nil {
			continue
		}

		responseStr := string(response)
		for _, expectedError := range test.expected {
			if strings.Contains(responseStr, expectedError) {
				result.Evidence = append(result.Evidence, fmt.Sprintf("Zabbix error: %s", expectedError))
				return true
			}
		}
	}

	return false
}

// detectZabbixProtocolHandling detects Zabbix-specific protocol handling
func (p *ZabbixAgentPlugin) detectZabbixProtocolHandling(conn net.Conn, result *DetectionResult) bool {
	// Test ZBXD protocol header handling
	if p.testZBXDProtocol(conn, result) {
		return true
	}

	// Test JSON protocol (Zabbix 7.0+)
	if p.testZabbixJSONProtocol(conn, result) {
		return true
	}

	return false
}

// sendZabbixRequest sends a Zabbix item request and returns response
func (p *ZabbixAgentPlugin) sendZabbixRequest(conn net.Conn, item string) ([]byte, error) {
	// Set timeouts
	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Send plaintext request (legacy protocol)
	_, err := conn.Write([]byte(item + "\n"))
	if err != nil {
		return nil, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

// isValidZabbixResponse checks if response is a valid Zabbix response
func (p *ZabbixAgentPlugin) isValidZabbixResponse(response []byte, item string, result *DetectionResult) bool {
	responseStr := string(response)

	// Check for Zabbix version response
	if item == "agent.version" && p.isZabbixVersionResponse(responseStr, result) {
		return true
	}

	// Check for agent.ping response
	if item == "agent.ping" && (responseStr == "1" || responseStr == "1\n") {
		result.Evidence = append(result.Evidence, "Valid agent.ping response: 1")
		return true
	}

	// Check for system.uptime numeric response
	if item == "system.uptime" && p.isNumericResponse(responseStr) {
		result.Evidence = append(result.Evidence, "Valid system.uptime numeric response")
		return true
	}

	// Check for hostname response
	if item == "agent.hostname" && p.isValidHostnameResponse(responseStr) {
		result.Evidence = append(result.Evidence, "Valid agent.hostname response")
		return true
	}

	return false
}

// isZabbixVersionResponse checks if response is a Zabbix version
func (p *ZabbixAgentPlugin) isZabbixVersionResponse(response string, result *DetectionResult) bool {
	response = strings.TrimSpace(response)

	// Zabbix version patterns
	zabbixPatterns := []string{
		"Zabbix Agent",
		"zabbix_agentd",
		"Zabbix agent",
	}

	for _, pattern := range zabbixPatterns {
		if strings.Contains(response, pattern) {
			result.AgentVersion = response
			result.Evidence = append(result.Evidence, fmt.Sprintf("Zabbix version response: %s", response))
			return true
		}
	}

	// Version number patterns (e.g., "7.0.0", "6.4.10", "5.0.25")
	if p.isVersionNumber(response) {
		result.AgentVersion = response
		result.Evidence = append(result.Evidence, fmt.Sprintf("Version number response: %s", response))
		return true
	}

	return false
}

// isVersionNumber checks if string looks like a version number
func (p *ZabbixAgentPlugin) isVersionNumber(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}

	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}

	return true
}

// isNumericResponse checks if response is numeric (for uptime, etc.)
func (p *ZabbixAgentPlugin) isNumericResponse(response string) bool {
	response = strings.TrimSpace(response)
	_, err := strconv.ParseFloat(response, 64)
	return err == nil
}

// isValidHostnameResponse checks if response looks like a hostname
func (p *ZabbixAgentPlugin) isValidHostnameResponse(response string) bool {
	response = strings.TrimSpace(response)

	// Basic hostname validation
	if len(response) < 1 || len(response) > 253 {
		return false
	}

	// Should not contain spaces or special characters (basic check)
	if strings.Contains(response, " ") || strings.Contains(response, "\t") {
		return false
	}

	return true
}

// testZBXDProtocol tests Zabbix ZBXD protocol handling
func (p *ZabbixAgentPlugin) testZBXDProtocol(conn net.Conn, result *DetectionResult) bool {
	// Create ZBXD header for "agent.ping"
	data := "agent.ping"
	header := make([]byte, 13)
	copy(header[0:4], "ZBXD")
	header[4] = 0x01 // Version
	binary.LittleEndian.PutUint64(header[5:13], uint64(len(data)))

	// Send ZBXD packet
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err := conn.Write(append(header, []byte(data)...))
	if err != nil {
		return false
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	// Check for ZBXD response header
	if n >= 13 && bytes.Equal(response[0:4], []byte("ZBXD")) {
		result.Evidence = append(result.Evidence, "Valid ZBXD protocol response")
		result.ProtocolVersion = "ZBXD"
		return true
	}

	return false
}

// testZabbixJSONProtocol tests Zabbix JSON protocol (7.0+)
func (p *ZabbixAgentPlugin) testZabbixJSONProtocol(conn net.Conn, result *DetectionResult) bool {
	// JSON request for agent.ping
	jsonRequest := `{"request":"agent.ping","ns":123456789}`

	// Create ZBXD header for JSON
	header := make([]byte, 13)
	copy(header[0:4], "ZBXD")
	header[4] = 0x01
	binary.LittleEndian.PutUint64(header[5:13], uint64(len(jsonRequest)))

	// Send JSON request
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err := conn.Write(append(header, []byte(jsonRequest)...))
	if err != nil {
		return false
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false
	}

	// Check for JSON response
	if n > 13 {
		responseData := response[13:n] // Skip ZBXD header
		if strings.Contains(string(responseData), `"response"`) || strings.Contains(string(responseData), `"data"`) {
			result.Evidence = append(result.Evidence, "Valid Zabbix JSON protocol response")
			result.ProtocolVersion = "JSON"
			return true
		}
	}

	return false
}

// determineAgentVariant determines if it's Agent 1 or Agent 2
func (p *ZabbixAgentPlugin) determineAgentVariant(version string) int {
	if strings.Contains(version, "Agent 2") || strings.Contains(version, "agent2") {
		return 2
	}
	return 1 // Default to Agent 1
}

// createConfirmedVendorInfo creates vendor information for confirmed Zabbix detection
func (p *ZabbixAgentPlugin) createConfirmedVendorInfo(result *DetectionResult) struct {
	Name        string
	Product     string
	Version     string
	Confidence  int
	Method      string
	Description string
} {
	product := "Zabbix Agent"
	if result.AgentVersion != "" {
		if strings.Contains(result.AgentVersion, "Agent 2") {
			product = "Zabbix Agent 2"
		}
	}

	vendor := struct {
		Name        string
		Product     string
		Version     string
		Confidence  int
		Method      string
		Description string
	}{
		Name:        "Zabbix",
		Product:     product,
		Version:     result.AgentVersion,
		Confidence:  result.Confidence,
		Method:      result.DetectionMethod,
		Description: fmt.Sprintf("Confirmed Zabbix agent detected via %s", result.DetectionMethod),
	}

	return vendor
}

// PortPriority returns true ONLY for standard Zabbix ports
func (p *ZabbixAgentPlugin) PortPriority(port uint16) bool {
	_, exists := standardZabbixPorts[int(port)]
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
