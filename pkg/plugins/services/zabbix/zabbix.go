package zabbixagent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

// ZabbixHeader represents the Zabbix protocol header
type ZabbixHeader struct {
	Protocol [4]byte // "ZBXD"
	Version  uint8   // Protocol version
	DataLen  uint32  // Data length (little endian)
	Reserved uint32  // Reserved (0)
}

// DetectionResult holds the results of Zabbix detection
type DetectionResult struct {
	IsZabbix         bool
	Version          string
	AgentVariant     int // 1 = Agent, 2 = Agent 2
	ProtocolVersion  string
	DetectionMethod  string
	Confidence       int
	ResponseTime     time.Duration
	SupportedItems   []string
	ErrorPatterns    []string
	ProtocolFeatures []string
}

var (
	// Common Zabbix ports
	commonZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}

	// Version detection patterns with confidence scores
	versionPatterns = []struct {
		pattern     *regexp.Regexp
		version     string
		confidence  int
		description string
	}{
		// Direct version patterns (highest confidence)
		{regexp.MustCompile(`"version"\s*:\s*"([7]\.[0-9]+\.[0-9]+)"`), "7.x", 95, "JSON version 7.x"},
		{regexp.MustCompile(`"version"\s*:\s*"([6]\.[0-9]+\.[0-9]+)"`), "6.x", 95, "JSON version 6.x"},
		{regexp.MustCompile(`"version"\s*:\s*"([5]\.[0-9]+\.[0-9]+)"`), "5.x", 95, "JSON version 5.x"},
		{regexp.MustCompile(`"version"\s*:\s*"([4]\.[0-9]+\.[0-9]+)"`), "4.x", 95, "JSON version 4.x"},
		{regexp.MustCompile(`"version"\s*:\s*"([3]\.[0-9]+\.[0-9]+)"`), "3.x", 95, "JSON version 3.x"},
		{regexp.MustCompile(`"version"\s*:\s*"([2]\.[0-9]+\.[0-9]+)"`), "2.x", 95, "JSON version 2.x"},

		// Agent variant patterns (7.0+)
		{regexp.MustCompile(`"variant"\s*:\s*[12]`), "7.0+", 90, "Agent variant field (7.0+)"},
		{regexp.MustCompile(`"variant"\s*:\s*2`), "7.0+ Agent2", 85, "Agent 2 variant"},

		// Feature-based patterns
		{regexp.MustCompile(`"commands"\s*:\s*\[`), "7.0+", 85, "Commands array (7.0+)"},
		{regexp.MustCompile(`"timeout"\s*:\s*"[0-9]+[smh]"`), "7.0+", 80, "Timeout with units (7.0+)"},
		{regexp.MustCompile(`"config_revision"\s*:\s*[0-9]+`), "6.4+", 80, "Config revision (6.4+)"},
		{regexp.MustCompile(`"session"\s*:\s*"`), "4.0+", 75, "Session field (4.0+)"},
		{regexp.MustCompile(`"ns"\s*:\s*[0-9]+`), "5.0+", 75, "Nanoseconds field (5.0+)"},

		// Error message patterns
		{regexp.MustCompile(`ZBX_NOTSUPPORTED:\s*Cannot\s+obtain\s+system\s+information`), "6.0+", 75, "Modern error format"},
		{regexp.MustCompile(`ZBX_NOTSUPPORTED:\s*Unsupported\s+item\s+key`), "4.0+", 70, "Standard error format"},
		{regexp.MustCompile(`NOTSUPPORTED:\s*Unsupported\s+item\s+key`), "2.0-3.4", 70, "Legacy error format"},
		{regexp.MustCompile(`ZBX_NOTSUPPORTED`), "4.0+", 65, "Modern error prefix"},
		{regexp.MustCompile(`NOTSUPPORTED`), "1.0+", 60, "Legacy error prefix"},

		// Agent 2 specific patterns
		{regexp.MustCompile(`zabbix_agent2`), "4.4+", 85, "Agent 2 identifier"},
		{regexp.MustCompile(`agent2`), "4.4+", 70, "Agent 2 reference"},

		// Protocol header patterns
		{regexp.MustCompile(`ZBXD\x01.{4}.{4}`), "4.0+", 70, "Modern ZBXD header"},
		{regexp.MustCompile(`ZBXD\x01.{8}`), "2.4-3.4", 65, "Legacy ZBXD header"},
	}

	// Test payloads for fingerprinting
	testPayloads = []struct {
		name        string
		data        string
		description string
		expectError bool
	}{
		{"agent.ping", "agent.ping", "Basic agent ping", false},
		{"agent.version", "agent.version", "Agent version request", false},
		{"agent.variant", "agent.variant", "Agent variant (7.0+ only)", true},
		{"system.uptime", "system.uptime", "System uptime", false},
		{"system.hostname", "system.hostname", "System hostname", false},
		{"invalid.test.key", "invalid.test.key.fingerprint", "Invalid key for error", true},
		{"malformed", "test\x00\x01\x02", "Malformed request", true},
	}

	// Known Zabbix response patterns
	zabbixIndicators = []string{
		"ZBX_NOTSUPPORTED",
		"NOTSUPPORTED",
		"Unsupported item key",
		"Cannot obtain system information",
		"Access denied",
		"Timeout while executing",
		"Invalid item key format",
		"Permission denied",
		"Item not supported",
		"zabbix_agentd",
		"zabbix_agent2",
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs Zabbix Agent detection and fingerprinting
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Perform comprehensive Zabbix detection
	result, err := p.detectZabbixAgent(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If not detected as Zabbix, return nil
	if !result.IsZabbix {
		return nil, nil
	}

	result.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(result)

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
		AgentVersion: result.Version,
		AgentVariant: result.AgentVariant,
		ResponseTime: result.ResponseTime.Milliseconds(),

		// Protocol information
		ProtocolVersion: result.ProtocolVersion,
		SupportedItems:  result.SupportedItems,
		PassiveChecks:   true, // Detected via passive check

		// Detection metadata
		DetectionLevel: result.DetectionMethod,
	}

	service := plugins.CreateServiceFrom(target, serviceZabbixAgent, false, "", plugins.TCP)
	return service, nil
}

// detectZabbixAgent performs comprehensive Zabbix Agent detection
func (p *ZabbixAgentPlugin) detectZabbixAgent(conn net.Conn, timeout time.Duration) (*DetectionResult, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	result := &DetectionResult{
		SupportedItems:   []string{},
		ErrorPatterns:    []string{},
		ProtocolFeatures: []string{},
	}

	// Try multiple detection methods in order of reliability

	// 1. JSON Protocol Detection (most reliable for modern versions)
	if p.tryJSONProtocol(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "JSON Protocol"
		return result, nil
	}

	// 2. Plaintext Protocol Detection (legacy versions)
	if p.tryPlaintextProtocol(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Plaintext Protocol"
		return result, nil
	}

	// 3. Protocol Header Analysis
	if p.tryProtocolHeader(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Protocol Header"
		return result, nil
	}

	// 4. Error Pattern Analysis (fallback)
	if p.tryErrorPatterns(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Error Patterns"
		return result, nil
	}

	// 5. Connection Behavior Analysis (last resort)
	if p.tryConnectionBehavior(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Connection Behavior"
		return result, nil
	}

	return result, nil
}

// tryJSONProtocol attempts JSON protocol detection
func (p *ZabbixAgentPlugin) tryJSONProtocol(conn net.Conn, result *DetectionResult) bool {
	// Create JSON request for passive checks
	jsonRequest := map[string]interface{}{
		"request": "passive checks",
		"data": []map[string]interface{}{
			{"key": "agent.version"},
			{"key": "agent.ping"},
		},
	}

	// Send JSON request with Zabbix header
	if err := p.sendZabbixJSON(conn, jsonRequest); err != nil {
		return false
	}

	// Read response
	response, err := p.readZabbixResponse(conn, 5*time.Second)
	if err != nil {
		return false
	}

	responseStr := string(response)

	// Check if response is valid JSON with Zabbix patterns
	if p.isValidZabbixJSON(response) {
		result.ProtocolVersion = "7.0+"
		result.ProtocolFeatures = append(result.ProtocolFeatures, "JSON Protocol")
		p.analyzeResponse(responseStr, result)
		return true
	}

	// Check for Zabbix error patterns in JSON response
	if p.containsZabbixPatterns(responseStr) {
		result.ProtocolVersion = "4.0+"
		p.analyzeResponse(responseStr, result)
		return true
	}

	return false
}

// tryPlaintextProtocol attempts plaintext protocol detection
func (p *ZabbixAgentPlugin) tryPlaintextProtocol(conn net.Conn, result *DetectionResult) bool {
	for _, payload := range testPayloads {
		// Send plaintext request
		_, err := conn.Write([]byte(payload.data + "\n"))
		if err != nil {
			continue
		}

		// Read response
		response, err := p.readPlaintextResponse(conn, 3*time.Second)
		if err != nil {
			continue
		}

		responseStr := strings.TrimSpace(string(response))

		// Analyze response
		if p.isValidZabbixResponse(responseStr, payload.name) {
			result.ProtocolVersion = "legacy"
			result.SupportedItems = append(result.SupportedItems, payload.name)
			p.analyzeResponse(responseStr, result)
			return true
		}

		// Check for Zabbix error patterns
		if p.containsZabbixPatterns(responseStr) {
			result.ErrorPatterns = append(result.ErrorPatterns, responseStr)
			p.analyzeResponse(responseStr, result)
			return true
		}
	}

	return false
}

// tryProtocolHeader attempts protocol header analysis
func (p *ZabbixAgentPlugin) tryProtocolHeader(conn net.Conn, result *DetectionResult) bool {
	// Send malformed Zabbix header to trigger response
	header := []byte{
		'Z', 'B', 'X', 'D', // Protocol signature
		0x01,                   // Version
		0x04, 0x00, 0x00, 0x00, // Data length (4 bytes)
		0x00, 0x00, 0x00, 0x00, // Reserved
		't', 'e', 's', 't', // Test data
	}

	_, err := conn.Write(header)
	if err != nil {
		return false
	}

	// Read response
	response, err := p.readZabbixResponse(conn, 3*time.Second)
	if err != nil {
		return false
	}

	// Check for ZBXD header in response
	if len(response) >= 4 && string(response[0:4]) == "ZBXD" {
		result.ProtocolFeatures = append(result.ProtocolFeatures, "ZBXD Header")
		p.analyzeHeaderFormat(response, result)
		return true
	}

	// Check for Zabbix patterns in response
	responseStr := string(response)
	if p.containsZabbixPatterns(responseStr) {
		p.analyzeResponse(responseStr, result)
		return true
	}

	return false
}

// tryErrorPatterns attempts error pattern analysis
func (p *ZabbixAgentPlugin) tryErrorPatterns(conn net.Conn, result *DetectionResult) bool {
	testRequests := [][]byte{
		[]byte("invalid.test.key\n"),
		[]byte("system.invalid\n"),
		[]byte("agent.invalid\n"),
		[]byte("test\n"),
		[]byte("\x00\x01\x02\n"),
	}

	for _, request := range testRequests {
		_, err := conn.Write(request)
		if err != nil {
			continue
		}

		response, err := p.readPlaintextResponse(conn, 2*time.Second)
		if err != nil {
			continue
		}

		responseStr := string(response)
		if p.containsZabbixPatterns(responseStr) {
			result.ErrorPatterns = append(result.ErrorPatterns, responseStr)
			p.analyzeResponse(responseStr, result)
			return true
		}
	}

	return false
}

// tryConnectionBehavior attempts connection behavior analysis
func (p *ZabbixAgentPlugin) tryConnectionBehavior(conn net.Conn, result *DetectionResult) bool {
	// Send various test patterns and analyze connection behavior
	testPatterns := [][]byte{
		[]byte("GET / HTTP/1.1\r\n\r\n"),     // HTTP request
		[]byte("CONNECT\r\n"),                // Generic connect
		[]byte("test\n"),                     // Simple test
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04}, // Binary data
	}

	responses := 0
	for _, pattern := range testPatterns {
		_, err := conn.Write(pattern)
		if err != nil {
			continue
		}

		response, err := p.readPlaintextResponse(conn, 1*time.Second)
		if err == nil && len(response) > 0 {
			responses++
			responseStr := string(response)
			if p.containsZabbixPatterns(responseStr) {
				result.ErrorPatterns = append(result.ErrorPatterns, responseStr)
				p.analyzeResponse(responseStr, result)
				return true
			}
		}
	}

	// If we got responses but no clear Zabbix patterns, it might still be Zabbix
	// with very restrictive configuration
	if responses > 0 {
		result.Confidence = 30 // Low confidence
		result.Version = "unknown"
		return true
	}

	return false
}

// sendZabbixJSON sends a JSON request with Zabbix header
func (p *ZabbixAgentPlugin) sendZabbixJSON(conn net.Conn, request interface{}) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// Create Zabbix header
	var buf bytes.Buffer
	buf.Write([]byte("ZBXD"))                                      // Protocol
	buf.WriteByte(0x01)                                            // Version
	binary.Write(&buf, binary.LittleEndian, uint32(len(jsonData))) // Data length
	binary.Write(&buf, binary.LittleEndian, uint32(0))             // Reserved
	buf.Write(jsonData)                                            // Data

	_, err = conn.Write(buf.Bytes())
	return err
}

// readZabbixResponse reads a Zabbix protocol response
func (p *ZabbixAgentPlugin) readZabbixResponse(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	// Try to read header first
	headerBuf := make([]byte, 13)
	n, err := conn.Read(headerBuf)
	if err != nil {
		return nil, err
	}

	// If we got less than header size, return what we got
	if n < 13 {
		return headerBuf[:n], nil
	}

	// Check for Zabbix header
	if string(headerBuf[0:4]) != "ZBXD" {
		return headerBuf, nil
	}

	// Parse data length
	dataLen := binary.LittleEndian.Uint32(headerBuf[5:9])
	if dataLen == 0 {
		return []byte{}, nil
	}

	if dataLen > 1024*1024 { // 1MB limit
		return headerBuf, nil
	}

	// Read data
	dataBuf := make([]byte, dataLen)
	totalRead := 0
	for totalRead < int(dataLen) {
		n, err := conn.Read(dataBuf[totalRead:])
		if err != nil {
			break
		}
		totalRead += n
	}

	return dataBuf[:totalRead], nil
}

// readPlaintextResponse reads a plaintext response
func (p *ZabbixAgentPlugin) readPlaintextResponse(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

// isValidZabbixJSON checks if response is valid Zabbix JSON
func (p *ZabbixAgentPlugin) isValidZabbixJSON(response []byte) bool {
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(response, &jsonResp); err != nil {
		return false
	}

	// Check for Zabbix JSON response fields
	if _, hasVersion := jsonResp["version"]; hasVersion {
		return true
	}
	if _, hasVariant := jsonResp["variant"]; hasVariant {
		return true
	}
	if _, hasData := jsonResp["data"]; hasData {
		return true
	}
	if response, hasResponse := jsonResp["response"]; hasResponse {
		if respStr, ok := response.(string); ok {
			return respStr == "success" || respStr == "failed"
		}
	}

	return false
}

// isValidZabbixResponse checks if response is valid for the given key
func (p *ZabbixAgentPlugin) isValidZabbixResponse(response, key string) bool {
	response = strings.TrimSpace(response)

	switch key {
	case "agent.ping":
		return response == "1"
	case "agent.version":
		return p.looksLikeVersion(response)
	case "system.uptime":
		return p.isNumeric(response)
	case "system.hostname":
		return len(response) > 0 && len(response) < 256 && !strings.Contains(response, "NOTSUPPORTED")
	default:
		return p.isNumeric(response) || p.looksLikeVersion(response) || response == "1"
	}
}

// containsZabbixPatterns checks for known Zabbix patterns
func (p *ZabbixAgentPlugin) containsZabbixPatterns(text string) bool {
	textUpper := strings.ToUpper(text)
	for _, indicator := range zabbixIndicators {
		if strings.Contains(textUpper, strings.ToUpper(indicator)) {
			return true
		}
	}
	return false
}

// analyzeResponse analyzes response text for version and features
func (p *ZabbixAgentPlugin) analyzeResponse(text string, result *DetectionResult) {
	bestConfidence := result.Confidence

	for _, pattern := range versionPatterns {
		if pattern.pattern.MatchString(text) {
			if pattern.confidence > bestConfidence {
				result.Version = pattern.version
				result.Confidence = pattern.confidence
				bestConfidence = pattern.confidence
			}

			// Extract agent variant
			if strings.Contains(pattern.description, "Agent 2") {
				result.AgentVariant = 2
			} else if result.AgentVariant == 0 {
				result.AgentVariant = 1
			}

			// Extract protocol features
			if strings.Contains(pattern.description, "JSON") {
				result.ProtocolFeatures = append(result.ProtocolFeatures, "JSON Protocol")
			}
			if strings.Contains(pattern.description, "Commands") {
				result.ProtocolFeatures = append(result.ProtocolFeatures, "Commands Support")
			}
			if strings.Contains(pattern.description, "Session") {
				result.ProtocolFeatures = append(result.ProtocolFeatures, "Session Management")
			}
		}
	}

	// Extract exact version if possible
	versionRegex := regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)
	if matches := versionRegex.FindStringSubmatch(text); len(matches) > 1 {
		result.Version = matches[1]
		result.Confidence = 95
	}
}

// analyzeHeaderFormat analyzes ZBXD header format
func (p *ZabbixAgentPlugin) analyzeHeaderFormat(header []byte, result *DetectionResult) {
	if len(header) < 13 {
		return
	}

	if string(header[0:4]) != "ZBXD" {
		return
	}

	version := header[4]
	if version == 0x01 {
		// Check if it's modern or legacy format
		dataLen := binary.LittleEndian.Uint32(header[5:9])
		reserved := binary.LittleEndian.Uint32(header[9:13])

		if reserved == 0 && dataLen < 1024*1024 {
			result.ProtocolVersion = "4.0+"
			result.Confidence = 70
		} else {
			result.ProtocolVersion = "2.4-3.4"
			result.Confidence = 65
		}
	}
}

// looksLikeVersion checks if string looks like a version number
func (p *ZabbixAgentPlugin) looksLikeVersion(s string) bool {
	if len(s) < 3 || len(s) > 20 {
		return false
	}

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

// isNumeric checks if string is numeric
func (p *ZabbixAgentPlugin) isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// createVendorInfo creates vendor information from detection results
func (p *ZabbixAgentPlugin) createVendorInfo(result *DetectionResult) struct {
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
		Product:     "Zabbix Agent",
		Version:     result.Version,
		Confidence:  result.Confidence,
		Method:      result.DetectionMethod,
		Description: fmt.Sprintf("Zabbix monitoring agent detected via %s", result.DetectionMethod),
	}

	// Adjust product name based on agent variant
	if result.AgentVariant == 2 {
		vendor.Product = "Zabbix Agent 2"
	}

	// Boost confidence for better detection methods
	switch result.DetectionMethod {
	case "JSON Protocol":
		vendor.Confidence += 10
	case "Plaintext Protocol":
		vendor.Confidence += 5
	case "Protocol Header":
		// No change
	case "Error Patterns":
		vendor.Confidence -= 5
	case "Connection Behavior":
		vendor.Confidence -= 10
	}

	// Boost confidence if we have exact version
	if p.looksLikeVersion(result.Version) {
		vendor.Confidence += 15
	}

	// Boost confidence for multiple supported items
	if len(result.SupportedItems) > 1 {
		vendor.Confidence += 5
	}

	// Cap confidence at 98 (not 100% without full auth)
	if vendor.Confidence > 98 {
		vendor.Confidence = 98
	}

	// Minimum confidence for detection
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
