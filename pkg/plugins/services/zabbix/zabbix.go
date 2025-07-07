package zabbixagent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

// ZabbixHeader represents the Zabbix protocol header
type ZabbixHeader struct {
	Protocol [4]byte // "ZBXD"
	Version  uint8   // Protocol version (1)
	DataLen  uint32  // Data length (little endian)
	Reserved uint32  // Reserved (0)
}

// VendorInfo represents detected Zabbix vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// ZabbixFingerprint represents collected Zabbix fingerprinting data
type ZabbixFingerprint struct {
	AgentVersion      string
	AgentVariant      int
	Hostname          string
	ResponseTime      time.Duration
	ProtocolVersion   string
	SupportedChecks   []string
	ActiveChecks      bool
	PassiveChecks     bool
	ConfigRevision    int
	SessionID         string
	HostMetadata      string
	HostInterface     string
	ListenIP          string
	ListenPort        int
	SupportedItems    []string
	RemoteCommands    bool
	TLSSupport        bool
	TLSVersion        string
	EncryptionEnabled bool
	PSKSupport        bool
	CertificateAuth   bool
	OperatingSystem   string
	Architecture      string
	KernelVersion     string
	DetectionLevel    string
	DetectionMethod   string
}

var (
	commonZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}

	// Magic payloads for Zabbix protocol detection
	zabbixMagicPayloads = []struct {
		name        string
		payload     []byte
		description string
	}{
		{
			name:        "agent.ping",
			payload:     []byte("agent.ping"),
			description: "Basic agent ping test",
		},
		{
			name:        "agent.version",
			payload:     []byte("agent.version"),
			description: "Agent version request",
		},
		{
			name:        "system.uptime",
			payload:     []byte("system.uptime"),
			description: "System uptime request",
		},
		{
			name:        "invalid_key_test",
			payload:     []byte("invalid.key.test.12345"),
			description: "Invalid key to trigger error response",
		},
	}

	// Expected Zabbix response patterns
	zabbixResponsePatterns = []string{
		"ZBX_NOTSUPPORTED",
		"Unsupported item key",
		"Cannot obtain system information",
		"Access denied",
		"Timeout while executing",
		"Invalid item key format",
		"NOTSUPPORTED",
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs Zabbix Agent detection
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Perform Zabbix Agent detection
	fingerprint, err := p.performZabbixDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If detection failed, this is not Zabbix Agent
	if fingerprint == nil {
		return nil, nil
	}

	fingerprint.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(fingerprint)

	// Create service result using ServiceZabbixAgent struct
	serviceZabbixAgent := plugins.ServiceZabbixAgent{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// Agent information
		AgentVersion: fingerprint.AgentVersion,
		AgentVariant: fingerprint.AgentVariant,
		Hostname:     fingerprint.Hostname,
		ResponseTime: fingerprint.ResponseTime.Milliseconds(),

		// Protocol information
		ProtocolVersion: fingerprint.ProtocolVersion,
		SupportedChecks: fingerprint.SupportedChecks,
		ActiveChecks:    fingerprint.ActiveChecks,
		PassiveChecks:   fingerprint.PassiveChecks,
		ConfigRevision:  fingerprint.ConfigRevision,
		SessionID:       fingerprint.SessionID,

		// Capabilities
		HostMetadata:   fingerprint.HostMetadata,
		HostInterface:  fingerprint.HostInterface,
		ListenIP:       fingerprint.ListenIP,
		ListenPort:     fingerprint.ListenPort,
		SupportedItems: fingerprint.SupportedItems,
		RemoteCommands: fingerprint.RemoteCommands,

		// Security features
		TLSSupport:        fingerprint.TLSSupport,
		TLSVersion:        fingerprint.TLSVersion,
		EncryptionEnabled: fingerprint.EncryptionEnabled,
		PSKSupport:        fingerprint.PSKSupport,
		CertificateAuth:   fingerprint.CertificateAuth,

		// System information
		OperatingSystem: fingerprint.OperatingSystem,
		Architecture:    fingerprint.Architecture,
		KernelVersion:   fingerprint.KernelVersion,

		// Detection metadata
		DetectionLevel: fingerprint.DetectionLevel,
	}

	service := plugins.CreateServiceFrom(target, serviceZabbixAgent, false, "", plugins.TCP)
	return service, nil
}

// performZabbixDetection performs Zabbix Agent protocol detection using magic payloads
func (p *ZabbixAgentPlugin) performZabbixDetection(conn net.Conn, timeout time.Duration) (*ZabbixFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	fingerprint := &ZabbixFingerprint{
		SupportedChecks: []string{},
		SupportedItems:  []string{},
		DetectionLevel:  "basic",
	}

	// Try different detection methods in order of reliability

	// 1. Try JSON protocol with magic payloads
	if success, method := p.tryJSONProtocolDetection(conn, fingerprint); success {
		fingerprint.ProtocolVersion = "7.0+"
		fingerprint.PassiveChecks = true
		fingerprint.DetectionLevel = "enhanced"
		fingerprint.DetectionMethod = method
		return fingerprint, nil
	}

	// 2. Try legacy plaintext protocol with magic payloads
	if success, method := p.tryPlaintextProtocolDetection(conn, fingerprint); success {
		fingerprint.ProtocolVersion = "legacy"
		fingerprint.PassiveChecks = true
		fingerprint.DetectionLevel = "enhanced"
		fingerprint.DetectionMethod = method
		return fingerprint, nil
	}

	// 3. Try protocol header detection
	if success, method := p.tryProtocolHeaderDetection(conn, fingerprint); success {
		fingerprint.ProtocolVersion = "detected"
		fingerprint.DetectionLevel = "basic"
		fingerprint.DetectionMethod = method
		return fingerprint, nil
	}

	// 4. Try response pattern detection
	if success, method := p.tryResponsePatternDetection(conn, fingerprint); success {
		fingerprint.ProtocolVersion = "pattern"
		fingerprint.DetectionLevel = "basic"
		fingerprint.DetectionMethod = method
		return fingerprint, nil
	}

	// Not a Zabbix Agent
	return nil, nil
}

// tryJSONProtocolDetection attempts JSON protocol detection
func (p *ZabbixAgentPlugin) tryJSONProtocolDetection(conn net.Conn, fingerprint *ZabbixFingerprint) (bool, string) {
	for _, magic := range zabbixMagicPayloads {
		// Create JSON request
		jsonRequest := map[string]interface{}{
			"request": "passive checks",
			"data": []map[string]interface{}{
				{
					"key":     magic.name,
					"timeout": 3,
				},
			},
		}

		// Send JSON request with Zabbix header
		if err := p.sendZabbixJSONRequest(conn, jsonRequest); err != nil {
			continue
		}

		// Try to read response
		response, err := p.readZabbixResponse(conn)
		if err != nil {
			continue
		}

		// Check if response is valid JSON and contains Zabbix patterns
		if p.isZabbixJSONResponse(response) {
			fingerprint.SupportedItems = append(fingerprint.SupportedItems, magic.name)
			return true, fmt.Sprintf("JSON protocol with %s", magic.name)
		}

		// Check for Zabbix error patterns in JSON
		if p.containsZabbixPatterns(string(response)) {
			return true, fmt.Sprintf("JSON protocol error pattern with %s", magic.name)
		}
	}

	return false, ""
}

// tryPlaintextProtocolDetection attempts plaintext protocol detection
func (p *ZabbixAgentPlugin) tryPlaintextProtocolDetection(conn net.Conn, fingerprint *ZabbixFingerprint) (bool, string) {
	for _, magic := range zabbixMagicPayloads {
		// Send plaintext request
		_, err := conn.Write(append(magic.payload, '\n'))
		if err != nil {
			continue
		}

		// Read response
		response := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(response)
		if err != nil {
			continue
		}

		responseStr := strings.TrimSpace(string(response[:n]))

		// Check for typical Zabbix responses
		if p.isZabbixPlaintextResponse(responseStr, magic.name) {
			fingerprint.SupportedItems = append(fingerprint.SupportedItems, magic.name)
			return true, fmt.Sprintf("Plaintext protocol with %s", magic.name)
		}

		// Check for Zabbix error patterns
		if p.containsZabbixPatterns(responseStr) {
			return true, fmt.Sprintf("Plaintext protocol error pattern with %s", magic.name)
		}
	}

	return false, ""
}

// tryProtocolHeaderDetection attempts to detect Zabbix by sending malformed requests and checking headers
func (p *ZabbixAgentPlugin) tryProtocolHeaderDetection(conn net.Conn, fingerprint *ZabbixFingerprint) (bool, string) {
	// Send a malformed Zabbix header to trigger a response
	malformedHeader := []byte{
		'Z', 'B', 'X', 'D', // Protocol signature
		0x01,                   // Version
		0x05, 0x00, 0x00, 0x00, // Data length (5 bytes)
		0x00, 0x00, 0x00, 0x00, // Reserved
		't', 'e', 's', 't', '\n', // Test data
	}

	_, err := conn.Write(malformedHeader)
	if err != nil {
		return false, ""
	}

	// Read response
	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(response)
	if err != nil {
		return false, ""
	}

	// Check if response starts with ZBXD header
	if n >= 4 && string(response[0:4]) == "ZBXD" {
		return true, "Protocol header detection"
	}

	// Check for Zabbix error patterns in response
	responseStr := string(response[:n])
	if p.containsZabbixPatterns(responseStr) {
		return true, "Protocol header error pattern"
	}

	return false, ""
}

// tryResponsePatternDetection attempts detection by sending various payloads and analyzing patterns
func (p *ZabbixAgentPlugin) tryResponsePatternDetection(conn net.Conn, fingerprint *ZabbixFingerprint) (bool, string) {
	testPayloads := [][]byte{
		[]byte("test\n"),
		[]byte("invalid\n"),
		[]byte("system.cpu.load\n"),
		[]byte("vfs.fs.size[/]\n"),
		[]byte("\n"),
		[]byte("GET / HTTP/1.1\r\n\r\n"), // HTTP request to see if it responds differently
	}

	for i, payload := range testPayloads {
		_, err := conn.Write(payload)
		if err != nil {
			continue
		}

		response := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(response)
		if err != nil {
			continue
		}

		responseStr := string(response[:n])

		// Check for Zabbix patterns
		if p.containsZabbixPatterns(responseStr) {
			return true, fmt.Sprintf("Response pattern detection with payload %d", i+1)
		}

		// Check for typical Zabbix behavior (connection close on invalid data)
		if n == 0 && i > 0 {
			return true, "Connection behavior pattern"
		}
	}

	return false, ""
}

// sendZabbixJSONRequest sends a JSON request with proper Zabbix header
func (p *ZabbixAgentPlugin) sendZabbixJSONRequest(conn net.Conn, request interface{}) error {
	// Marshal request to JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// Create Zabbix header
	header := ZabbixHeader{
		Protocol: [4]byte{'Z', 'B', 'X', 'D'},
		Version:  1,
		DataLen:  uint32(len(jsonData)),
		Reserved: 0,
	}

	// Write header
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, header)
	buf.Write(jsonData)

	_, err = conn.Write(buf.Bytes())
	return err
}

// readZabbixResponse reads a Zabbix protocol response
func (p *ZabbixAgentPlugin) readZabbixResponse(conn net.Conn) ([]byte, error) {
	// Try to read header first
	headerBuf := make([]byte, 13)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
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
	_, err = io.ReadFull(conn, dataBuf)
	if err != nil {
		return headerBuf, nil // Return header even if data read fails
	}

	return dataBuf, nil
}

// isZabbixJSONResponse checks if response is a valid Zabbix JSON response
func (p *ZabbixAgentPlugin) isZabbixJSONResponse(response []byte) bool {
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(response, &jsonResp); err != nil {
		return false
	}

	// Check for Zabbix JSON response fields
	if version, exists := jsonResp["version"]; exists {
		if versionStr, ok := version.(string); ok && p.isZabbixVersion(versionStr) {
			return true
		}
	}

	if variant, exists := jsonResp["variant"]; exists {
		if variantNum, ok := variant.(float64); ok && (variantNum == 1 || variantNum == 2) {
			return true
		}
	}

	// Check for data array with Zabbix-like content
	if data, exists := jsonResp["data"]; exists {
		if dataArray, ok := data.([]interface{}); ok && len(dataArray) > 0 {
			if dataItem, ok := dataArray[0].(map[string]interface{}); ok {
				if _, hasValue := dataItem["value"]; hasValue {
					return true
				}
				if _, hasError := dataItem["error"]; hasError {
					return true
				}
			}
		}
	}

	return false
}

// isZabbixPlaintextResponse checks if response is a valid Zabbix plaintext response
func (p *ZabbixAgentPlugin) isZabbixPlaintextResponse(response, key string) bool {
	response = strings.TrimSpace(response)

	switch key {
	case "agent.ping":
		return response == "1"
	case "agent.version":
		return p.isZabbixVersion(response)
	case "system.uptime":
		return p.isNumeric(response)
	default:
		// Check for typical Zabbix responses
		return response == "1" ||
			p.isNumeric(response) ||
			p.isZabbixVersion(response) ||
			p.containsZabbixPatterns(response)
	}
}

// containsZabbixPatterns checks if text contains known Zabbix error patterns
func (p *ZabbixAgentPlugin) containsZabbixPatterns(text string) bool {
	text = strings.ToUpper(text)
	for _, pattern := range zabbixResponsePatterns {
		if strings.Contains(text, strings.ToUpper(pattern)) {
			return true
		}
	}
	return false
}

// isZabbixVersion checks if a string looks like a Zabbix version
func (p *ZabbixAgentPlugin) isZabbixVersion(s string) bool {
	if len(s) < 3 || len(s) > 20 {
		return false
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}

	for _, part := range parts {
		if !p.isNumeric(part) {
			return false
		}
	}

	return true
}

// isNumeric checks if a string is numeric
func (p *ZabbixAgentPlugin) isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// createVendorInfo creates vendor information based on detection results
func (p *ZabbixAgentPlugin) createVendorInfo(fingerprint *ZabbixFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:        "Zabbix",
		Product:     "Zabbix Agent",
		Version:     fingerprint.AgentVersion,
		Method:      fingerprint.DetectionMethod,
		Description: "Zabbix monitoring agent detected via protocol analysis",
		Confidence:  60, // Start with moderate confidence
	}

	// Adjust confidence based on detection method
	switch {
	case strings.Contains(fingerprint.DetectionMethod, "JSON protocol"):
		vendor.Confidence = 90
	case strings.Contains(fingerprint.DetectionMethod, "Plaintext protocol"):
		vendor.Confidence = 85
	case strings.Contains(fingerprint.DetectionMethod, "Protocol header"):
		vendor.Confidence = 80
	case strings.Contains(fingerprint.DetectionMethod, "Response pattern"):
		vendor.Confidence = 70
	case strings.Contains(fingerprint.DetectionMethod, "Connection behavior"):
		vendor.Confidence = 60
	}

	// Adjust based on agent variant
	switch fingerprint.AgentVariant {
	case 1:
		vendor.Product = "Zabbix Agent"
	case 2:
		vendor.Product = "Zabbix Agent 2"
	}

	// Boost confidence if we have version info
	if fingerprint.AgentVersion != "" {
		vendor.Confidence += 10
	}

	// Boost confidence if we have multiple supported items
	if len(fingerprint.SupportedItems) > 1 {
		vendor.Confidence += 5
	}

	// Cap at 95 for protocol detection (not 100% without full handshake)
	if vendor.Confidence > 95 {
		vendor.Confidence = 95
	}

	return vendor
}

// PortPriority returns true if the port is a common Zabbix port
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
