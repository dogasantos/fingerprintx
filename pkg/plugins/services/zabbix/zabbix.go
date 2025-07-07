package zabbixagent

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

var (
	// Common Zabbix ports
	commonZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}

	// Simple test payloads
	simpleTests = []string{
		"agent.ping",
		"agent.version",
		"system.uptime",
		"invalid.test.key",
	}

	// Zabbix response indicators
	zabbixIndicators = []string{
		"ZBX_NOTSUPPORTED",
		"NOTSUPPORTED",
		"Unsupported item key",
		"Cannot obtain",
		"Access denied",
		"Permission denied",
		"zabbix",
		"ZBXD",
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs simple Zabbix Agent detection
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Set a reasonable timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Try simple detection methods
	detected, version, method := p.detectZabbix(conn)

	if !detected {
		return nil, nil
	}

	// Create basic service response
	serviceZabbixAgent := plugins.ServiceZabbixAgent{
		VendorName:        "Zabbix",
		VendorProduct:     "Zabbix Agent",
		VendorVersion:     version,
		VendorConfidence:  75,
		VendorMethod:      method,
		VendorDescription: fmt.Sprintf("Zabbix Agent detected via %s", method),
		AgentVersion:      version,
		AgentVariant:      1,
		ProtocolVersion:   "detected",
		PassiveChecks:     true,
		DetectionLevel:    "basic",
	}

	service := plugins.CreateServiceFrom(target, serviceZabbixAgent, false, "", plugins.TCP)
	return service, nil
}

// detectZabbix performs simple Zabbix detection
func (p *ZabbixAgentPlugin) detectZabbix(conn net.Conn) (bool, string, string) {
	// Method 1: Try simple plaintext requests
	for _, test := range simpleTests {
		if detected, version := p.tryPlaintext(conn, test); detected {
			return true, version, fmt.Sprintf("plaintext-%s", test)
		}
	}

	// Method 2: Try connection behavior
	if p.tryConnectionTest(conn) {
		return true, "unknown", "connection-behavior"
	}

	return false, "", ""
}

// tryPlaintext tries a simple plaintext request
func (p *ZabbixAgentPlugin) tryPlaintext(conn net.Conn, test string) (bool, string) {
	// Send simple request
	request := test + "\n"
	_, err := conn.Write([]byte(request))
	if err != nil {
		return false, ""
	}

	// Read response with short timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return false, ""
	}

	responseStr := strings.TrimSpace(string(response[:n]))

	// Check for Zabbix patterns
	if p.isZabbixResponse(responseStr, test) {
		version := p.extractVersion(responseStr)
		return true, version
	}

	return false, ""
}

// tryConnectionTest tries basic connection behavior test
func (p *ZabbixAgentPlugin) tryConnectionTest(conn net.Conn) bool {
	// Send various test patterns
	tests := [][]byte{
		[]byte("test\n"),
		[]byte("invalid\n"),
		[]byte{0x00, 0x01, 0x02, 0x03},
		[]byte("GET /\n"),
	}

	responses := 0
	for _, test := range tests {
		_, err := conn.Write(test)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		response := make([]byte, 512)
		n, err := conn.Read(response)
		if err == nil && n > 0 {
			responses++
			responseStr := string(response[:n])
			if p.containsZabbixIndicators(responseStr) {
				return true
			}
		}
	}

	// If we got multiple responses, might be Zabbix with restrictive config
	return responses >= 2
}

// isZabbixResponse checks if response indicates Zabbix
func (p *ZabbixAgentPlugin) isZabbixResponse(response, test string) bool {
	response = strings.TrimSpace(response)

	// Check for Zabbix error patterns first
	if p.containsZabbixIndicators(response) {
		return true
	}

	// Check for valid responses based on test
	switch test {
	case "agent.ping":
		return response == "1"
	case "agent.version":
		return p.looksLikeVersion(response) && !strings.Contains(strings.ToUpper(response), "ERROR")
	case "system.uptime":
		return p.isNumeric(response)
	default:
		// Any reasonable response that's not an error
		return len(response) > 0 && len(response) < 1000 &&
			!strings.Contains(strings.ToUpper(response), "ERROR") &&
			!strings.Contains(strings.ToUpper(response), "INVALID")
	}
}

// containsZabbixIndicators checks for Zabbix-specific patterns
func (p *ZabbixAgentPlugin) containsZabbixIndicators(text string) bool {
	textUpper := strings.ToUpper(text)
	for _, indicator := range zabbixIndicators {
		if strings.Contains(textUpper, strings.ToUpper(indicator)) {
			return true
		}
	}
	return false
}

// extractVersion tries to extract version from response
func (p *ZabbixAgentPlugin) extractVersion(response string) string {
	response = strings.TrimSpace(response)

	// If it looks like a version, return it
	if p.looksLikeVersion(response) {
		return response
	}

	// Look for version patterns in error messages
	if strings.Contains(strings.ToUpper(response), "ZBX_NOTSUPPORTED") {
		return "4.0+"
	}
	if strings.Contains(strings.ToUpper(response), "NOTSUPPORTED") {
		return "2.0+"
	}

	return "unknown"
}

// looksLikeVersion checks if string looks like a version
func (p *ZabbixAgentPlugin) looksLikeVersion(s string) bool {
	if len(s) < 3 || len(s) > 20 {
		return false
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}

	return true
}

// isNumeric checks if string is numeric
func (p *ZabbixAgentPlugin) isNumeric(s string) bool {
	if len(s) == 0 || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
