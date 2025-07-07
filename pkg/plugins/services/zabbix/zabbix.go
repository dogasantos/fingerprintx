package zabbixagent

import (
	"fmt"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

// DetectionResult holds the results of silent Zabbix detection
type DetectionResult struct {
	IsZabbix        bool
	DetectionMethod string
	Confidence      int
	ConnectionTime  time.Duration
	BehaviorPattern string
	ResponsePattern string
}

var (
	// Common Zabbix ports
	commonZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}

	// Test payloads for silent detection
	testPayloads = [][]byte{
		[]byte("agent.ping\n"),
		[]byte("agent.version\n"),
		[]byte("system.uptime\n"),
		[]byte("invalid.test.key\n"),
		[]byte("test\n"),
		// Zabbix protocol header
		{0x5A, 0x42, 0x58, 0x44, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74},
		// HTTP request (should be rejected differently)
		[]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"),
		// SSH-like request
		[]byte("SSH-2.0-Test\r\n"),
		// Random binary
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs silent Zabbix Agent detection based on connection behavior
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Perform silent detection based on connection behavior
	result, err := p.detectSilentZabbix(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If not detected as Zabbix, return nil
	if !result.IsZabbix {
		return nil, nil
	}

	result.ConnectionTime = time.Since(startTime)

	// Create vendor information for silent detection
	vendor := p.createSilentVendorInfo(result)

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

// detectSilentZabbix performs detection based on connection behavior patterns
func (p *ZabbixAgentPlugin) detectSilentZabbix(conn net.Conn, timeout time.Duration) (*DetectionResult, error) {
	result := &DetectionResult{}

	// Set overall timeout
	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	// Method 1: Connection timing analysis
	if p.analyzeConnectionTiming(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Connection Timing"
		return result, nil
	}

	// Method 2: Silent response pattern analysis
	if p.analyzeSilentResponses(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Silent Response Pattern"
		return result, nil
	}

	// Method 3: Port-based heuristic (for known Zabbix ports)
	if p.analyzePortBehavior(conn, result) {
		result.IsZabbix = true
		result.DetectionMethod = "Port Behavior"
		return result, nil
	}

	return result, nil
}

// analyzeConnectionTiming analyzes connection timing patterns
func (p *ZabbixAgentPlugin) analyzeConnectionTiming(conn net.Conn, result *DetectionResult) bool {
	timings := []time.Duration{}

	// Send multiple requests and measure timing
	for i, payload := range testPayloads[:5] { // Test first 5 payloads
		start := time.Now()

		// Set short timeout for each test
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Send payload
		_, err := conn.Write(payload)
		if err != nil {
			continue
		}

		// Try to read response (expecting none)
		response := make([]byte, 1024)
		n, err := conn.Read(response)

		elapsed := time.Since(start)
		timings = append(timings, elapsed)

		// If we get any response, analyze it
		if err == nil && n > 0 {
			result.ResponsePattern = fmt.Sprintf("Got %d bytes on test %d", n, i)
			// If we get responses, this might not be a silent agent
			return false
		}
	}

	// Analyze timing patterns
	if len(timings) >= 3 {
		avgTiming := p.calculateAverage(timings)
		consistency := p.calculateConsistency(timings)

		// Zabbix agents typically have consistent timing patterns
		// even when not responding (connection handling, parsing, rejection)
		if avgTiming > 100*time.Millisecond && avgTiming < 5*time.Second && consistency > 0.7 {
			result.Confidence = 70
			result.BehaviorPattern = fmt.Sprintf("Consistent timing: avg=%.2fms, consistency=%.2f",
				float64(avgTiming.Nanoseconds())/1000000, consistency)
			return true
		}
	}

	return false
}

// analyzeSilentResponses analyzes patterns in silent responses
func (p *ZabbixAgentPlugin) analyzeSilentResponses(conn net.Conn, result *DetectionResult) bool {
	connectionDrops := 0
	timeouts := 0
	immediateRejects := 0

	for i, payload := range testPayloads {
		start := time.Now()

		// Set timeout for this test
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))

		// Send payload
		_, writeErr := conn.Write(payload)
		if writeErr != nil {
			connectionDrops++
			continue
		}

		// Try to read response
		response := make([]byte, 512)
		n, readErr := conn.Read(response)
		elapsed := time.Since(start)

		if readErr != nil {
			if elapsed < 100*time.Millisecond {
				immediateRejects++
			} else {
				timeouts++
			}
		} else if n == 0 {
			timeouts++
		}

		// Log the behavior for analysis
		result.ResponsePattern += fmt.Sprintf("Test%d: write=%v, read=%v, time=%dms; ",
			i, writeErr == nil, n > 0, elapsed.Milliseconds())
	}

	// Analyze response patterns
	totalTests := len(testPayloads)

	// Pattern 1: Consistent timeouts (typical for PSK-protected agents)
	if timeouts >= totalTests/2 && connectionDrops == 0 {
		result.Confidence = 75
		result.BehaviorPattern = fmt.Sprintf("Consistent timeouts: %d/%d (PSK-protected)", timeouts, totalTests)
		return true
	}

	// Pattern 2: Immediate connection drops (access control)
	if connectionDrops >= totalTests/3 {
		result.Confidence = 65
		result.BehaviorPattern = fmt.Sprintf("Connection drops: %d/%d (access control)", connectionDrops, totalTests)
		return true
	}

	// Pattern 3: Mixed behavior but consistent pattern
	if timeouts+connectionDrops >= totalTests*2/3 {
		result.Confidence = 60
		result.BehaviorPattern = fmt.Sprintf("Silent behavior: timeouts=%d, drops=%d", timeouts, connectionDrops)
		return true
	}

	return false
}

// analyzePortBehavior analyzes behavior specific to known Zabbix ports
func (p *ZabbixAgentPlugin) analyzePortBehavior(conn net.Conn, result *DetectionResult) bool {
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

	// For known Zabbix ports, if the connection is accepted but silent,
	// it's likely a Zabbix agent with strict configuration

	// Test connection stability
	stable := p.testConnectionStability(conn)
	if stable {
		result.Confidence = 55 // Lower confidence for port-based detection
		result.BehaviorPattern = "Silent on known Zabbix port with stable connection"
		return true
	}

	return false
}

// testConnectionStability tests if the connection remains stable
func (p *ZabbixAgentPlugin) testConnectionStability(conn net.Conn) bool {
	// Send small test data and see if connection stays open
	testData := []byte("test")

	for i := 0; i < 3; i++ {
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, err := conn.Write(testData)
		if err != nil {
			return false // Connection not stable
		}

		// Small delay between tests
		time.Sleep(100 * time.Millisecond)
	}

	return true // Connection remained stable
}

// calculateAverage calculates average duration
func (p *ZabbixAgentPlugin) calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	var total time.Duration
	for _, d := range durations {
		total += d
	}

	return total / time.Duration(len(durations))
}

// calculateConsistency calculates timing consistency (0-1, higher is more consistent)
func (p *ZabbixAgentPlugin) calculateConsistency(durations []time.Duration) float64 {
	if len(durations) < 2 {
		return 0
	}

	avg := p.calculateAverage(durations)
	var variance float64

	for _, d := range durations {
		diff := float64(d - avg)
		variance += diff * diff
	}

	variance /= float64(len(durations))
	stddev := variance // Simplified

	// Consistency is inverse of coefficient of variation
	if avg == 0 {
		return 0
	}

	cv := stddev / float64(avg)
	consistency := 1.0 / (1.0 + cv)

	if consistency > 1.0 {
		consistency = 1.0
	}

	return consistency
}

// createSilentVendorInfo creates vendor information for silent detection
func (p *ZabbixAgentPlugin) createSilentVendorInfo(result *DetectionResult) struct {
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
		Description: fmt.Sprintf("Silent Zabbix agent detected via %s - likely PSK/access-controlled", result.DetectionMethod),
	}

	// Adjust confidence based on detection method
	switch result.DetectionMethod {
	case "Connection Timing":
		// Good confidence for timing analysis
	case "Silent Response Pattern":
		vendor.Confidence += 5
	case "Port Behavior":
		vendor.Confidence -= 10 // Lower confidence for port-only detection
	}

	// Cap confidence for silent detection (can't be 100% sure without responses)
	if vendor.Confidence > 80 {
		vendor.Confidence = 80
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
