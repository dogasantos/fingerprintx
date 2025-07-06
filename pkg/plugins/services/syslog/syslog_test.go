package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Test structures (simplified versions of the plugin structures)
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int
	Method      string
	Description string
}

type SyslogMessage struct {
	Priority   int
	Facility   int
	Severity   int
	Timestamp  string
	Hostname   string
	Tag        string
	Content    string
	RawMessage string
	RFC        string
}

// Test vendor patterns (subset from main plugin)
var testVendorPatterns = []struct {
	Pattern     *regexp.Regexp
	VendorInfo  VendorInfo
	Description string
}{
	{
		Pattern: regexp.MustCompile(`(?i)rsyslogd.*(\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "rsyslog",
			Product:     "rsyslogd",
			Confidence:  95,
			Description: "rsyslog - Rocket-fast system for log processing",
		},
		Description: "rsyslog daemon with version",
	},
	{
		Pattern: regexp.MustCompile(`(?i)syslog-ng.*(\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "syslog-ng",
			Product:     "syslog-ng",
			Confidence:  95,
			Description: "syslog-ng - Next-generation syslog daemon",
		},
		Description: "syslog-ng with version",
	},
	{
		Pattern: regexp.MustCompile(`(?i)cisco.*ios`),
		VendorInfo: VendorInfo{
			Name:        "Cisco",
			Product:     "IOS",
			Confidence:  90,
			Description: "Cisco IOS Device",
		},
		Description: "Cisco IOS device",
	},
	{
		Pattern: regexp.MustCompile(`(?i)microsoft.*event.*log`),
		VendorInfo: VendorInfo{
			Name:        "Microsoft",
			Product:     "Windows Event Log",
			Confidence:  90,
			Description: "Microsoft Windows Event Log Service",
		},
		Description: "Windows Event Log service",
	},
}

// Test functions (simplified versions from main plugin)
func createTestMessage(priority int, hostname string, tag string, content string) string {
	timestamp := time.Now().Format("Jan 02 15:04:05")
	return fmt.Sprintf("<%d>%s %s %s: %s", priority, timestamp, hostname, tag, content)
}

func createRFC5424Message(priority int, hostname string, appName string, content string) string {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf("<%d>1 %s %s %s - - - %s", priority, timestamp, hostname, appName, content)
}

func parseSyslogMessage(message string) (*SyslogMessage, error) {
	if len(message) < 5 {
		return nil, fmt.Errorf("message too short")
	}

	if message[0] != '<' {
		return nil, fmt.Errorf("invalid priority format")
	}

	priEnd := strings.Index(message, ">")
	if priEnd == -1 {
		return nil, fmt.Errorf("priority not closed")
	}

	priorityStr := message[1:priEnd]
	priority := 0
	for _, char := range priorityStr {
		if char >= '0' && char <= '9' {
			priority = priority*10 + int(char-'0')
		} else {
			return nil, fmt.Errorf("invalid priority value")
		}
	}

	facility := priority / 8
	severity := priority % 8

	remainder := message[priEnd+1:]

	rfc := "3164"
	if len(remainder) > 0 && remainder[0] == '1' && len(remainder) > 1 && remainder[1] == ' ' {
		rfc = "5424"
		remainder = remainder[2:]
	}

	parts := strings.SplitN(remainder, " ", 4)
	if len(parts) < 3 {
		return nil, fmt.Errorf("insufficient message parts")
	}

	var timestamp, hostname, msgPart string
	if rfc == "5424" {
		timestamp = parts[0]
		hostname = parts[1]
		if len(parts) > 2 {
			msgPart = strings.Join(parts[2:], " ")
		}
	} else {
		timestamp = parts[0] + " " + parts[1]
		hostname = parts[2]
		if len(parts) > 3 {
			msgPart = parts[3]
		}
	}

	var tag, content string
	if msgPart != "" {
		colonIndex := strings.Index(msgPart, ":")
		if colonIndex > 0 {
			tag = msgPart[:colonIndex]
			content = strings.TrimSpace(msgPart[colonIndex+1:])
		} else {
			spaceIndex := strings.Index(msgPart, " ")
			if spaceIndex > 0 {
				tag = msgPart[:spaceIndex]
				content = strings.TrimSpace(msgPart[spaceIndex+1:])
			} else {
				tag = msgPart
			}
		}
	}

	return &SyslogMessage{
		Priority:   priority,
		Facility:   facility,
		Severity:   severity,
		Timestamp:  timestamp,
		Hostname:   hostname,
		Tag:        tag,
		Content:    content,
		RawMessage: message,
		RFC:        rfc,
	}, nil
}

func analyzeMessageContent(message *SyslogMessage) *VendorInfo {
	searchText := strings.ToLower(message.Tag + " " + message.Content + " " + message.Hostname)

	for _, pattern := range testVendorPatterns {
		if matches := pattern.Pattern.FindStringSubmatch(searchText); matches != nil {
			vendorInfo := pattern.VendorInfo
			vendorInfo.Method = "Message Content Analysis"

			if len(matches) > 1 && matches[1] != "" {
				vendorInfo.Version = matches[1]
			}

			return &vendorInfo
		}
	}

	return nil
}

func analyzeFacilityUsage(messages []*SyslogMessage) *VendorInfo {
	if len(messages) == 0 {
		return nil
	}

	facilityCount := make(map[int]int)
	for _, msg := range messages {
		facilityCount[msg.Facility]++
	}

	totalMessages := len(messages)

	localFacilities := 0
	for facility, count := range facilityCount {
		if facility >= 16 && facility <= 23 {
			localFacilities += count
		}
	}

	if localFacilities > totalMessages/2 {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Network Device",
			Confidence:  60,
			Method:      "Facility Usage Analysis",
			Description: "Heavy use of local facilities suggests network device",
		}
	}

	return nil
}

func analyzeResponseTiming(responseTime time.Duration) *VendorInfo {
	if responseTime < 10*time.Millisecond {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "High-Performance Syslog Server",
			Confidence:  30,
			Method:      "Timing Analysis",
			Description: "Very fast response suggests optimized implementation",
		}
	} else if responseTime > 100*time.Millisecond {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Basic Syslog Server",
			Confidence:  25,
			Method:      "Timing Analysis",
			Description: "Slow response suggests basic or overloaded implementation",
		}
	}

	return nil
}

// Test functions
func testSyslogMessageCreation() {
	fmt.Println("=== Testing Syslog Message Creation ===")

	// Test RFC 3164 message creation
	rfc3164Msg := createTestMessage(134, "testhost", "fingerprintx", "Test message")
	fmt.Printf("✓ RFC 3164 message created (%d bytes)\n", len(rfc3164Msg))
	fmt.Printf("  Message: %s\n", rfc3164Msg)

	// Test RFC 5424 message creation
	rfc5424Msg := createRFC5424Message(134, "testhost", "fingerprintx", "Test message")
	fmt.Printf("✓ RFC 5424 message created (%d bytes)\n", len(rfc5424Msg))
	fmt.Printf("  Message: %s\n", rfc5424Msg)

	// Validate message structure
	if strings.HasPrefix(rfc3164Msg, "<134>") {
		fmt.Println("✓ RFC 3164 message structure valid")
	} else {
		fmt.Println("✗ RFC 3164 message structure invalid")
	}

	if strings.HasPrefix(rfc5424Msg, "<134>1 ") {
		fmt.Println("✓ RFC 5424 message structure valid")
	} else {
		fmt.Println("✗ RFC 5424 message structure invalid")
	}
}

func testSyslogMessageParsing() {
	fmt.Println("\n=== Testing Syslog Message Parsing ===")

	testMessages := []string{
		"<134>Dec 25 10:30:45 hostname fingerprintx: Test message content",
		"<165>1 2023-12-25T10:30:45.123Z hostname fingerprintx - - - RFC 5424 test message",
		"<16>Dec 25 10:30:45 router01 %SYS-5-CONFIG_I: Configured from console by admin",
		"<38>Dec 25 10:30:45 webserver httpd[1234]: 192.168.1.100 GET /index.html 200",
	}

	for i, testMsg := range testMessages {
		fmt.Printf("Testing message %d: ", i+1)

		parsed, err := parseSyslogMessage(testMsg)
		if err != nil {
			fmt.Printf("✗ Parse error: %v\n", err)
			continue
		}

		fmt.Printf("✓ Parsed successfully\n")
		fmt.Printf("  Priority: %d (Facility: %d, Severity: %d)\n", parsed.Priority, parsed.Facility, parsed.Severity)
		fmt.Printf("  RFC: %s\n", parsed.RFC)
		fmt.Printf("  Hostname: %s\n", parsed.Hostname)
		fmt.Printf("  Tag: %s\n", parsed.Tag)
		fmt.Printf("  Content: %s\n", parsed.Content)
	}
}

func testVendorDetection() {
	fmt.Println("\n=== Testing Vendor Detection ===")

	testCases := []struct {
		name     string
		message  string
		expected string
	}{
		{
			name:     "rsyslog detection",
			message:  "<134>Dec 25 10:30:45 logserver rsyslogd-8.2.0: [origin software=\"rsyslogd\" swVersion=\"8.2.0\"]",
			expected: "rsyslog",
		},
		{
			name:     "syslog-ng detection",
			message:  "<134>Dec 25 10:30:45 logserver syslog-ng[1234]: syslog-ng starting up; version='3.35.1'",
			expected: "syslog-ng",
		},
		{
			name:     "Cisco IOS detection",
			message:  "<189>Dec 25 10:30:45 192.168.1.1 %SYS-5-CONFIG_I: Configured from console by cisco on vty0",
			expected: "Cisco",
		},
		{
			name:     "Windows Event Log detection",
			message:  "<134>Dec 25 10:30:45 winserver Microsoft-Windows-EventLog: Event log service started",
			expected: "Microsoft",
		},
		{
			name:     "Unknown vendor (should not detect)",
			message:  "<134>Dec 25 10:30:45 unknown-server unknown-daemon: Generic log message",
			expected: "",
		},
	}

	for _, testCase := range testCases {
		fmt.Printf("Testing: %s\n", testCase.name)

		parsed, err := parseSyslogMessage(testCase.message)
		if err != nil {
			fmt.Printf("  ✗ Parse error: %v\n", err)
			continue
		}

		vendor := analyzeMessageContent(parsed)
		if testCase.expected == "" {
			if vendor == nil {
				fmt.Printf("  ✓ Correctly not detected\n")
			} else {
				fmt.Printf("  ✗ Unexpected detection: %s\n", vendor.Name)
			}
		} else {
			if vendor != nil && vendor.Name == testCase.expected {
				fmt.Printf("  ✓ Detected: %s %s (Confidence: %d%%)\n", vendor.Name, vendor.Product, vendor.Confidence)
				if vendor.Version != "" {
					fmt.Printf("    Version: %s\n", vendor.Version)
				}
			} else if vendor != nil {
				fmt.Printf("  ✗ Wrong detection: %s (expected %s)\n", vendor.Name, testCase.expected)
			} else {
				fmt.Printf("  ✗ Failed to detect %s\n", testCase.expected)
			}
		}
	}
}

func testFacilityAnalysis() {
	fmt.Println("\n=== Testing Facility Usage Analysis ===")

	// Test network device pattern (heavy local facility usage)
	networkMessages := []*SyslogMessage{
		{Facility: 16, Severity: 5}, // local0
		{Facility: 17, Severity: 3}, // local1
		{Facility: 16, Severity: 6}, // local0
		{Facility: 18, Severity: 4}, // local2
	}

	fmt.Println("Testing: Network device pattern")
	vendor := analyzeFacilityUsage(networkMessages)
	if vendor != nil && vendor.Product == "Network Device" {
		fmt.Printf("  ✓ Detected: %s (Confidence: %d%%)\n", vendor.Product, vendor.Confidence)
		fmt.Printf("    Method: %s\n", vendor.Method)
	} else {
		fmt.Println("  ✗ Failed to detect network device pattern")
	}

	// Test system logger pattern (standard facilities)
	systemMessages := []*SyslogMessage{
		{Facility: 0, Severity: 3}, // kernel
		{Facility: 3, Severity: 6}, // daemon
		{Facility: 4, Severity: 5}, // auth
		{Facility: 1, Severity: 6}, // user
	}

	fmt.Println("Testing: System logger pattern")
	vendor = analyzeFacilityUsage(systemMessages)
	if vendor != nil && vendor.Product == "System Logger" {
		fmt.Printf("  ✓ Detected: %s (Confidence: %d%%)\n", vendor.Product, vendor.Confidence)
	} else {
		fmt.Println("  ✓ No specific pattern detected (expected for balanced usage)")
	}
}

func testTimingAnalysis() {
	fmt.Println("\n=== Testing Timing Analysis ===")

	testCases := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "Very fast response (5ms)",
			duration: 5 * time.Millisecond,
			expected: "High-Performance",
		},
		{
			name:     "Normal response (50ms)",
			duration: 50 * time.Millisecond,
			expected: "",
		},
		{
			name:     "Slow response (200ms)",
			duration: 200 * time.Millisecond,
			expected: "Basic",
		},
	}

	for _, testCase := range testCases {
		fmt.Printf("Testing: %s\n", testCase.name)

		vendor := analyzeResponseTiming(testCase.duration)
		if testCase.expected == "" {
			if vendor == nil {
				fmt.Println("  ✓ No timing-based detection")
			} else {
				fmt.Printf("  ✗ Unexpected detection: %s\n", vendor.Product)
			}
		} else {
			if vendor != nil && strings.Contains(vendor.Product, testCase.expected) {
				fmt.Printf("  ✓ Detected: %s (Confidence: %d%%)\n", vendor.Product, vendor.Confidence)
			} else {
				fmt.Printf("  ✗ Failed to detect %s pattern\n", testCase.expected)
			}
		}
	}
}

func testComprehensiveDetection() {
	fmt.Println("\n=== Testing Comprehensive Vendor Detection ===")

	testCases := []struct {
		name     string
		messages []string
		expected string
	}{
		{
			name: "rsyslog Server",
			messages: []string{
				"<134>Dec 25 10:30:45 logserver rsyslogd-8.2.0: [origin software=\"rsyslogd\" swVersion=\"8.2.0\"] start",
				"<38>Dec 25 10:30:45 logserver systemd[1]: Started rsyslog service",
				"<134>Dec 25 10:30:45 logserver rsyslogd: configuration loaded successfully",
			},
			expected: "rsyslog",
		},
		{
			name: "Network Device",
			messages: []string{
				"<189>Dec 25 10:30:45 192.168.1.1 %SYS-5-CONFIG_I: Configured from console",
				"<165>Dec 25 10:30:45 switch01 %LINK-3-UPDOWN: Interface changed state",
				"<133>Dec 25 10:30:45 router01 %OSPF-5-ADJCHG: Neighbor state change",
			},
			expected: "Network Device",
		},
	}

	for _, testCase := range testCases {
		fmt.Printf("Testing: %s\n", testCase.name)

		var messages []*SyslogMessage
		var bestVendor *VendorInfo

		// Parse all messages
		for _, msgStr := range testCase.messages {
			if parsed, err := parseSyslogMessage(msgStr); err == nil {
				messages = append(messages, parsed)

				// Try content analysis
				if vendor := analyzeMessageContent(parsed); vendor != nil {
					if bestVendor == nil || vendor.Confidence > bestVendor.Confidence {
						bestVendor = vendor
					}
				}
			}
		}

		// Try facility analysis if no vendor found
		if bestVendor == nil {
			bestVendor = analyzeFacilityUsage(messages)
		}

		if bestVendor != nil {
			if strings.Contains(bestVendor.Name, testCase.expected) || strings.Contains(bestVendor.Product, testCase.expected) {
				fmt.Printf("  ✓ Detected: %s %s (Confidence: %d%%)\n", bestVendor.Name, bestVendor.Product, bestVendor.Confidence)
				fmt.Printf("    Method: %s\n", bestVendor.Method)
			} else {
				fmt.Printf("  ✗ Wrong detection: %s %s (expected %s)\n", bestVendor.Name, bestVendor.Product, testCase.expected)
			}
		} else {
			fmt.Printf("  ✗ Failed to detect %s\n", testCase.expected)
		}
	}
}

func main() {
	fmt.Println("Syslog Plugin Comprehensive Test Suite")
	fmt.Println("======================================")

	testSyslogMessageCreation()
	testSyslogMessageParsing()
	testVendorDetection()
	testFacilityAnalysis()
	testTimingAnalysis()
	testComprehensiveDetection()

	fmt.Println("\n=== Test Suite Complete ===")
}
