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

package syslog

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
)

const SYSLOG = "Syslog"

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

// SyslogMessage represents a parsed syslog message
type SyslogMessage struct {
	Priority   int
	Facility   int
	Severity   int
	Timestamp  string
	Hostname   string
	Tag        string
	Content    string
	RawMessage string
	RFC        string // "3164" or "5424"
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Known syslog server patterns and characteristics
var vendorPatterns = []struct {
	Pattern     *regexp.Regexp
	VendorInfo  VendorInfo
	Description string
}{
	// rsyslog patterns
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
		Pattern: regexp.MustCompile(`(?i)rsyslog`),
		VendorInfo: VendorInfo{
			Name:        "rsyslog",
			Product:     "rsyslogd",
			Confidence:  90,
			Description: "rsyslog - High-performance syslog daemon",
		},
		Description: "Generic rsyslog identification",
	},

	// syslog-ng patterns
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
		Pattern: regexp.MustCompile(`(?i)syslog-ng`),
		VendorInfo: VendorInfo{
			Name:        "syslog-ng",
			Product:     "syslog-ng",
			Confidence:  90,
			Description: "syslog-ng - Advanced syslog daemon",
		},
		Description: "Generic syslog-ng identification",
	},

	// Traditional syslogd patterns
	{
		Pattern: regexp.MustCompile(`(?i)syslogd.*(\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "BSD",
			Product:     "syslogd",
			Confidence:  85,
			Description: "Traditional BSD syslogd",
		},
		Description: "BSD syslogd with version",
	},

	// Windows Event Log patterns
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
	{
		Pattern: regexp.MustCompile(`(?i)nxlog`),
		VendorInfo: VendorInfo{
			Name:        "NXLog",
			Product:     "NXLog",
			Confidence:  90,
			Description: "NXLog - Multi-platform log collection",
		},
		Description: "NXLog forwarder",
	},

	// Network device patterns
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
		Pattern: regexp.MustCompile(`(?i)juniper`),
		VendorInfo: VendorInfo{
			Name:        "Juniper",
			Product:     "JunOS",
			Confidence:  85,
			Description: "Juniper Networks Device",
		},
		Description: "Juniper device",
	},
	{
		Pattern: regexp.MustCompile(`(?i)palo.*alto`),
		VendorInfo: VendorInfo{
			Name:        "Palo Alto",
			Product:     "PAN-OS",
			Confidence:  85,
			Description: "Palo Alto Networks Device",
		},
		Description: "Palo Alto device",
	},

	// Application patterns
	{
		Pattern: regexp.MustCompile(`(?i)apache.*httpd`),
		VendorInfo: VendorInfo{
			Name:        "Apache",
			Product:     "HTTP Server",
			Confidence:  80,
			Description: "Apache HTTP Server logs",
		},
		Description: "Apache web server",
	},
	{
		Pattern: regexp.MustCompile(`(?i)nginx`),
		VendorInfo: VendorInfo{
			Name:        "nginx",
			Product:     "Web Server",
			Confidence:  80,
			Description: "nginx Web Server logs",
		},
		Description: "nginx web server",
	},
}

// Facility names for analysis
var facilityNames = map[int]string{
	0:  "kernel",
	1:  "user",
	2:  "mail",
	3:  "daemon",
	4:  "auth",
	5:  "syslog",
	6:  "lpr",
	7:  "news",
	8:  "uucp",
	9:  "cron",
	10: "authpriv",
	11: "ftp",
	12: "ntp",
	13: "audit",
	14: "alert",
	15: "clock",
	16: "local0",
	17: "local1",
	18: "local2",
	19: "local3",
	20: "local4",
	21: "local5",
	22: "local6",
	23: "local7",
}

// Severity names for analysis
var severityNames = map[int]string{
	0: "emergency",
	1: "alert",
	2: "critical",
	3: "error",
	4: "warning",
	5: "notice",
	6: "info",
	7: "debug",
}

// createTestMessage creates a test syslog message
func createTestMessage(priority int, hostname string, tag string, content string) string {
	timestamp := time.Now().Format("Jan 02 15:04:05")
	return fmt.Sprintf("<%d>%s %s %s: %s", priority, timestamp, hostname, tag, content)
}

// createRFC5424Message creates an RFC 5424 formatted test message
func createRFC5424Message(priority int, hostname string, appName string, content string) string {
	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf("<%d>1 %s %s %s - - - %s", priority, timestamp, hostname, appName, content)
}

// parseSyslogMessage parses a syslog message and extracts components
func parseSyslogMessage(message string) (*SyslogMessage, error) {
	if len(message) < 5 {
		return nil, fmt.Errorf("message too short")
	}

	// Check for priority
	if message[0] != '<' {
		return nil, fmt.Errorf("invalid priority format")
	}

	// Find end of priority
	priEnd := strings.Index(message, ">")
	if priEnd == -1 {
		return nil, fmt.Errorf("priority not closed")
	}

	// Parse priority
	priorityStr := message[1:priEnd]
	priority, err := strconv.Atoi(priorityStr)
	if err != nil {
		return nil, fmt.Errorf("invalid priority value")
	}

	facility := priority / 8
	severity := priority % 8

	remainder := message[priEnd+1:]

	// Determine RFC format
	rfc := "3164"
	if len(remainder) > 0 && remainder[0] == '1' && len(remainder) > 1 && remainder[1] == ' ' {
		rfc = "5424"
		remainder = remainder[2:] // Skip version
	}

	// Parse timestamp and hostname (simplified)
	parts := strings.SplitN(remainder, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("insufficient message parts")
	}

	var timestamp, hostname, msgPart string
	if rfc == "5424" {
		timestamp = parts[0]
		hostname = parts[1]
		if len(parts) > 2 {
			msgPart = parts[2]
		}
	} else {
		// RFC 3164 format: timestamp hostname message
		timestamp = parts[0] + " " + parts[1]
		hostname = parts[2]
		if len(parts) > 3 {
			msgPart = strings.Join(parts[3:], " ")
		}
	}

	// Parse tag and content from message part
	var tag, content string
	if msgPart != "" {
		colonIndex := strings.Index(msgPart, ":")
		bracketIndex := strings.Index(msgPart, "[")

		if colonIndex > 0 && (bracketIndex == -1 || colonIndex < bracketIndex) {
			tag = msgPart[:colonIndex]
			content = strings.TrimSpace(msgPart[colonIndex+1:])
		} else if bracketIndex > 0 {
			closeBracket := strings.Index(msgPart, "]")
			if closeBracket > bracketIndex {
				tag = msgPart[:closeBracket+1]
				remainder := msgPart[closeBracket+1:]
				if strings.HasPrefix(remainder, ":") {
					content = strings.TrimSpace(remainder[1:])
				} else {
					content = strings.TrimSpace(remainder)
				}
			}
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

// analyzeMessageContent analyzes message content for vendor patterns
func analyzeMessageContent(message *SyslogMessage) *VendorInfo {
	// Combine all text fields for pattern matching
	searchText := strings.ToLower(message.Tag + " " + message.Content + " " + message.Hostname)

	for _, pattern := range vendorPatterns {
		if matches := pattern.Pattern.FindStringSubmatch(searchText); matches != nil {
			vendorInfo := pattern.VendorInfo
			vendorInfo.Method = "Message Content Analysis"

			// Extract version if captured
			if len(matches) > 1 && matches[1] != "" {
				vendorInfo.Version = matches[1]
			}

			return &vendorInfo
		}
	}

	return nil
}

// analyzeFacilityUsage analyzes facility usage patterns for vendor identification
func analyzeFacilityUsage(messages []*SyslogMessage) *VendorInfo {
	if len(messages) == 0 {
		return nil
	}

	facilityCount := make(map[int]int)
	for _, msg := range messages {
		facilityCount[msg.Facility]++
	}

	// Analyze facility usage patterns
	totalMessages := len(messages)

	// Check for network device patterns (heavy use of local facilities)
	localFacilities := 0
	for facility, count := range facilityCount {
		if facility >= 16 && facility <= 23 { // local0-local7
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

	// Check for system daemon patterns
	systemFacilities := 0
	for facility, count := range facilityCount {
		if facility >= 0 && facility <= 15 { // Standard system facilities
			systemFacilities += count
		}
	}

	if systemFacilities > totalMessages*3/4 {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "System Logger",
			Confidence:  50,
			Method:      "Facility Usage Analysis",
			Description: "Heavy use of system facilities suggests system logger",
		}
	}

	return nil
}

// analyzeMessageFormat analyzes message format characteristics
func analyzeMessageFormat(messages []*SyslogMessage) *VendorInfo {
	if len(messages) == 0 {
		return nil
	}

	rfc5424Count := 0
	rfc3164Count := 0

	for _, msg := range messages {
		if msg.RFC == "5424" {
			rfc5424Count++
		} else {
			rfc3164Count++
		}
	}

	// Analyze RFC format usage
	if rfc5424Count > rfc3164Count {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Modern Syslog Server",
			Confidence:  40,
			Method:      "Message Format Analysis",
			Description: "Primarily uses RFC 5424 format (structured syslog)",
		}
	} else if rfc3164Count > 0 {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Traditional Syslog Server",
			Confidence:  35,
			Method:      "Message Format Analysis",
			Description: "Primarily uses RFC 3164 format (BSD syslog)",
		}
	}

	return nil
}

// analyzeResponseTiming analyzes response timing characteristics
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

// testSyslogServer performs comprehensive syslog server testing
func testSyslogServer(conn net.Conn, timeout time.Duration, target string) (*VendorInfo, []*SyslogMessage, error) {
	var bestVendor *VendorInfo
	var messages []*SyslogMessage

	// Test messages to send
	testMessages := []string{
		createTestMessage(134, "test-host", "fingerprintx", "Test message for syslog detection"),
		createTestMessage(165, "scanner", "test", "Syslog server capability test"),
		createRFC5424Message(134, "test-host", "fingerprintx", "RFC 5424 format test"),
		createTestMessage(16, "kernel", "kernel", "Kernel facility test message"),
		createTestMessage(24, "mail", "postfix", "Mail facility test message"),
	}

	// Send test messages and analyze responses
	for _, testMsg := range testMessages {
		start := time.Now()

		// Send message (syslog is typically fire-and-forget, but we'll try to detect responses)
		_, err := conn.Write([]byte(testMsg + "\n"))
		if err != nil {
			continue
		}

		// Try to read any response (most syslog servers don't respond, but some might)
		conn.SetReadDeadline(time.Now().Add(timeout))
		response := make([]byte, 1024)
		n, readErr := conn.Read(response)
		responseTime := time.Since(start)

		// Parse the test message for analysis
		if parsedMsg, parseErr := parseSyslogMessage(testMsg); parseErr == nil {
			messages = append(messages, parsedMsg)
		}

		// If we got a response, analyze it
		if readErr == nil && n > 0 {
			responseStr := string(response[:n])

			// Try to parse response as syslog message
			if respMsg, respErr := parseSyslogMessage(responseStr); respErr == nil {
				messages = append(messages, respMsg)

				// Analyze response content for vendor identification
				if vendor := analyzeMessageContent(respMsg); vendor != nil {
					if bestVendor == nil || vendor.Confidence > bestVendor.Confidence {
						bestVendor = vendor
					}
				}
			}

			// Analyze response for vendor patterns
			for _, pattern := range vendorPatterns {
				if matches := pattern.Pattern.FindStringSubmatch(strings.ToLower(responseStr)); matches != nil {
					vendorInfo := pattern.VendorInfo
					vendorInfo.Method = "Response Analysis"

					if len(matches) > 1 && matches[1] != "" {
						vendorInfo.Version = matches[1]
					}

					if bestVendor == nil || vendorInfo.Confidence > bestVendor.Confidence {
						bestVendor = &vendorInfo
					}
				}
			}
		}

		// Analyze timing if no vendor found yet
		if bestVendor == nil {
			if vendor := analyzeResponseTiming(responseTime); vendor != nil {
				bestVendor = vendor
			}
		}
	}

	// Analyze message patterns if no vendor found
	if bestVendor == nil {
		if vendor := analyzeFacilityUsage(messages); vendor != nil {
			bestVendor = vendor
		}
	}

	// Analyze message format if still no vendor found
	if bestVendor == nil {
		if vendor := analyzeMessageFormat(messages); vendor != nil {
			bestVendor = vendor
		}
	}

	return bestVendor, messages, nil
}

// createServiceWithVendorInfo creates a service object with vendor information
func createServiceWithVendorInfo(target plugins.Target, vendor *VendorInfo, messages []*SyslogMessage) *plugins.Service {
	serviceName := SYSLOG
	if vendor != nil {
		serviceName = fmt.Sprintf("%s (%s %s)", SYSLOG, vendor.Name, vendor.Product)
		if vendor.Version != "" {
			serviceName = fmt.Sprintf("%s (%s %s %s)", SYSLOG, vendor.Name, vendor.Product, vendor.Version)
		}
	}

	service := &plugins.Service{
		Name:     serviceName,
		Protocol: plugins.UDP, // Syslog commonly uses UDP, but can also use TCP
		Port:     target.Port,
		Host:     target.Host,
		TLS:      false,
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

	// Add message analysis
	if len(messages) > 0 {
		facilityStats := make(map[string]int)
		severityStats := make(map[string]int)
		rfcStats := make(map[string]int)

		for _, msg := range messages {
			if facilityName, exists := facilityNames[msg.Facility]; exists {
				facilityStats[facilityName]++
			}
			if severityName, exists := severityNames[msg.Severity]; exists {
				severityStats[severityName]++
			}
			rfcStats[msg.RFC]++
		}

		service.Details["message_analysis"] = map[string]interface{}{
			"total_messages":   len(messages),
			"facility_usage":   facilityStats,
			"severity_usage":   severityStats,
			"rfc_format_usage": rfcStats,
		}

		// Add sample messages (first few)
		sampleCount := len(messages)
		if sampleCount > 3 {
			sampleCount = 3
		}

		samples := make([]map[string]interface{}, sampleCount)
		for i := 0; i < sampleCount; i++ {
			msg := messages[i]
			samples[i] = map[string]interface{}{
				"priority":  msg.Priority,
				"facility":  facilityNames[msg.Facility],
				"severity":  severityNames[msg.Severity],
				"timestamp": msg.Timestamp,
				"hostname":  msg.Hostname,
				"tag":       msg.Tag,
				"rfc":       msg.RFC,
			}
		}
		service.Details["sample_messages"] = samples
	}

	// Add protocol information
	service.Details["protocol_info"] = map[string]interface{}{
		"standard_port":    514,
		"secure_port":      6514,
		"transport":        []string{"UDP", "TCP", "TLS"},
		"rfc_formats":      []string{"RFC 3164", "RFC 5424"},
		"max_message_size": 1024, // RFC 3164 limit
	}

	return service
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * Comprehensive Syslog Server Detection and Vendor Identification
	 *
	 * This plugin performs multi-stage syslog detection and vendor identification:
	 * 1. Message injection testing with various syslog formats
	 * 2. Response analysis for vendor-specific patterns
	 * 3. Message content analysis for implementation characteristics
	 * 4. Facility usage pattern analysis
	 * 5. Message format analysis (RFC 3164 vs RFC 5424)
	 * 6. Timing behavior analysis for performance characteristics
	 *
	 * Supported vendor detection:
	 * - rsyslog (High-performance syslog daemon)
	 * - syslog-ng (Next-generation syslog daemon)
	 * - Traditional BSD syslogd
	 * - Windows Event Log services (NXLog, etc.)
	 * - Network device syslog (Cisco, Juniper, Palo Alto)
	 * - Application-specific syslog (Apache, nginx, etc.)
	 */

	// Extract target host for message construction
	targetHost := target.Host

	// Attempt vendor detection through active testing
	vendor, messages, err := testSyslogServer(conn, timeout, targetHost)
	if err != nil {
		// If active testing failed, try basic syslog detection
		testMsg := createTestMessage(134, "test", "fingerprintx", "Basic syslog test")
		_, sendErr := conn.Write([]byte(testMsg + "\n"))
		if sendErr != nil {
			return nil, sendErr
		}

		// Try to read any response
		conn.SetReadDeadline(time.Now().Add(timeout))
		response := make([]byte, 512)
		n, readErr := conn.Read(response)

		// Even if no response, if send succeeded, it's likely a syslog server
		if sendErr == nil {
			// Parse our test message for basic service creation
			if parsedMsg, parseErr := parseSyslogMessage(testMsg); parseErr == nil {
				messages = []*SyslogMessage{parsedMsg}
			}

			// Check if we got any response
			if readErr == nil && n > 0 {
				responseStr := string(response[:n])
				if respMsg, respErr := parseSyslogMessage(responseStr); respErr == nil {
					messages = append(messages, respMsg)
				}
			}

			return createServiceWithVendorInfo(target, nil, messages), nil
		}

		return nil, sendErr
	}

	// Create service with detected vendor information
	return createServiceWithVendorInfo(target, vendor, messages), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 514 || i == 6514
}

func (p *Plugin) Name() string {
	return SYSLOG
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 650
}
