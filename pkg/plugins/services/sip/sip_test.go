package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Test structures (simplified versions of the main plugin)

type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int
	Method      string
	Description string
}

type SIPResponse struct {
	StatusCode   int
	ReasonPhrase string
	Headers      map[string]string
	Body         string
	RawResponse  string
}

// Test vendor patterns (subset of main plugin patterns)
var testVendorPatterns = []struct {
	Pattern     *regexp.Regexp
	VendorInfo  VendorInfo
	Description string
}{
	{
		Pattern: regexp.MustCompile(`(?i)asterisk\s+pbx\s*(\d+\.\d+\.\d+)?`),
		VendorInfo: VendorInfo{
			Name:        "Asterisk",
			Product:     "Asterisk PBX",
			Confidence:  95,
			Description: "Asterisk Open Source PBX",
		},
		Description: "Asterisk PBX identification",
	},
	{
		Pattern: regexp.MustCompile(`(?i)freeswitch-mod_sofia/(\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "FreeSWITCH",
			Product:     "FreeSWITCH",
			Confidence:  95,
			Description: "FreeSWITCH Telephony Platform",
		},
		Description: "FreeSWITCH with version",
	},
	{
		Pattern: regexp.MustCompile(`(?i)cisco-cucm(\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Cisco",
			Product:     "CUCM",
			Confidence:  95,
			Description: "Cisco Unified Communications Manager",
		},
		Description: "Cisco CUCM with version",
	},
	{
		Pattern: regexp.MustCompile(`(?i)avaya\s+one-x\s+deskphone`),
		VendorInfo: VendorInfo{
			Name:        "Avaya",
			Product:     "One-X Deskphone",
			Confidence:  95,
			Description: "Avaya One-X Deskphone",
		},
		Description: "Avaya One-X Deskphone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)3cx\s+phone\s+system\s+(\d+\.\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "3CX",
			Product:     "Phone System",
			Confidence:  95,
			Description: "3CX Phone System",
		},
		Description: "3CX Phone System with version",
	},
}

// Test SIP packet creation
func testSIPPacketCreation() {
	fmt.Println("=== Testing SIP Packet Creation ===")

	// Test OPTIONS request creation
	optionsRequest := createTestOPTIONSRequest("192.168.1.100", "192.168.1.1")
	fmt.Printf("✓ OPTIONS request created (%d bytes)\n", len(optionsRequest))

	// Validate OPTIONS request structure
	lines := strings.Split(optionsRequest, "\r\n")
	if len(lines) < 8 {
		fmt.Printf("✗ Invalid OPTIONS request structure: %d lines (expected >= 8)\n", len(lines))
	} else {
		fmt.Printf("✓ OPTIONS request structure valid\n")
	}

	// Check request line
	if !strings.HasPrefix(lines[0], "OPTIONS sip:") || !strings.HasSuffix(lines[0], " SIP/2.0") {
		fmt.Printf("✗ Invalid OPTIONS request line: %s\n", lines[0])
	} else {
		fmt.Printf("✓ OPTIONS request line correct\n")
	}

	// Test INVITE request creation
	inviteRequest := createTestINVITERequest("192.168.1.100", "192.168.1.1")
	fmt.Printf("✓ INVITE request created (%d bytes)\n", len(inviteRequest))

	// Validate INVITE request structure
	lines = strings.Split(inviteRequest, "\r\n")
	if len(lines) < 15 {
		fmt.Printf("✗ Invalid INVITE request structure: %d lines (expected >= 15)\n", len(lines))
	} else {
		fmt.Printf("✓ INVITE request structure valid\n")
	}

	// Check for SDP body
	if !strings.Contains(inviteRequest, "v=0") || !strings.Contains(inviteRequest, "m=audio") {
		fmt.Printf("✗ INVITE request missing SDP body\n")
	} else {
		fmt.Printf("✓ INVITE request contains SDP body\n")
	}
}

// Test SIP response parsing
func testSIPResponseParsing() {
	fmt.Println("\n=== Testing SIP Response Parsing ===")

	// Test successful response parsing
	testResponses := []string{
		createMockSIPResponse(200, "OK", map[string]string{
			"User-Agent": "Asterisk PBX 18.9.0",
			"Allow":      "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS",
			"Supported":  "replaces, timer",
		}),
		createMockSIPResponse(401, "Unauthorized", map[string]string{
			"Server":           "FreeSWITCH-mod_sofia/1.10.7-release",
			"WWW-Authenticate": "Digest realm=\"test.com\", nonce=\"12345\"",
		}),
		createMockSIPResponse(404, "Not Found", map[string]string{
			"User-Agent": "Cisco-CUCM11.5",
			"Allow":      "INVITE, OPTIONS, BYE, CANCEL, SUBSCRIBE, NOTIFY",
		}),
	}

	for i, responseStr := range testResponses {
		response, err := parseSIPResponse(responseStr)
		if err != nil {
			fmt.Printf("✗ Response %d parsing failed: %v\n", i+1, err)
			continue
		}

		fmt.Printf("✓ Response %d parsed successfully\n", i+1)
		fmt.Printf("  Status: %d %s\n", response.StatusCode, response.ReasonPhrase)
		fmt.Printf("  Headers: %d\n", len(response.Headers))

		// Validate specific fields
		if response.StatusCode < 100 || response.StatusCode > 699 {
			fmt.Printf("✗ Invalid status code: %d\n", response.StatusCode)
		}

		if response.ReasonPhrase == "" {
			fmt.Printf("✗ Missing reason phrase\n")
		}
	}
}

// Test vendor detection
func testVendorDetection() {
	fmt.Println("\n=== Testing Vendor Detection ===")

	testCases := []struct {
		userAgent    string
		server       string
		expectedName string
		description  string
	}{
		{
			userAgent:    "Asterisk PBX 18.9.0",
			expectedName: "Asterisk",
			description:  "Asterisk PBX detection",
		},
		{
			userAgent:    "FreeSWITCH-mod_sofia/1.10.7-release",
			expectedName: "FreeSWITCH",
			description:  "FreeSWITCH detection",
		},
		{
			server:       "Cisco-CUCM11.5",
			expectedName: "Cisco",
			description:  "Cisco CUCM detection",
		},
		{
			userAgent:    "Avaya one-X Deskphone",
			expectedName: "Avaya",
			description:  "Avaya phone detection",
		},
		{
			userAgent:    "3CX Phone System 18.0.3.461",
			expectedName: "3CX",
			description:  "3CX system detection",
		},
		{
			userAgent:    "Unknown SIP Client 1.0",
			expectedName: "",
			description:  "Unknown client (should not detect)",
		},
	}

	for _, testCase := range testCases {
		fmt.Printf("Testing: %s\n", testCase.description)

		// Create mock response
		headers := make(map[string]string)
		if testCase.userAgent != "" {
			headers["user-agent"] = testCase.userAgent
		}
		if testCase.server != "" {
			headers["server"] = testCase.server
		}

		response := &SIPResponse{
			StatusCode:   200,
			ReasonPhrase: "OK",
			Headers:      headers,
		}

		vendor := analyzeUserAgent(response)
		if testCase.expectedName == "" {
			if vendor == nil {
				fmt.Printf("  ✓ Correctly not detected\n")
			} else {
				fmt.Printf("  ✗ Unexpected detection: %s\n", vendor.Name)
			}
		} else {
			if vendor != nil && vendor.Name == testCase.expectedName {
				fmt.Printf("  ✓ Detected %s %s (Confidence: %d%%)\n",
					vendor.Name, vendor.Product, vendor.Confidence)
				if vendor.Version != "" {
					fmt.Printf("    Version: %s\n", vendor.Version)
				}
			} else if vendor == nil {
				fmt.Printf("  ✗ Failed to detect %s\n", testCase.expectedName)
			} else {
				fmt.Printf("  ✗ Wrong detection: expected %s, got %s\n",
					testCase.expectedName, vendor.Name)
			}
		}
	}
}

// Test response pattern analysis
func testResponsePatternAnalysis() {
	fmt.Println("\n=== Testing Response Pattern Analysis ===")

	testCases := []struct {
		allow       string
		supported   string
		description string
		expectType  string
	}{
		{
			allow:       "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS, INFO, PRACK, UPDATE, REFER, SUBSCRIBE, NOTIFY",
			supported:   "replaces, timer, 100rel, gruu",
			description: "Full-featured PBX",
			expectType:  "Full-Featured PBX",
		},
		{
			allow:       "INVITE, ACK, CANCEL, BYE",
			supported:   "",
			description: "Basic SIP device",
			expectType:  "Basic SIP Device",
		},
		{
			allow:       "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS, cisco-extension",
			supported:   "cisco-timer, cisco-replaces",
			description: "Cisco device with extensions",
			expectType:  "Cisco",
		},
	}

	for _, testCase := range testCases {
		fmt.Printf("Testing: %s\n", testCase.description)

		headers := make(map[string]string)
		if testCase.allow != "" {
			headers["allow"] = testCase.allow
		}
		if testCase.supported != "" {
			headers["supported"] = testCase.supported
		}

		response := &SIPResponse{
			StatusCode:   200,
			ReasonPhrase: "OK",
			Headers:      headers,
		}

		vendor := analyzeResponsePatterns(response)
		if vendor != nil {
			fmt.Printf("  ✓ Detected: %s (Confidence: %d%%)\n",
				vendor.Product, vendor.Confidence)
			fmt.Printf("    Method: %s\n", vendor.Method)
		} else {
			fmt.Printf("  ○ No pattern-based detection\n")
		}
	}
}

// Test timing analysis
func testTimingAnalysis() {
	fmt.Println("\n=== Testing Timing Analysis ===")

	timingTests := []struct {
		responseTime time.Duration
		description  string
	}{
		{25 * time.Millisecond, "Very fast response"},
		{100 * time.Millisecond, "Normal response"},
		{750 * time.Millisecond, "Slow response"},
	}

	for _, test := range timingTests {
		vendor := analyzeTimingBehavior(test.responseTime)
		if vendor != nil {
			fmt.Printf("  %s (%v): %s (Confidence: %d%%)\n",
				test.description, test.responseTime, vendor.Description, vendor.Confidence)
		} else {
			fmt.Printf("  %s (%v): No timing-based detection\n",
				test.description, test.responseTime)
		}
	}
}

// Test comprehensive vendor detection
func testComprehensiveDetection() {
	fmt.Println("\n=== Testing Comprehensive Vendor Detection ===")

	// Simulate different vendor responses
	testScenarios := []struct {
		name         string
		statusCode   int
		headers      map[string]string
		expectVendor string
	}{
		{
			name:       "Asterisk PBX Server",
			statusCode: 200,
			headers: map[string]string{
				"user-agent": "Asterisk PBX 18.9.0",
				"server":     "Asterisk PBX 18.9.0",
				"allow":      "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS, INFO, PRACK, UPDATE, REFER, SUBSCRIBE, NOTIFY",
				"supported":  "replaces, timer",
			},
			expectVendor: "Asterisk",
		},
		{
			name:       "FreeSWITCH Server",
			statusCode: 200,
			headers: map[string]string{
				"user-agent": "FreeSWITCH-mod_sofia/1.10.7-release",
				"allow":      "INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, UPDATE, REGISTER, REFER, NOTIFY, PUBLISH, SUBSCRIBE",
				"supported":  "timer, path, replaces",
			},
			expectVendor: "FreeSWITCH",
		},
		{
			name:       "Cisco CUCM",
			statusCode: 401,
			headers: map[string]string{
				"server":           "Cisco-CUCM11.5",
				"www-authenticate": "Digest realm=\"asterisk\", nonce=\"1234567890\"",
				"allow":            "INVITE, OPTIONS, BYE, CANCEL, SUBSCRIBE, NOTIFY, REFER, INFO, PUBLISH",
			},
			expectVendor: "Cisco",
		},
	}

	for _, scenario := range testScenarios {
		fmt.Printf("Testing: %s\n", scenario.name)

		response := &SIPResponse{
			StatusCode:   scenario.statusCode,
			ReasonPhrase: getReasonPhrase(scenario.statusCode),
			Headers:      scenario.headers,
		}

		// Test User-Agent analysis
		vendor := analyzeUserAgent(response)
		if vendor != nil {
			fmt.Printf("  ✓ User-Agent Detection: %s %s", vendor.Name, vendor.Product)
			if vendor.Version != "" {
				fmt.Printf(" %s", vendor.Version)
			}
			fmt.Printf(" (Confidence: %d%%)\n", vendor.Confidence)
		}

		// Test pattern analysis
		patternVendor := analyzeResponsePatterns(response)
		if patternVendor != nil {
			fmt.Printf("  ✓ Pattern Detection: %s (Confidence: %d%%)\n",
				patternVendor.Product, patternVendor.Confidence)
		}

		// Verify expected vendor
		if vendor != nil && vendor.Name == scenario.expectVendor {
			fmt.Printf("  ✓ Expected vendor detected correctly\n")
		} else if vendor == nil {
			fmt.Printf("  ✗ Failed to detect expected vendor: %s\n", scenario.expectVendor)
		} else {
			fmt.Printf("  ✗ Wrong vendor detected: expected %s, got %s\n",
				scenario.expectVendor, vendor.Name)
		}
	}
}

// Helper functions (simplified versions of main plugin functions)

func createTestOPTIONSRequest(target string, sourceIP string) string {
	request := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-test\r\n", sourceIP)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:%s>\r\n", target)
	request += "Call-ID: test@test.com\r\n"
	request += "CSeq: 1 OPTIONS\r\n"
	request += "Max-Forwards: 70\r\n"
	request += "User-Agent: Fingerprintx-SIP-Scanner\r\n"
	request += "Content-Length: 0\r\n"
	request += "\r\n"
	return request
}

func createTestINVITERequest(target string, sourceIP string) string {
	sdpBody := "v=0\r\n"
	sdpBody += fmt.Sprintf("o=test 123456 654321 IN IP4 %s\r\n", sourceIP)
	sdpBody += "s=Test Session\r\n"
	sdpBody += fmt.Sprintf("c=IN IP4 %s\r\n", sourceIP)
	sdpBody += "t=0 0\r\n"
	sdpBody += "m=audio 5004 RTP/AVP 0 8\r\n"
	sdpBody += "a=rtpmap:0 PCMU/8000\r\n"
	sdpBody += "a=rtpmap:8 PCMA/8000\r\n"

	request := fmt.Sprintf("INVITE sip:test@%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-test\r\n", sourceIP)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:test@%s>\r\n", target)
	request += "Call-ID: test@test.com\r\n"
	request += "CSeq: 1 INVITE\r\n"
	request += "Max-Forwards: 70\r\n"
	request += "User-Agent: Fingerprintx-SIP-Scanner\r\n"
	request += "Contact: <sip:test@" + sourceIP + ":5060>\r\n"
	request += "Content-Type: application/sdp\r\n"
	request += fmt.Sprintf("Content-Length: %d\r\n", len(sdpBody))
	request += "\r\n"
	request += sdpBody
	return request
}

func createMockSIPResponse(statusCode int, reasonPhrase string, headers map[string]string) string {
	response := fmt.Sprintf("SIP/2.0 %d %s\r\n", statusCode, reasonPhrase)

	for name, value := range headers {
		response += fmt.Sprintf("%s: %s\r\n", name, value)
	}

	response += "Content-Length: 0\r\n"
	response += "\r\n"

	return response
}

func parseSIPResponse(response string) (*SIPResponse, error) {
	lines := strings.Split(response, "\r\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid SIP response")
	}

	// Parse status line
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[0], "SIP/2.0") {
		return nil, fmt.Errorf("invalid SIP status line")
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code")
	}

	reasonPhrase := parts[2]

	// Parse headers
	headers := make(map[string]string)
	bodyStart := -1

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			bodyStart = i + 1
			break
		}

		colonIndex := strings.Index(line, ":")
		if colonIndex > 0 {
			headerName := strings.TrimSpace(line[:colonIndex])
			headerValue := strings.TrimSpace(line[colonIndex+1:])
			headers[strings.ToLower(headerName)] = headerValue
		}
	}

	// Extract body
	var body string
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\r\n")
	}

	return &SIPResponse{
		StatusCode:   statusCode,
		ReasonPhrase: reasonPhrase,
		Headers:      headers,
		Body:         body,
		RawResponse:  response,
	}, nil
}

func analyzeUserAgent(response *SIPResponse) *VendorInfo {
	// Check User-Agent header first
	if userAgent, exists := response.Headers["user-agent"]; exists {
		for _, pattern := range testVendorPatterns {
			if matches := pattern.Pattern.FindStringSubmatch(userAgent); matches != nil {
				vendorInfo := pattern.VendorInfo
				vendorInfo.Method = "User-Agent Analysis"

				// Extract version if captured
				if len(matches) > 1 && matches[1] != "" {
					vendorInfo.Version = matches[1]
				}

				return &vendorInfo
			}
		}
	}

	// Check Server header
	if server, exists := response.Headers["server"]; exists {
		for _, pattern := range testVendorPatterns {
			if matches := pattern.Pattern.FindStringSubmatch(server); matches != nil {
				vendorInfo := pattern.VendorInfo
				vendorInfo.Method = "Server Header Analysis"

				// Extract version if captured
				if len(matches) > 1 && matches[1] != "" {
					vendorInfo.Version = matches[1]
				}

				return &vendorInfo
			}
		}
	}

	return nil
}

func analyzeResponsePatterns(response *SIPResponse) *VendorInfo {
	// Analyze Allow header for method support patterns
	if allow, exists := response.Headers["allow"]; exists {
		methods := strings.Split(allow, ",")
		methodCount := len(methods)

		// Different implementations support different method sets
		if methodCount > 10 {
			return &VendorInfo{
				Name:        "Unknown",
				Product:     "Full-Featured PBX",
				Confidence:  40,
				Method:      "Method Support Analysis",
				Description: "Comprehensive SIP method support suggests full PBX",
			}
		} else if methodCount < 6 {
			return &VendorInfo{
				Name:        "Unknown",
				Product:     "Basic SIP Device",
				Confidence:  30,
				Method:      "Method Support Analysis",
				Description: "Limited SIP method support suggests basic device",
			}
		}
	}

	// Analyze Supported header for extension patterns
	if supported, exists := response.Headers["supported"]; exists {
		extensions := strings.Split(supported, ",")

		// Look for vendor-specific extension patterns
		for _, ext := range extensions {
			ext = strings.TrimSpace(ext)
			if strings.Contains(ext, "cisco") {
				return &VendorInfo{
					Name:        "Cisco",
					Product:     "Unknown",
					Confidence:  60,
					Method:      "Extension Analysis",
					Description: "Cisco-specific SIP extensions detected",
				}
			}
		}
	}

	return nil
}

func analyzeTimingBehavior(responseTime time.Duration) *VendorInfo {
	if responseTime < 50*time.Millisecond {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Fast SIP Implementation",
			Confidence:  25,
			Method:      "Timing Analysis",
			Description: "Very fast response suggests optimized implementation",
		}
	} else if responseTime > 500*time.Millisecond {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Slow SIP Implementation",
			Confidence:  25,
			Method:      "Timing Analysis",
			Description: "Slow response suggests complex processing or high load",
		}
	}

	return nil
}

func getReasonPhrase(statusCode int) string {
	switch statusCode {
	case 200:
		return "OK"
	case 401:
		return "Unauthorized"
	case 404:
		return "Not Found"
	case 500:
		return "Internal Server Error"
	default:
		return "Unknown"
	}
}

func main() {
	fmt.Println("SIP Plugin Comprehensive Test Suite")
	fmt.Println("====================================")

	testSIPPacketCreation()
	testSIPResponseParsing()
	testVendorDetection()
	testResponsePatternAnalysis()
	testTimingAnalysis()
	testComprehensiveDetection()

	fmt.Println("\n=== Test Suite Complete ===")
}
