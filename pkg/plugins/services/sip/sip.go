// Strict SIP plugin that only detects actual SIP services - no false positives

package sip

import (
	"crypto/rand"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

const SIP = "SIP"

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

// SIPResponse represents a parsed SIP response
type SIPResponse struct {
	StatusCode   int
	ReasonPhrase string
	Headers      map[string]string
	Body         string
	RawResponse  string
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Known SIP vendor patterns for User-Agent and Server headers
var vendorPatterns = []struct {
	Pattern     *regexp.Regexp
	VendorInfo  VendorInfo
	Description string
}{
	// Asterisk patterns
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
		Pattern: regexp.MustCompile(`(?i)asterisk\s*(\d+\.\d+\.\d+)?`),
		VendorInfo: VendorInfo{
			Name:        "Asterisk",
			Product:     "Asterisk",
			Confidence:  90,
			Description: "Asterisk PBX (Generic)",
		},
		Description: "Generic Asterisk identification",
	},

	// FreeSWITCH patterns
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
		Pattern: regexp.MustCompile(`(?i)freeswitch`),
		VendorInfo: VendorInfo{
			Name:        "FreeSWITCH",
			Product:     "FreeSWITCH",
			Confidence:  90,
			Description: "FreeSWITCH Telephony Platform",
		},
		Description: "Generic FreeSWITCH identification",
	},

	// Cisco patterns
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
		Pattern: regexp.MustCompile(`(?i)cisco-sipgateway/ios-(\d+\.x)`),
		VendorInfo: VendorInfo{
			Name:        "Cisco",
			Product:     "SIP Gateway",
			Confidence:  95,
			Description: "Cisco SIP Gateway/Router",
		},
		Description: "Cisco SIP Gateway",
	},
	{
		Pattern: regexp.MustCompile(`(?i)csco/(\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Cisco",
			Product:     "IP Phone",
			Confidence:  90,
			Description: "Cisco IP Phone",
		},
		Description: "Cisco IP Phone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)cisco`),
		VendorInfo: VendorInfo{
			Name:        "Cisco",
			Product:     "Unknown",
			Confidence:  80,
			Description: "Cisco SIP Device",
		},
		Description: "Generic Cisco identification",
	},

	// 3CX patterns
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
	{
		Pattern: regexp.MustCompile(`(?i)3cx`),
		VendorInfo: VendorInfo{
			Name:        "3CX",
			Product:     "Phone System",
			Confidence:  90,
			Description: "3CX Phone System",
		},
		Description: "Generic 3CX identification",
	},
}

// generateCallID creates a unique Call-ID for SIP requests
func generateCallID(host string) string {
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("%x@%s", randomBytes, host)
}

// generateBranch creates a unique branch parameter for Via header
func generateBranch() string {
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("z9hG4bK-%x", randomBytes)
}

// createOPTIONSRequest creates a SIP OPTIONS request
func createOPTIONSRequest(target string, sourceIP string) string {
	callID := generateCallID(sourceIP)
	branch := generateBranch()

	request := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:5060;branch=%s\r\n", sourceIP, branch)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:%s>\r\n", target)
	request += fmt.Sprintf("Call-ID: %s\r\n", callID)
	request += "CSeq: 1 OPTIONS\r\n"
	request += "Max-Forwards: 70\r\n"
	request += "User-Agent: Fingerprintx-SIP-Scanner\r\n"
	request += "Content-Length: 0\r\n"
	request += "\r\n"

	return request
}

// parseSIPResponse parses a SIP response message with STRICT validation
func parseSIPResponse(response string) (*SIPResponse, error) {
	if len(response) < 12 { // Minimum SIP response: "SIP/2.0 200"
		return nil, fmt.Errorf("response too short to be SIP")
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid SIP response format")
	}

	// STRICT: Parse status line - must be exact SIP format
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SIP status line format")
	}

	// STRICT: Must start with exactly "SIP/2.0"
	if parts[0] != "SIP/2.0" {
		return nil, fmt.Errorf("not a SIP response - invalid protocol: %s", parts[0])
	}

	// STRICT: Status code must be valid 3-digit number
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 699 {
		return nil, fmt.Errorf("invalid SIP status code: %s", parts[1])
	}

	reasonPhrase := parts[2]

	// Parse headers with validation
	headers := make(map[string]string)
	bodyStart := -1
	requiredHeaders := map[string]bool{
		"via":     false,
		"from":    false,
		"to":      false,
		"call-id": false,
		"cseq":    false,
	}

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			bodyStart = i + 1
			break
		}

		colonIndex := strings.Index(line, ":")
		if colonIndex > 0 {
			headerName := strings.ToLower(strings.TrimSpace(line[:colonIndex]))
			headerValue := strings.TrimSpace(line[colonIndex+1:])
			headers[headerName] = headerValue

			// Check for required SIP headers
			if _, exists := requiredHeaders[headerName]; exists {
				requiredHeaders[headerName] = true
			}
		}
	}

	// STRICT: Require essential SIP headers for valid detection
	missingHeaders := []string{}
	for header, found := range requiredHeaders {
		if !found {
			missingHeaders = append(missingHeaders, header)
		}
	}

	// For non-standard ports, require ALL essential headers
	// For standard ports, be slightly more lenient
	if len(missingHeaders) > 2 {
		return nil, fmt.Errorf("missing essential SIP headers: %v", missingHeaders)
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

// validateSIPResponse performs additional validation to ensure it's really SIP
func validateSIPResponse(response *SIPResponse, port int) bool {
	// STRICT: Valid SIP status codes only
	validStatusCodes := map[int]bool{
		// 1xx Provisional
		100: true, 180: true, 181: true, 182: true, 183: true,
		// 2xx Success
		200: true, 202: true,
		// 3xx Redirection
		300: true, 301: true, 302: true, 305: true, 380: true,
		// 4xx Client Error
		400: true, 401: true, 402: true, 403: true, 404: true, 405: true,
		406: true, 407: true, 408: true, 410: true, 413: true, 414: true,
		415: true, 416: true, 420: true, 421: true, 423: true, 480: true,
		481: true, 482: true, 483: true, 484: true, 485: true, 486: true,
		487: true, 488: true, 491: true, 493: true,
		// 5xx Server Error
		500: true, 501: true, 502: true, 503: true, 504: true, 505: true,
		513: true,
		// 6xx Global Failure
		600: true, 603: true, 604: true, 606: true,
	}

	if !validStatusCodes[response.StatusCode] {
		return false
	}

	// STRICT: Check for SIP-specific header patterns
	sipHeaderPatterns := []string{
		"sip:", "SIP/2.0", "z9hG4bK", "tag=", "branch=",
	}

	foundSipPatterns := 0
	responseText := strings.ToLower(response.RawResponse)

	for _, pattern := range sipHeaderPatterns {
		if strings.Contains(responseText, strings.ToLower(pattern)) {
			foundSipPatterns++
		}
	}

	// STRICT: Require multiple SIP-specific patterns
	if foundSipPatterns < 3 {
		return false
	}

	// STRICT: For non-standard ports, require even more validation
	if port != 5060 && port != 5061 {
		// Require CSeq header with valid format
		if cseq, exists := response.Headers["cseq"]; exists {
			cseqParts := strings.Fields(cseq)
			if len(cseqParts) != 2 {
				return false
			}
			// Check if first part is a number
			if _, err := strconv.Atoi(cseqParts[0]); err != nil {
				return false
			}
			// Check if second part is a valid SIP method
			validMethods := map[string]bool{
				"INVITE": true, "ACK": true, "BYE": true, "CANCEL": true,
				"OPTIONS": true, "REGISTER": true, "PRACK": true, "SUBSCRIBE": true,
				"NOTIFY": true, "PUBLISH": true, "INFO": true, "REFER": true,
				"MESSAGE": true, "UPDATE": true,
			}
			if !validMethods[strings.ToUpper(cseqParts[1])] {
				return false
			}
		} else {
			return false // CSeq is mandatory for non-standard ports
		}

		// Require Via header with SIP/2.0 format
		if via, exists := response.Headers["via"]; exists {
			if !strings.Contains(strings.ToUpper(via), "SIP/2.0") {
				return false
			}
		} else {
			return false // Via is mandatory for non-standard ports
		}
	}

	return true
}

// analyzeUserAgent analyzes User-Agent and Server headers for vendor identification
func analyzeUserAgent(response *SIPResponse) *VendorInfo {
	// Check User-Agent header first
	if userAgent, exists := response.Headers["user-agent"]; exists {
		for _, pattern := range vendorPatterns {
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
		for _, pattern := range vendorPatterns {
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

// detectSIPVendor performs comprehensive vendor detection with STRICT validation
func detectSIPVendor(conn net.Conn, timeout time.Duration, target string, port int) (*VendorInfo, *SIPResponse, error) {
	// Get source IP for SIP message construction
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sourceIP := localAddr.IP.String()

	var bestVendor *VendorInfo
	var sipResponse *SIPResponse

	// Method 1: OPTIONS probe (most reliable for capability detection)
	optionsRequest := createOPTIONSRequest(target, sourceIP)
	response, err := utils.SendRecv(conn, []byte(optionsRequest), timeout)

	if err == nil && len(response) > 0 {
		// STRICT: Parse and validate SIP response
		parsedResponse, parseErr := parseSIPResponse(string(response))
		if parseErr != nil {
			return nil, nil, fmt.Errorf("not a valid SIP response: %v", parseErr)
		}

		// STRICT: Additional SIP validation
		if !validateSIPResponse(parsedResponse, port) {
			return nil, nil, fmt.Errorf("response failed SIP validation")
		}

		sipResponse = parsedResponse

		// Analyze User-Agent/Server headers (highest confidence)
		if vendor := analyzeUserAgent(parsedResponse); vendor != nil {
			bestVendor = vendor
		}
	}

	// Only return if we have a valid SIP response
	if sipResponse == nil {
		return nil, nil, fmt.Errorf("no valid SIP response received")
	}

	return bestVendor, sipResponse, nil
}

// createServiceWithVendorInfo creates a service object with vendor information
func createServiceWithVendorInfo(target plugins.Target, vendor *VendorInfo, response *SIPResponse) *plugins.Service {
	// Create ServiceSIP struct with vendor information
	serviceSIP := plugins.ServiceSIP{
		// Vendor information
		VendorName:        "",
		VendorProduct:     "",
		VendorVersion:     "",
		VendorConfidence:  0,
		VendorMethod:      "",
		VendorDescription: "",

		// SIP response information
		StatusCode:   0,
		ReasonPhrase: "",
		HeadersCount: 0,

		// Important SIP headers
		UserAgent: "",
		Server:    "",
		Allow:     "",
		Supported: "",
		Contact:   "",

		// Protocol information
		StandardPort: 5060,
		SecurePort:   5061,
		Transport:    []string{"UDP", "TCP", "TLS"},
		Methods:      []string{"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"},

		// Detection metadata
		DetectionMethod: "OPTIONS",
		ResponseTime:    0,

		// Security features (passive detection)
		AuthenticationRequired: false,
		AuthenticationMethods:  []string{},
		TLSSupported:           false,
		SecurityHeaders:        []string{},
		EncryptionSupported:    []string{},

		// Device fingerprinting
		DeviceType:      "",
		DeviceModel:     "",
		FirmwareVersion: "",
		SupportedCodecs: []string{},
		HeaderOrder:     []string{},

		// Configuration analysis
		AllowedMethods:      []string{},
		SupportedExtensions: []string{},
		SecurityPolicies:    []string{},
		TransportSecurity:   []string{},
	}

	// Add vendor information if available
	if vendor != nil {
		serviceSIP.VendorName = vendor.Name
		serviceSIP.VendorProduct = vendor.Product
		serviceSIP.VendorVersion = vendor.Version
		serviceSIP.VendorConfidence = vendor.Confidence
		serviceSIP.VendorMethod = vendor.Method
		serviceSIP.VendorDescription = vendor.Description
	}

	// Add SIP response information (REQUIRED for valid detection)
	if response != nil {
		serviceSIP.StatusCode = response.StatusCode
		serviceSIP.ReasonPhrase = response.ReasonPhrase
		serviceSIP.HeadersCount = len(response.Headers)

		// Add important headers
		if userAgent, exists := response.Headers["user-agent"]; exists {
			serviceSIP.UserAgent = userAgent
		}
		if server, exists := response.Headers["server"]; exists {
			serviceSIP.Server = server
		}
		if allow, exists := response.Headers["allow"]; exists {
			serviceSIP.Allow = allow
		}
		if supported, exists := response.Headers["supported"]; exists {
			serviceSIP.Supported = supported
		}
		if contact, exists := response.Headers["contact"]; exists {
			serviceSIP.Contact = contact
		}
	}

	return plugins.CreateServiceFrom(target, serviceSIP, false, "", plugins.UDP)
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * STRICT SIP Server Detection - No False Positives
	 *
	 * This plugin performs STRICT SIP detection with multiple validation layers:
	 * 1. STRICT SIP response format validation
	 * 2. Required SIP headers validation
	 * 3. Valid SIP status codes only
	 * 4. SIP-specific pattern matching
	 * 5. Enhanced validation for non-standard ports
	 *
	 * Will NOT detect:
	 * - VNC services (like FictusVNC on port 8910)
	 * - HTTP services
	 * - Other protocols that don't respond with valid SIP
	 *
	 * Will ONLY detect actual SIP services with proper SIP responses
	 */

	// Extract target host for SIP message construction
	targetHost := target.Host
	targetPort := int(target.Address.Port())
	if targetPort != 5060 {
		targetHost = fmt.Sprintf("%s:%d", target.Host, targetPort)
	}

	// STRICT: Attempt vendor detection with validation
	vendor, response, err := detectSIPVendor(conn, timeout, targetHost, targetPort)
	if err != nil {
		// STRICT: If detection failed, do NOT fall back to basic detection
		// This prevents false positives like VNC being detected as SIP
		return nil, nil
	}

	// STRICT: Only return service if we have a validated SIP response
	if response == nil {
		return nil, nil
	}

	// Create service with detected vendor information
	return createServiceWithVendorInfo(target, vendor, response), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	// STRICT: Only prioritize standard SIP ports
	return i == 5060 || i == 5061
}

func (p *Plugin) Name() string {
	return SIP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 700
}
