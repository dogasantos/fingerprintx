// Balanced SIP plugin - detects real SIP services but avoids false positives

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

// parseSIPResponse parses a SIP response message with balanced validation
func parseSIPResponse(response string, port int) (*SIPResponse, error) {
	if len(response) < 12 { // Minimum SIP response: "SIP/2.0 200"
		return nil, fmt.Errorf("response too short to be SIP")
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid SIP response format")
	}

	// Parse status line - must be SIP format
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid SIP status line format")
	}

	// Must start with exactly "SIP/2.0"
	if parts[0] != "SIP/2.0" {
		return nil, fmt.Errorf("not a SIP response - invalid protocol: %s", parts[0])
	}

	// Status code must be valid 3-digit number
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 699 {
		return nil, fmt.Errorf("invalid SIP status code: %s", parts[1])
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
			headerName := strings.ToLower(strings.TrimSpace(line[:colonIndex]))
			headerValue := strings.TrimSpace(line[colonIndex+1:])
			headers[headerName] = headerValue
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

// validateSIPResponse performs balanced validation to ensure it's really SIP
func validateSIPResponse(response *SIPResponse, port int) bool {
	// Check for obvious non-SIP protocols first
	responseText := response.RawResponse

	// Reject VNC responses
	if strings.Contains(responseText, "RFB ") ||
		strings.Contains(responseText, "FictusVNC") ||
		strings.Contains(responseText, "VNC ") {
		return false
	}

	// Reject HTTP responses
	if strings.HasPrefix(responseText, "HTTP/") {
		return false
	}

	// Reject SSH responses
	if strings.HasPrefix(responseText, "SSH-") {
		return false
	}

	// Reject FTP responses
	if strings.Contains(responseText, "220 ") && strings.Contains(responseText, "FTP") {
		return false
	}

	// For standard SIP ports (5060, 5061), be more lenient
	if port == 5060 || port == 5061 {
		// Just require it to be a valid SIP response format
		// Status code validation already done in parseSIPResponse
		return true
	}

	// For non-standard ports, require more validation
	// Check for SIP-specific patterns
	sipPatterns := []string{
		"sip:", "SIP/2.0", "z9hG4bK", "tag=", "branch=",
	}

	foundSipPatterns := 0
	responseTextLower := strings.ToLower(responseText)

	for _, pattern := range sipPatterns {
		if strings.Contains(responseTextLower, strings.ToLower(pattern)) {
			foundSipPatterns++
		}
	}

	// For non-standard ports, require at least 2 SIP patterns
	if foundSipPatterns < 2 {
		return false
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

// detectSIPVendor performs comprehensive vendor detection with balanced validation
func detectSIPVendor(conn net.Conn, timeout time.Duration, target string, port int) (*VendorInfo, *SIPResponse, error) {
	// Get source IP for SIP message construction
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sourceIP := localAddr.IP.String()

	var bestVendor *VendorInfo
	var sipResponse *SIPResponse

	// Method 1: OPTIONS probe
	optionsRequest := createOPTIONSRequest(target, sourceIP)
	response, err := utils.SendRecv(conn, []byte(optionsRequest), timeout)

	if err == nil && len(response) > 0 {
		// Parse and validate SIP response
		parsedResponse, parseErr := parseSIPResponse(string(response), port)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("not a valid SIP response: %v", parseErr)
		}

		// Additional SIP validation
		if !validateSIPResponse(parsedResponse, port) {
			return nil, nil, fmt.Errorf("response failed SIP validation")
		}

		sipResponse = parsedResponse

		// Analyze User-Agent/Server headers
		if vendor := analyzeUserAgent(parsedResponse); vendor != nil {
			bestVendor = vendor
		}
	}

	// Return if we have a valid SIP response
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
	 * Balanced SIP Server Detection
	 *
	 * This plugin performs balanced SIP detection:
	 * 1. Validates SIP response format (SIP/2.0 + valid status codes)
	 * 2. Rejects obvious non-SIP protocols (VNC, HTTP, SSH, FTP)
	 * 3. More lenient for standard SIP ports (5060, 5061)
	 * 4. More strict for non-standard ports
	 * 5. Detects real SIP services like "482 Merged Request"
	 *
	 * Will detect:
	 * - Real SIP services on port 5060/5061 (like 482 responses)
	 * - SIP services on non-standard ports (with extra validation)
	 *
	 * Will NOT detect:
	 * - VNC services (FictusVNC, RFB protocol)
	 * - HTTP services
	 * - SSH services
	 * - Other non-SIP protocols
	 */

	// Extract target host for SIP message construction
	targetHost := target.Host
	targetPort := int(target.Address.Port())
	if targetPort != 5060 {
		targetHost = fmt.Sprintf("%s:%d", target.Host, targetPort)
	}

	// Attempt vendor detection with balanced validation
	vendor, response, err := detectSIPVendor(conn, timeout, targetHost, targetPort)
	if err != nil {
		// If detection failed, do not fall back to avoid false positives
		return nil, nil
	}

	// Only return service if we have a validated SIP response
	if response == nil {
		return nil, nil
	}

	// Create service with detected vendor information
	return createServiceWithVendorInfo(target, vendor, response), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	// Prioritize standard SIP ports
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
