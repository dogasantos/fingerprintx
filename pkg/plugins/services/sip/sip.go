// Improved SIP plugin with enhanced protocol detection

package sip

import (
	"crypto/rand"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
	utils "github.com/vcore8/fingerprintx/pkg/plugins/pluginutils"
)

const SIP = "SIP"

type Plugin struct{}

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

// Method 1: Standard OPTIONS request
func createOPTIONSRequest(target string, sourceIP string, sourcePort int) string {
	callID := generateCallID(sourceIP)
	branch := generateBranch()

	request := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:%d;branch=%s\r\n", sourceIP, sourcePort, branch)
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

// Method 2: Simple OPTIONS (minimal headers)
func createSimpleOPTIONSRequest(target string, sourceIP string) string {
	callID := generateCallID(sourceIP)

	request := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s\r\n", sourceIP)
	request += fmt.Sprintf("From: sip:%s\r\n", sourceIP)
	request += fmt.Sprintf("To: sip:%s\r\n", target)
	request += fmt.Sprintf("Call-ID: %s\r\n", callID)
	request += "CSeq: 1 OPTIONS\r\n"
	request += "Content-Length: 0\r\n"
	request += "\r\n"

	return request
}

// Method 3: INVITE request
func createINVITERequest(target string, sourceIP string, sourcePort int) string {
	callID := generateCallID(sourceIP)
	branch := generateBranch()

	request := fmt.Sprintf("INVITE sip:test@%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:%d;branch=%s\r\n", sourceIP, sourcePort, branch)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:test@%s>\r\n", target)
	request += fmt.Sprintf("Call-ID: %s\r\n", callID)
	request += "CSeq: 1 INVITE\r\n"
	request += "Max-Forwards: 70\r\n"
	request += "User-Agent: Fingerprintx-SIP-Scanner\r\n"
	request += fmt.Sprintf("Contact: <sip:test@%s:%d>\r\n", sourceIP, sourcePort)
	request += "Content-Length: 0\r\n"
	request += "\r\n"

	return request
}

// Method 4: REGISTER request
func createREGISTERRequest(target string, sourceIP string, sourcePort int) string {
	callID := generateCallID(sourceIP)
	branch := generateBranch()

	request := fmt.Sprintf("REGISTER sip:%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:%d;branch=%s\r\n", sourceIP, sourcePort, branch)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:test@%s>\r\n", target)
	request += fmt.Sprintf("Call-ID: %s\r\n", callID)
	request += "CSeq: 1 REGISTER\r\n"
	request += "Max-Forwards: 70\r\n"
	request += "User-Agent: Fingerprintx-SIP-Scanner\r\n"
	request += fmt.Sprintf("Contact: <sip:test@%s:%d>\r\n", sourceIP, sourcePort)
	request += "Content-Length: 0\r\n"
	request += "\r\n"

	return request
}

// Method 5: Malformed request (to trigger error responses)
func createMalformedRequest(target string) string {
	return fmt.Sprintf("INVALID sip:%s SIP/2.0\r\n\r\n", target)
}

// Method 6: Basic UDP probe
func createBasicProbe() string {
	return "\r\n\r\n"
}

// parseSIPResponse parses a SIP response message with improved error handling
func parseSIPResponse(response string) (*SIPResponse, error) {
	if len(response) < 8 {
		return nil, fmt.Errorf("response too short")
	}

	// Check if it looks like SIP
	if !strings.HasPrefix(response, "SIP/2.0") {
		return nil, fmt.Errorf("not a SIP response")
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid response format")
	}

	// Parse status line
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid status line")
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code")
	}

	reasonPhrase := parts[2]

	// Parse headers
	headers := make(map[string]string)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break
		}

		colonIndex := strings.Index(line, ":")
		if colonIndex > 0 {
			headerName := strings.ToLower(strings.TrimSpace(line[:colonIndex]))
			headerValue := strings.TrimSpace(line[colonIndex+1:])
			headers[headerName] = headerValue
		}
	}

	return &SIPResponse{
		StatusCode:   statusCode,
		ReasonPhrase: reasonPhrase,
		Headers:      headers,
		RawResponse:  response,
	}, nil
}

// isSIPLikeResponse checks if response contains SIP-like content
func isSIPLikeResponse(response string) bool {
	sipIndicators := []string{
		"SIP/2.0",
		"Via:",
		"From:",
		"To:",
		"Call-ID:",
		"CSeq:",
		"User-Agent:",
		"Server:",
		"Contact:",
		"Allow:",
		"Content-Length:",
	}

	foundIndicators := 0
	responseLower := strings.ToLower(response)

	for _, indicator := range sipIndicators {
		if strings.Contains(responseLower, strings.ToLower(indicator)) {
			foundIndicators++
		}
	}

	// Require at least 3 SIP indicators for positive identification
	return foundIndicators >= 3
}

// extractDeviceBanner extracts device and version information into a banner string
func extractDeviceBanner(response *SIPResponse) string {
	// Try User-Agent header first
	if userAgent, exists := response.Headers["user-agent"]; exists {
		banner := parseDeviceFromHeader(userAgent)
		if banner != "" {
			return banner
		}
	}

	// Try Server header
	if server, exists := response.Headers["server"]; exists {
		banner := parseDeviceFromHeader(server)
		if banner != "" {
			return banner
		}
	}

	// Try Contact header (sometimes contains device info)
	if contact, exists := response.Headers["contact"]; exists {
		banner := parseDeviceFromHeader(contact)
		if banner != "" {
			return banner
		}
	}

	// Fallback: create generic banner
	return fmt.Sprintf("SIP Server (%d %s)", response.StatusCode, response.ReasonPhrase)
}

// parseDeviceFromHeader parses device information from SIP headers
func parseDeviceFromHeader(header string) string {
	patterns := []struct {
		regex  *regexp.Regexp
		format string
	}{
		// Asterisk patterns
		{regexp.MustCompile(`(?i)asterisk\s+pbx\s+(\d+\.\d+\.\d+)`), "Asterisk PBX %s"},
		{regexp.MustCompile(`(?i)asterisk\s+(\d+\.\d+\.\d+)`), "Asterisk %s"},
		{regexp.MustCompile(`(?i)asterisk`), "Asterisk PBX"},

		// FreeSWITCH patterns
		{regexp.MustCompile(`(?i)freeswitch-mod_sofia/(\d+\.\d+\.\d+)`), "FreeSWITCH %s"},
		{regexp.MustCompile(`(?i)freeswitch`), "FreeSWITCH"},

		// Cisco patterns
		{regexp.MustCompile(`(?i)cisco-cucm(\d+\.\d+)`), "Cisco CUCM %s"},
		{regexp.MustCompile(`(?i)cisco-sipgateway/ios-(\d+\.x)`), "Cisco SIP Gateway IOS %s"},
		{regexp.MustCompile(`(?i)csco/(\d+)`), "Cisco IP Phone %s"},
		{regexp.MustCompile(`(?i)cisco`), "Cisco SIP Device"},

		// Avaya patterns
		{regexp.MustCompile(`(?i)avaya\s+one-x\s+deskphone`), "Avaya One-X Deskphone"},
		{regexp.MustCompile(`(?i)avaya\s+cm/r(\d+x\.\d+\.\d+\.\d+)`), "Avaya Communication Manager %s"},
		{regexp.MustCompile(`(?i)avaya`), "Avaya Communication System"},

		// 3CX patterns
		{regexp.MustCompile(`(?i)3cx\s+phone\s+system\s+(\d+\.\d+\.\d+\.\d+)`), "3CX Phone System %s"},
		{regexp.MustCompile(`(?i)3cx`), "3CX Phone System"},

		// Microsoft patterns
		{regexp.MustCompile(`(?i)uccapi`), "Microsoft Skype for Business"},
		{regexp.MustCompile(`(?i)microsoft.*teams`), "Microsoft Teams"},

		// OpenSIPS/Kamailio patterns
		{regexp.MustCompile(`(?i)opensips\s*\((\d+\.\d+\.\d+)\)`), "OpenSIPS %s"},
		{regexp.MustCompile(`(?i)kamailio\s*\((\d+\.\d+\.\d+)\)`), "Kamailio %s"},

		// Hardware phone patterns
		{regexp.MustCompile(`(?i)grandstream\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)`), "Grandstream %s %s"},
		{regexp.MustCompile(`(?i)polycom.*soundpoint`), "Polycom SoundPoint IP"},
		{regexp.MustCompile(`(?i)yealink\s+sip-(\w+)`), "Yealink IP Phone %s"},
		{regexp.MustCompile(`(?i)snom(\d+)`), "Snom IP Phone %s"},

		// Software client patterns
		{regexp.MustCompile(`(?i)x-lite\s+(release\s+)?(\d+\w*)`), "CounterPath X-Lite %s"},
		{regexp.MustCompile(`(?i)linphone/(\d+\.\d+\.\d+)`), "Linphone %s"},
		{regexp.MustCompile(`(?i)zoiper\s+r(\d+)`), "Zoiper %s"},

		// Generic patterns
		{regexp.MustCompile(`(?i)(\w+)\s+(\d+\.\d+\.\d+)`), "%s %s"},
		{regexp.MustCompile(`(?i)(\w+)/(\d+\.\d+\.\d+)`), "%s %s"},
	}

	for _, pattern := range patterns {
		if matches := pattern.regex.FindStringSubmatch(header); matches != nil {
			if len(matches) == 2 {
				return fmt.Sprintf(pattern.format, matches[1])
			} else if len(matches) == 3 {
				return fmt.Sprintf(pattern.format, matches[1], matches[2])
			} else {
				return pattern.format
			}
		}
	}

	// Basic device type detection
	headerLower := strings.ToLower(header)
	if strings.Contains(headerLower, "phone") {
		return "IP Phone"
	}
	if strings.Contains(headerLower, "pbx") {
		return "PBX System"
	}
	if strings.Contains(headerLower, "gateway") {
		return "SIP Gateway"
	}

	return ""
}

// detectSIPService tries multiple methods to detect SIP with improved detection
func detectSIPService(conn net.Conn, timeout time.Duration, target string, targetPort int) (*SIPResponse, error) {
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sourceIP := localAddr.IP.String()
	sourcePort := localAddr.Port

	// List of methods to try in order of effectiveness
	methods := []struct {
		name    string
		request func() string
	}{
		{"OPTIONS", func() string { return createOPTIONSRequest(target, sourceIP, sourcePort) }},
		{"Simple OPTIONS", func() string { return createSimpleOPTIONSRequest(target, sourceIP) }},
		{"INVITE", func() string { return createINVITERequest(target, sourceIP, sourcePort) }},
		{"REGISTER", func() string { return createREGISTERRequest(target, sourceIP, sourcePort) }},
		{"Malformed", func() string { return createMalformedRequest(target) }},
		{"Basic Probe", func() string { return createBasicProbe() }},
	}

	// Try each method
	for _, method := range methods {
		request := method.request()
		response, err := utils.SendRecv(conn, []byte(request), timeout)

		if err == nil && len(response) > 0 {
			responseStr := string(response)

			// Try to parse as proper SIP response first
			if parsedResponse, parseErr := parseSIPResponse(responseStr); parseErr == nil {
				return parsedResponse, nil
			}

			// Check if it contains SIP-like content (fallback)
			if isSIPLikeResponse(responseStr) {
				// Create a minimal response object for SIP-like content
				return &SIPResponse{
					StatusCode:   200,
					ReasonPhrase: "OK",
					Headers:      make(map[string]string),
					RawResponse:  responseStr,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no SIP response received")
}

// createServiceWithBanner creates a service object with device banner
func createServiceWithBanner(target plugins.Target, response *SIPResponse) *plugins.Service {
	// Extract device banner
	deviceBanner := extractDeviceBanner(response)

	// Create ServiceSIP struct
	serviceSIP := plugins.ServiceSIP{
		// Basic SIP information
		StatusCode:   response.StatusCode,
		ReasonPhrase: response.ReasonPhrase,
		HeadersCount: len(response.Headers),

		// Device banner
		VendorName:        deviceBanner,
		VendorProduct:     deviceBanner,
		VendorConfidence:  85,
		VendorMethod:      "SIP Header Analysis",
		VendorDescription: fmt.Sprintf("Device identified from SIP headers: %s", deviceBanner),

		// Important SIP headers
		UserAgent: response.Headers["user-agent"],
		Server:    response.Headers["server"],
		Allow:     response.Headers["allow"],
		Supported: response.Headers["supported"],
		Contact:   response.Headers["contact"],

		// Protocol information
		StandardPort: 5060,
		SecurePort:   5061,
		Transport:    []string{"UDP", "TCP", "TLS"},
		Methods:      []string{"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"},

		// Detection metadata
		DetectionMethod: "SIP Protocol Detection",
		ResponseTime:    0,

		// Security features
		AuthenticationRequired: response.StatusCode == 401 || response.StatusCode == 407,
		AuthenticationMethods:  []string{},
		TLSSupported:           false,
		SecurityHeaders:        []string{},
		EncryptionSupported:    []string{},

		// Device fingerprinting
		DeviceType:      "",
		DeviceModel:     deviceBanner,
		FirmwareVersion: "",
		SupportedCodecs: []string{},
		HeaderOrder:     []string{},

		// Configuration analysis
		AllowedMethods:      []string{},
		SupportedExtensions: []string{},
		SecurityPolicies:    []string{},
		TransportSecurity:   []string{},
	}

	return plugins.CreateServiceFrom(target, serviceSIP, false, "", plugins.UDP)
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Extract target host and port
	targetHost := target.Address.Addr().String()
	targetPort := int(target.Address.Port())

	if targetHost == "" && target.Host != "" {
		targetHost = target.Host
	}

	if targetHost == "" {
		return nil, nil
	}

	// Create target string for SIP request
	sipTarget := targetHost
	if targetPort != 5060 {
		sipTarget = fmt.Sprintf("%s:%d", targetHost, targetPort)
	}

	// Attempt SIP detection with improved methods
	response, err := detectSIPService(conn, timeout, sipTarget, targetPort)
	if err != nil {
		return nil, nil
	}

	if response == nil {
		return nil, nil
	}

	// Create service with device banner
	return createServiceWithBanner(target, response), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
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
