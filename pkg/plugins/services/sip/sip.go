// SIP plugin with device banner extraction

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

// createINVITERequest creates a SIP INVITE request (alternative method)
func createINVITERequest(target string, sourceIP string) string {
	callID := generateCallID(sourceIP)
	branch := generateBranch()

	request := fmt.Sprintf("INVITE sip:test@%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:5060;branch=%s\r\n", sourceIP, branch)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:test@%s>\r\n", target)
	request += fmt.Sprintf("Call-ID: %s\r\n", callID)
	request += "CSeq: 1 INVITE\r\n"
	request += "Max-Forwards: 70\r\n"
	request += "User-Agent: Fingerprintx-SIP-Scanner\r\n"
	request += "Contact: <sip:test@" + sourceIP + ":5060>\r\n"
	request += "Content-Length: 0\r\n"
	request += "\r\n"

	return request
}

// parseSIPResponse parses a SIP response message
func parseSIPResponse(response string) (*SIPResponse, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("response too short to be SIP")
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid SIP response format")
	}

	// Parse status line
	statusLine := lines[0]
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 || parts[0] != "SIP/2.0" {
		return nil, fmt.Errorf("not a SIP response")
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 699 {
		return nil, fmt.Errorf("invalid SIP status code")
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

// extractDeviceBanner extracts device and version information into a banner string
func extractDeviceBanner(response *SIPResponse) string {
	// Try User-Agent header first (most common)
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

	// Fallback: create generic banner from status
	return fmt.Sprintf("SIP Server (%d %s)", response.StatusCode, response.ReasonPhrase)
}

// parseDeviceFromHeader parses device information from SIP headers
func parseDeviceFromHeader(header string) string {
	// Device patterns with version extraction
	patterns := []struct {
		regex  *regexp.Regexp
		format string
	}{
		// Asterisk patterns
		{
			regex:  regexp.MustCompile(`(?i)asterisk\s+pbx\s+(\d+\.\d+\.\d+)`),
			format: "Asterisk PBX %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)asterisk\s+(\d+\.\d+\.\d+)`),
			format: "Asterisk %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)asterisk`),
			format: "Asterisk PBX",
		},

		// FreeSWITCH patterns
		{
			regex:  regexp.MustCompile(`(?i)freeswitch-mod_sofia/(\d+\.\d+\.\d+)`),
			format: "FreeSWITCH %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)freeswitch`),
			format: "FreeSWITCH",
		},

		// Cisco patterns
		{
			regex:  regexp.MustCompile(`(?i)cisco-cucm(\d+\.\d+)`),
			format: "Cisco CUCM %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)cisco-sipgateway/ios-(\d+\.x)`),
			format: "Cisco SIP Gateway IOS %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)csco/(\d+)`),
			format: "Cisco IP Phone %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)cisco`),
			format: "Cisco SIP Device",
		},

		// Avaya patterns
		{
			regex:  regexp.MustCompile(`(?i)avaya\s+one-x\s+deskphone`),
			format: "Avaya One-X Deskphone",
		},
		{
			regex:  regexp.MustCompile(`(?i)avaya\s+cm/r(\d+x\.\d+\.\d+\.\d+)`),
			format: "Avaya Communication Manager %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)avaya`),
			format: "Avaya Communication System",
		},

		// 3CX patterns
		{
			regex:  regexp.MustCompile(`(?i)3cx\s+phone\s+system\s+(\d+\.\d+\.\d+\.\d+)`),
			format: "3CX Phone System %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)3cx`),
			format: "3CX Phone System",
		},

		// Microsoft patterns
		{
			regex:  regexp.MustCompile(`(?i)uccapi`),
			format: "Microsoft Skype for Business",
		},
		{
			regex:  regexp.MustCompile(`(?i)microsoft.*teams`),
			format: "Microsoft Teams",
		},

		// OpenSIPS/Kamailio patterns
		{
			regex:  regexp.MustCompile(`(?i)opensips\s*\((\d+\.\d+\.\d+)\)`),
			format: "OpenSIPS %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)kamailio\s*\((\d+\.\d+\.\d+)\)`),
			format: "Kamailio %s",
		},

		// Hardware phone patterns
		{
			regex:  regexp.MustCompile(`(?i)grandstream\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)`),
			format: "Grandstream %s %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)polycom.*soundpoint`),
			format: "Polycom SoundPoint IP",
		},
		{
			regex:  regexp.MustCompile(`(?i)yealink\s+sip-(\w+)`),
			format: "Yealink IP Phone %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)snom(\d+)`),
			format: "Snom IP Phone %s",
		},

		// Software client patterns
		{
			regex:  regexp.MustCompile(`(?i)x-lite\s+(release\s+)?(\d+\w*)`),
			format: "CounterPath X-Lite %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)linphone/(\d+\.\d+\.\d+)`),
			format: "Linphone %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)zoiper\s+r(\d+)`),
			format: "Zoiper %s",
		},

		// Generic patterns
		{
			regex:  regexp.MustCompile(`(?i)(\w+)\s+(\d+\.\d+\.\d+)`),
			format: "%s %s",
		},
		{
			regex:  regexp.MustCompile(`(?i)(\w+)/(\d+\.\d+\.\d+)`),
			format: "%s %s",
		},
	}

	// Try each pattern
	for _, pattern := range patterns {
		if matches := pattern.regex.FindStringSubmatch(header); matches != nil {
			if len(matches) == 2 {
				// Single capture group (version)
				return fmt.Sprintf(pattern.format, matches[1])
			} else if len(matches) == 3 {
				// Two capture groups (model + version)
				return fmt.Sprintf(pattern.format, matches[1], matches[2])
			} else {
				// No capture groups
				return pattern.format
			}
		}
	}

	// If no pattern matches, try to extract basic info
	if strings.Contains(strings.ToLower(header), "phone") {
		return "IP Phone"
	}
	if strings.Contains(strings.ToLower(header), "pbx") {
		return "PBX System"
	}
	if strings.Contains(strings.ToLower(header), "gateway") {
		return "SIP Gateway"
	}

	return ""
}

// detectSIPService performs SIP detection with multiple methods
func detectSIPService(conn net.Conn, timeout time.Duration, target string) (*SIPResponse, error) {
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sourceIP := localAddr.IP.String()

	// Method 1: Try OPTIONS request
	optionsRequest := createOPTIONSRequest(target, sourceIP)
	response, err := utils.SendRecv(conn, []byte(optionsRequest), timeout)

	if err == nil && len(response) > 0 {
		if parsedResponse, parseErr := parseSIPResponse(string(response)); parseErr == nil {
			return parsedResponse, nil
		}
	}

	// Method 2: Try INVITE request (some servers respond better to INVITE)
	inviteRequest := createINVITERequest(target, sourceIP)
	response, err = utils.SendRecv(conn, []byte(inviteRequest), timeout)

	if err == nil && len(response) > 0 {
		if parsedResponse, parseErr := parseSIPResponse(string(response)); parseErr == nil {
			return parsedResponse, nil
		}
	}

	return nil, fmt.Errorf("no valid SIP response received")
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
		VendorName:        deviceBanner, // Use banner as vendor name for now
		VendorProduct:     deviceBanner,
		VendorConfidence:  85,
		VendorMethod:      "SIP Header Analysis",
		VendorDescription: fmt.Sprintf("Device identified from SIP headers: %s", deviceBanner),

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
		DetectionMethod: "SIP Protocol",
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

	return plugins.CreateServiceFrom(target, serviceSIP, false, "", plugins.UDP)
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Extract target host
	targetHost := target.Address.Addr().String()
	targetPort := int(target.Address.Port())

	if targetHost == "" && target.Host != "" {
		targetHost = target.Host
	}

	if targetHost == "" {
		return nil, fmt.Errorf("no target host found")
	}

	// Create target string for SIP request
	sipTarget := targetHost
	if targetPort != 5060 {
		sipTarget = fmt.Sprintf("%s:%d", targetHost, targetPort)
	}

	// Attempt SIP detection
	response, err := detectSIPService(conn, timeout, sipTarget)
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
