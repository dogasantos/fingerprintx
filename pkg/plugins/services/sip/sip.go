// Fixed SIP plugin with proper target host extraction

package sip

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
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

// parseSIPResponse parses a SIP response message with debug output
func parseSIPResponse(response string, port int) (*SIPResponse, error) {
	log.Printf("DEBUG: Parsing SIP response (length: %d)", len(response))
	log.Printf("DEBUG: Raw response: %q", response)

	if len(response) < 12 { // Minimum SIP response: "SIP/2.0 200"
		log.Printf("DEBUG: Response too short to be SIP (length: %d)", len(response))
		return nil, fmt.Errorf("response too short to be SIP")
	}

	lines := strings.Split(response, "\r\n")
	if len(lines) < 1 {
		log.Printf("DEBUG: Invalid SIP response format - no lines")
		return nil, fmt.Errorf("invalid SIP response format")
	}

	// Parse status line
	statusLine := lines[0]
	log.Printf("DEBUG: Status line: %q", statusLine)

	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 3 {
		log.Printf("DEBUG: Invalid status line format - parts: %v", parts)
		return nil, fmt.Errorf("invalid SIP status line format")
	}

	// Must start with exactly "SIP/2.0"
	if parts[0] != "SIP/2.0" {
		log.Printf("DEBUG: Not a SIP response - protocol: %q", parts[0])
		return nil, fmt.Errorf("not a SIP response - invalid protocol: %s", parts[0])
	}

	// Status code must be valid 3-digit number
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 699 {
		log.Printf("DEBUG: Invalid status code: %q (error: %v)", parts[1], err)
		return nil, fmt.Errorf("invalid SIP status code: %s", parts[1])
	}

	reasonPhrase := parts[2]
	log.Printf("DEBUG: Parsed status: %d %s", statusCode, reasonPhrase)

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
			log.Printf("DEBUG: Header: %s = %s", headerName, headerValue)
		}
	}

	// Extract body
	var body string
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\r\n")
		log.Printf("DEBUG: Body length: %d", len(body))
	}

	log.Printf("DEBUG: Successfully parsed SIP response with %d headers", len(headers))

	return &SIPResponse{
		StatusCode:   statusCode,
		ReasonPhrase: reasonPhrase,
		Headers:      headers,
		Body:         body,
		RawResponse:  response,
	}, nil
}

// validateSIPResponse performs validation with debug output
func validateSIPResponse(response *SIPResponse, port int) bool {
	log.Printf("DEBUG: Validating SIP response for port %d", port)

	responseText := response.RawResponse

	// Check for obvious non-SIP protocols first
	if strings.Contains(responseText, "RFB ") ||
		strings.Contains(responseText, "FictusVNC") ||
		strings.Contains(responseText, "VNC ") {
		log.Printf("DEBUG: Rejected as VNC protocol")
		return false
	}

	if strings.HasPrefix(responseText, "HTTP/") {
		log.Printf("DEBUG: Rejected as HTTP protocol")
		return false
	}

	if strings.HasPrefix(responseText, "SSH-") {
		log.Printf("DEBUG: Rejected as SSH protocol")
		return false
	}

	if strings.Contains(responseText, "220 ") && strings.Contains(responseText, "FTP") {
		log.Printf("DEBUG: Rejected as FTP protocol")
		return false
	}

	// For standard SIP ports (5060, 5061), be more lenient
	if port == 5060 || port == 5061 {
		log.Printf("DEBUG: Standard SIP port - accepting response")
		return true
	}

	// For non-standard ports, require more validation
	sipPatterns := []string{
		"sip:", "SIP/2.0", "z9hG4bK", "tag=", "branch=",
	}

	foundSipPatterns := 0
	responseTextLower := strings.ToLower(responseText)

	for _, pattern := range sipPatterns {
		if strings.Contains(responseTextLower, strings.ToLower(pattern)) {
			foundSipPatterns++
			log.Printf("DEBUG: Found SIP pattern: %s", pattern)
		}
	}

	log.Printf("DEBUG: Found %d SIP patterns (need 2 for non-standard ports)", foundSipPatterns)

	// For non-standard ports, require at least 2 SIP patterns
	if foundSipPatterns < 2 {
		log.Printf("DEBUG: Insufficient SIP patterns for non-standard port")
		return false
	}

	log.Printf("DEBUG: SIP validation passed")
	return true
}

// detectSIPVendor performs detection with extensive debug output
func detectSIPVendor(conn net.Conn, timeout time.Duration, target string, port int) (*SIPResponse, error) {
	log.Printf("DEBUG: Starting SIP detection for %s:%d", target, port)

	// Get source IP for SIP message construction
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sourceIP := localAddr.IP.String()
	log.Printf("DEBUG: Source IP: %s", sourceIP)

	var sipResponse *SIPResponse

	// Method 1: OPTIONS probe
	optionsRequest := createOPTIONSRequest(target, sourceIP)
	log.Printf("DEBUG: Sending OPTIONS request:")
	log.Printf("DEBUG: Request: %q", optionsRequest)

	response, err := utils.SendRecv(conn, []byte(optionsRequest), timeout)
	log.Printf("DEBUG: SendRecv result - error: %v, response length: %d", err, len(response))

	if err != nil {
		log.Printf("DEBUG: SendRecv failed: %v", err)
		return nil, fmt.Errorf("SendRecv failed: %v", err)
	}

	if len(response) == 0 {
		log.Printf("DEBUG: Empty response received")
		return nil, fmt.Errorf("empty response received")
	}

	log.Printf("DEBUG: Raw response received: %q", string(response))

	// Parse and validate SIP response
	parsedResponse, parseErr := parseSIPResponse(string(response), port)
	if parseErr != nil {
		log.Printf("DEBUG: Parse failed: %v", parseErr)
		return nil, fmt.Errorf("not a valid SIP response: %v", parseErr)
	}

	log.Printf("DEBUG: Parse successful")

	// Additional SIP validation
	if !validateSIPResponse(parsedResponse, port) {
		log.Printf("DEBUG: Validation failed")
		return nil, fmt.Errorf("response failed SIP validation")
	}

	log.Printf("DEBUG: Validation successful")
	sipResponse = parsedResponse

	log.Printf("DEBUG: SIP detection successful - Status: %d %s", sipResponse.StatusCode, sipResponse.ReasonPhrase)
	return sipResponse, nil
}

// createServiceWithVendorInfo creates a service object with debug output
func createServiceWithVendorInfo(target plugins.Target, response *SIPResponse) *plugins.Service {
	log.Printf("DEBUG: Creating service with status %d %s", response.StatusCode, response.ReasonPhrase)

	// Create ServiceSIP struct with basic information
	serviceSIP := plugins.ServiceSIP{
		// Vendor information
		VendorName:        "",
		VendorProduct:     "",
		VendorVersion:     "",
		VendorConfidence:  0,
		VendorMethod:      "",
		VendorDescription: "",

		// SIP response information
		StatusCode:   response.StatusCode,
		ReasonPhrase: response.ReasonPhrase,
		HeadersCount: len(response.Headers),

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

	log.Printf("DEBUG: Service created successfully")
	return plugins.CreateServiceFrom(target, serviceSIP, false, "", plugins.UDP)
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// FIXED: Proper target host extraction for netip.AddrPort
	targetHost := target.Address.Addr().String()
	targetPort := int(target.Address.Port())

	// Fallback: use target.Host if available and targetHost is empty
	if targetHost == "" && target.Host != "" {
		targetHost = target.Host
	}

	log.Printf("DEBUG: SIP plugin starting for %s:%d", targetHost, targetPort)
	log.Printf("DEBUG: Target: %s, Port: %d", targetHost, targetPort)

	// Ensure we have a valid target host
	if targetHost == "" {
		log.Printf("DEBUG: No target host found")
		return nil, fmt.Errorf("no target host found")
	}

	// Create target string for SIP request
	sipTarget := targetHost
	if targetPort != 5060 {
		sipTarget = fmt.Sprintf("%s:%d", targetHost, targetPort)
	}

	// Attempt detection with fixed target
	response, err := detectSIPVendor(conn, timeout, sipTarget, targetPort)
	if err != nil {
		log.Printf("DEBUG: Detection failed: %v", err)
		return nil, nil
	}

	// Only return service if we have a validated SIP response
	if response == nil {
		log.Printf("DEBUG: No valid SIP response")
		return nil, nil
	}

	log.Printf("DEBUG: Creating service result")
	// Create service with detected information
	return createServiceWithVendorInfo(target, response), nil
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
