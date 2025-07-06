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

	// Avaya patterns
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
		Pattern: regexp.MustCompile(`(?i)avaya\s+cm/r(\d+x\.\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Avaya",
			Product:     "Communication Manager",
			Confidence:  95,
			Description: "Avaya Communication Manager",
		},
		Description: "Avaya Communication Manager",
	},
	{
		Pattern: regexp.MustCompile(`(?i)avaya`),
		VendorInfo: VendorInfo{
			Name:        "Avaya",
			Product:     "Unknown",
			Confidence:  85,
			Description: "Avaya Communication System",
		},
		Description: "Generic Avaya identification",
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

	// Microsoft patterns
	{
		Pattern: regexp.MustCompile(`(?i)uccapi`),
		VendorInfo: VendorInfo{
			Name:        "Microsoft",
			Product:     "Skype for Business",
			Confidence:  90,
			Description: "Microsoft Skype for Business",
		},
		Description: "Microsoft Skype for Business",
	},
	{
		Pattern: regexp.MustCompile(`(?i)microsoft.*teams`),
		VendorInfo: VendorInfo{
			Name:        "Microsoft",
			Product:     "Teams",
			Confidence:  90,
			Description: "Microsoft Teams",
		},
		Description: "Microsoft Teams",
	},

	// OpenSIPS/Kamailio patterns
	{
		Pattern: regexp.MustCompile(`(?i)opensips\s*\((\d+\.\d+\.\d+)\)`),
		VendorInfo: VendorInfo{
			Name:        "OpenSIPS",
			Product:     "OpenSIPS",
			Confidence:  95,
			Description: "OpenSIPS SIP Server",
		},
		Description: "OpenSIPS with version",
	},
	{
		Pattern: regexp.MustCompile(`(?i)kamailio\s*\((\d+\.\d+\.\d+)\)`),
		VendorInfo: VendorInfo{
			Name:        "Kamailio",
			Product:     "Kamailio",
			Confidence:  95,
			Description: "Kamailio SIP Server",
		},
		Description: "Kamailio with version",
	},

	// Hardware phone patterns
	{
		Pattern: regexp.MustCompile(`(?i)grandstream\s+(\w+)\s+(\d+\.\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Grandstream",
			Product:     "IP Phone",
			Confidence:  95,
			Description: "Grandstream IP Phone",
		},
		Description: "Grandstream IP Phone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)polycom.*soundpoint`),
		VendorInfo: VendorInfo{
			Name:        "Polycom",
			Product:     "SoundPoint IP",
			Confidence:  95,
			Description: "Polycom SoundPoint IP Phone",
		},
		Description: "Polycom SoundPoint IP Phone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)yealink\s+sip-(\w+)`),
		VendorInfo: VendorInfo{
			Name:        "Yealink",
			Product:     "IP Phone",
			Confidence:  95,
			Description: "Yealink IP Phone",
		},
		Description: "Yealink IP Phone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)snom(\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Snom",
			Product:     "IP Phone",
			Confidence:  95,
			Description: "Snom IP Phone",
		},
		Description: "Snom IP Phone",
	},

	// Software client patterns
	{
		Pattern: regexp.MustCompile(`(?i)x-lite\s+(release\s+)?(\d+\w*)`),
		VendorInfo: VendorInfo{
			Name:        "CounterPath",
			Product:     "X-Lite",
			Confidence:  95,
			Description: "CounterPath X-Lite Softphone",
		},
		Description: "X-Lite Softphone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)linphone/(\d+\.\d+\.\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Belledonne",
			Product:     "Linphone",
			Confidence:  95,
			Description: "Linphone Softphone",
		},
		Description: "Linphone Softphone",
	},
	{
		Pattern: regexp.MustCompile(`(?i)zoiper\s+r(\d+)`),
		VendorInfo: VendorInfo{
			Name:        "Zoiper",
			Product:     "Zoiper",
			Confidence:  95,
			Description: "Zoiper Softphone",
		},
		Description: "Zoiper Softphone",
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

// createINVITERequest creates a SIP INVITE request for testing
func createINVITERequest(target string, sourceIP string) string {
	callID := generateCallID(sourceIP)
	branch := generateBranch()

	// Simple SDP body
	sdpBody := "v=0\r\n"
	sdpBody += fmt.Sprintf("o=test 123456 654321 IN IP4 %s\r\n", sourceIP)
	sdpBody += "s=Test Session\r\n"
	sdpBody += fmt.Sprintf("c=IN IP4 %s\r\n", sourceIP)
	sdpBody += "t=0 0\r\n"
	sdpBody += "m=audio 5004 RTP/AVP 0 8\r\n"
	sdpBody += "a=rtpmap:0 PCMU/8000\r\n"
	sdpBody += "a=rtpmap:8 PCMA/8000\r\n"

	request := fmt.Sprintf("INVITE sip:test@%s SIP/2.0\r\n", target)
	request += fmt.Sprintf("Via: SIP/2.0/UDP %s:5060;branch=%s\r\n", sourceIP, branch)
	request += fmt.Sprintf("From: <sip:test@%s>;tag=test\r\n", sourceIP)
	request += fmt.Sprintf("To: <sip:test@%s>\r\n", target)
	request += fmt.Sprintf("Call-ID: %s\r\n", callID)
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

// parseSIPResponse parses a SIP response message
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

// analyzeResponsePatterns analyzes response patterns for vendor identification
func analyzeResponsePatterns(response *SIPResponse) *VendorInfo {
	// Analyze Allow header for method support patterns
	if allow, exists := response.Headers["allow"]; exists {
		methods := strings.Split(allow, ",")
		methodCount := len(methods)

		// Different implementations support different method sets
		if methodCount > 15 {
			return &VendorInfo{
				Name:        "Unknown",
				Product:     "Full-Featured PBX",
				Confidence:  40,
				Method:      "Method Support Analysis",
				Description: "Comprehensive SIP method support suggests full PBX",
			}
		} else if methodCount < 8 {
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

// analyzeTimingBehavior analyzes response timing for vendor identification
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

// detectSIPVendor performs comprehensive vendor detection
func detectSIPVendor(conn net.Conn, timeout time.Duration, target string) (*VendorInfo, *SIPResponse, error) {
	// Get source IP for SIP message construction
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sourceIP := localAddr.IP.String()

	var bestVendor *VendorInfo
	var sipResponse *SIPResponse

	// Method 1: OPTIONS probe (most reliable for capability detection)
	optionsRequest := createOPTIONSRequest(target, sourceIP)
	start := time.Now()
	response, err := utils.SendRecv(conn, []byte(optionsRequest), timeout)
	responseTime := time.Since(start)

	if err == nil && len(response) > 0 {
		parsedResponse, parseErr := parseSIPResponse(string(response))
		if parseErr == nil && parsedResponse.StatusCode >= 200 && parsedResponse.StatusCode < 600 {
			sipResponse = parsedResponse

			// Analyze User-Agent/Server headers (highest confidence)
			if vendor := analyzeUserAgent(parsedResponse); vendor != nil {
				bestVendor = vendor
			}

			// Analyze response patterns if no vendor found
			if bestVendor == nil {
				if vendor := analyzeResponsePatterns(parsedResponse); vendor != nil {
					bestVendor = vendor
				}
			}

			// Analyze timing if no other method worked
			if bestVendor == nil {
				if vendor := analyzeTimingBehavior(responseTime); vendor != nil {
					bestVendor = vendor
				}
			}
		}
	}

	// Method 2: INVITE probe (if OPTIONS failed or no vendor detected)
	if bestVendor == nil || bestVendor.Confidence < 70 {
		inviteRequest := createINVITERequest(target, sourceIP)
		start = time.Now()
		response, err = utils.SendRecv(conn, []byte(inviteRequest), timeout)
		responseTime = time.Since(start)

		if err == nil && len(response) > 0 {
			parsedResponse, parseErr := parseSIPResponse(string(response))
			if parseErr == nil && parsedResponse.StatusCode >= 200 && parsedResponse.StatusCode < 600 {
				if sipResponse == nil {
					sipResponse = parsedResponse
				}

				// Analyze headers
				if vendor := analyzeUserAgent(parsedResponse); vendor != nil {
					if bestVendor == nil || vendor.Confidence > bestVendor.Confidence {
						bestVendor = vendor
					}
				}

				// Analyze patterns
				if bestVendor == nil {
					if vendor := analyzeResponsePatterns(parsedResponse); vendor != nil {
						bestVendor = vendor
					}
				}

				// Analyze timing
				if bestVendor == nil {
					if vendor := analyzeTimingBehavior(responseTime); vendor != nil {
						bestVendor = vendor
					}
				}
			}
		}
	}

	return bestVendor, sipResponse, nil
}

// createServiceWithVendorInfo creates a service object with vendor information
func createServiceWithVendorInfo(target plugins.Target, vendor *VendorInfo, response *SIPResponse) *plugins.Service {
	serviceName := SIP
	if vendor != nil {
		serviceName = fmt.Sprintf("%s (%s %s)", SIP, vendor.Name, vendor.Product)
		if vendor.Version != "" {
			serviceName = fmt.Sprintf("%s (%s %s %s)", SIP, vendor.Name, vendor.Product, vendor.Version)
		}
	}

	service := &plugins.Service{
		Name:     serviceName,
		Protocol: plugins.UDP, // SIP commonly uses UDP, but can also use TCP
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

	// Add SIP response information
	if response != nil {
		service.Details["sip_response"] = map[string]interface{}{
			"status_code":   response.StatusCode,
			"reason_phrase": response.ReasonPhrase,
			"headers_count": len(response.Headers),
		}

		// Add important headers
		importantHeaders := []string{"user-agent", "server", "allow", "supported", "contact"}
		headers := make(map[string]string)
		for _, header := range importantHeaders {
			if value, exists := response.Headers[header]; exists {
				headers[header] = value
			}
		}
		if len(headers) > 0 {
			service.Details["sip_headers"] = headers
		}
	}

	// Add protocol information
	service.Details["protocol_info"] = map[string]interface{}{
		"standard_port": 5060,
		"secure_port":   5061,
		"transport":     []string{"UDP", "TCP", "TLS"},
		"methods":       []string{"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"},
	}

	return service
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * Comprehensive SIP Server Detection and Vendor Identification
	 *
	 * This plugin performs multi-stage SIP detection and vendor identification:
	 * 1. OPTIONS probe for capability discovery and vendor identification
	 * 2. INVITE probe for detailed analysis (if needed)
	 * 3. User-Agent/Server header analysis for precise vendor identification
	 * 4. Response pattern analysis for implementation characteristics
	 * 5. Timing behavior analysis for additional fingerprinting
	 *
	 * Supported vendor detection:
	 * - Asterisk PBX (Open Source)
	 * - FreeSWITCH (Telephony Platform)
	 * - Cisco CUCM/SIP Gateway/IP Phones
	 * - Avaya Communication Manager/Phones
	 * - 3CX Phone System
	 * - Microsoft Skype for Business/Teams
	 * - OpenSIPS/Kamailio (SIP Servers)
	 * - Hardware phones (Grandstream, Polycom, Yealink, Snom)
	 * - Software clients (X-Lite, Linphone, Zoiper)
	 */

	// Extract target host for SIP message construction
	targetHost := target.Host
	if target.Port != 5060 {
		targetHost = fmt.Sprintf("%s:%d", target.Host, target.Port)
	}

	// Attempt vendor detection
	vendor, response, err := detectSIPVendor(conn, timeout, targetHost)
	if err != nil {
		// If vendor detection failed, try basic SIP detection
		optionsRequest := createOPTIONSRequest(targetHost, "127.0.0.1")
		sipResponse, sendErr := utils.SendRecv(conn, []byte(optionsRequest), timeout)
		if sendErr != nil {
			return nil, sendErr
		}

		if len(sipResponse) < 10 {
			return nil, nil // Not a SIP server
		}

		// Check if response looks like SIP
		responseStr := string(sipResponse)
		if !strings.HasPrefix(responseStr, "SIP/2.0") {
			return nil, nil
		}

		// Parse basic response
		parsedResponse, parseErr := parseSIPResponse(responseStr)
		if parseErr != nil {
			return nil, nil
		}

		// Valid SIP response codes
		if parsedResponse.StatusCode >= 200 && parsedResponse.StatusCode < 600 {
			return createServiceWithVendorInfo(target, nil, parsedResponse), nil
		}

		return nil, nil
	}

	// Create service with detected vendor information
	return createServiceWithVendorInfo(target, vendor, response), nil
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
