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

package winrm

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type WinRMPlugin struct{}

const WINRM = "winrm"

func init() {
	plugins.RegisterPlugin(&WinRMPlugin{})
}

// getPortFromConnection extracts port number from connection
func getPortFromConnection(conn net.Conn) uint16 {
	addr := conn.RemoteAddr().String()
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		portStr := parts[len(parts)-1]
		if port, err := strconv.Atoi(portStr); err == nil {
			return uint16(port)
		}
	}
	return 0
}

// createBasicWinRMRequest creates a basic HTTP request to test WinRM
func createBasicWinRMRequest(host string) string {
	return fmt.Sprintf(`GET /wsman HTTP/1.1
Host: %s
User-Agent: Microsoft WinRM Client
Connection: close

`, host)
}

// createNTLMType1Request creates an NTLM Type 1 message request
func createNTLMType1Request(host string) string {
	// NTLM Type 1 message with flags for requesting target info
	ntlmType1 := "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKADkAAAAA"

	return fmt.Sprintf(`GET /wsman HTTP/1.1
Host: %s
Authorization: NTLM %s
User-Agent: Microsoft WinRM Client
Connection: close

`, host, ntlmType1)
}

// parseNTLMType2Response extracts comprehensive information from NTLM Type 2 response
func parseNTLMType2Response(response string) plugins.ServiceWinRM {
	result := plugins.ServiceWinRM{
		Product:    "winrm",
		Anonymous:  false,
		Vulnerable: false,
	}

	// Look for NTLM Type 2 message in WWW-Authenticate header
	ntlmRegex := regexp.MustCompile(`WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]+)`)
	matches := ntlmRegex.FindStringSubmatch(response)
	if len(matches) < 2 {
		return result
	}

	// Decode base64 NTLM message
	ntlmData, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil || len(ntlmData) < 32 {
		return result
	}

	// Parse NTLM Type 2 message structure
	if len(ntlmData) >= 8 && string(ntlmData[0:8]) == "NTLMSSP\x00" {
		messageType := binary.LittleEndian.Uint32(ntlmData[8:12])
		if messageType == 2 { // Type 2 message
			// Extract target name (domain/computer name)
			if len(ntlmData) >= 20 {
				targetNameLen := binary.LittleEndian.Uint16(ntlmData[12:14])
				targetNameOffset := binary.LittleEndian.Uint32(ntlmData[16:20])

				if targetNameOffset < uint32(len(ntlmData)) && targetNameLen > 0 {
					endOffset := targetNameOffset + uint32(targetNameLen)
					if endOffset <= uint32(len(ntlmData)) {
						targetName := utf16ToString(ntlmData[targetNameOffset:endOffset])
						if targetName != "" {
							result.ComputerName = targetName
							result.Domain = targetName
						}
					}
				}
			}

			// Extract flags for OS version detection
			if len(ntlmData) >= 24 {
				flags := binary.LittleEndian.Uint32(ntlmData[20:24])
				result = analyzeNTLMFlags(flags, result)
			}

			// Extract target info (if present) - this contains detailed OS information
			if len(ntlmData) >= 48 {
				targetInfoLen := binary.LittleEndian.Uint16(ntlmData[40:42])
				targetInfoOffset := binary.LittleEndian.Uint32(ntlmData[44:48])

				if targetInfoOffset < uint32(len(ntlmData)) && targetInfoLen > 0 {
					endOffset := targetInfoOffset + uint32(targetInfoLen)
					if endOffset <= uint32(len(ntlmData)) {
						targetInfo := ntlmData[targetInfoOffset:endOffset]
						result = parseTargetInfo(targetInfo, result)
					}
				}
			}
		}
	}

	return result
}

// analyzeNTLMFlags extracts OS information from NTLM flags
func analyzeNTLMFlags(flags uint32, result plugins.ServiceWinRM) plugins.ServiceWinRM {
	// NTLM flags can indicate certain OS capabilities
	if flags&0x00800000 != 0 { // NTLMSSP_NEGOTIATE_VERSION
		// Version information is present
	}

	if flags&0x00200000 != 0 { // NTLMSSP_NEGOTIATE_TARGET_INFO
		// Target info is present (good for detailed OS info)
	}

	return result
}

// parseTargetInfo extracts detailed OS and system information from NTLM target info
func parseTargetInfo(targetInfo []byte, result plugins.ServiceWinRM) plugins.ServiceWinRM {
	offset := 0

	for offset+4 <= len(targetInfo) {
		avId := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])
		offset += 4

		if avLen == 0 {
			if avId == 0 { // End of list
				break
			}
			continue
		}

		if offset+int(avLen) > len(targetInfo) {
			break
		}

		value := targetInfo[offset : offset+int(avLen)]

		switch avId {
		case 1: // MsvAvNbComputerName - NetBIOS computer name
			result.NetBIOSName = utf16ToString(value)
			if result.ComputerName == "" {
				result.ComputerName = result.NetBIOSName
			}
		case 2: // MsvAvNbDomainName - NetBIOS domain name
			result.NetBIOSDomain = utf16ToString(value)
			if result.Domain == "" {
				result.Domain = result.NetBIOSDomain
			}
		case 3: // MsvAvDnsComputerName - DNS computer name
			result.DNSName = utf16ToString(value)
		case 4: // MsvAvDnsDomainName - DNS domain name
			result.DNSDomain = utf16ToString(value)
		case 5: // MsvAvDnsTreeName - DNS tree name
			result.TreeName = utf16ToString(value)
		case 6: // MsvAvFlags - Flags
			if len(value) >= 4 {
				flags := binary.LittleEndian.Uint32(value)
				result = analyzeTargetFlags(flags, result)
			}
		case 7: // MsvAvTimestamp - Timestamp
			if len(value) >= 8 {
				timestamp := binary.LittleEndian.Uint64(value)
				result.ServerTime = formatNTLMTimestamp(timestamp)
			}
		case 9: // MsvAvTargetName - Target name
			targetName := utf16ToString(value)
			if targetName != "" && result.ComputerName == "" {
				result.ComputerName = targetName
			}
		case 10: // MsvAvChannelBindings - Channel bindings
			// Could extract channel binding info if needed
		}

		offset += int(avLen)

		if avId == 0 { // End of list
			break
		}
	}

	// Build FQDN if we have DNS name and domain
	if result.DNSName != "" && result.DNSDomain != "" {
		result.FQDN = fmt.Sprintf("%s.%s", result.DNSName, result.DNSDomain)
	}

	// Determine OS version from computer name and other indicators
	result = determineOSVersion(result)

	return result
}

// analyzeTargetFlags extracts information from target flags
func analyzeTargetFlags(flags uint32, result plugins.ServiceWinRM) plugins.ServiceWinRM {
	// Target flags can indicate various capabilities
	if flags&0x00000001 != 0 { // Server
		result.ServerType = "Windows Server"
	}

	if flags&0x00000002 != 0 { // Domain Controller
		result.ServerType = "Domain Controller"
	}

	return result
}

// determineOSVersion attempts to determine Windows version from available information
func determineOSVersion(result plugins.ServiceWinRM) plugins.ServiceWinRM {
	// Analyze computer name patterns
	computerName := strings.ToUpper(result.ComputerName)

	// Common Windows Server naming patterns
	if strings.Contains(computerName, "WIN-") {
		result.ServerType = "Windows Server"
		// Default assumption for WIN- prefix
		if result.OSVersion == "" {
			result.OSVersion = "Windows Server"
		}
	}

	// Analyze domain patterns
	domain := strings.ToUpper(result.Domain)
	if strings.Contains(domain, "WORKGROUP") {
		if result.ServerType == "" {
			result.ServerType = "Windows Workstation"
		}
	}

	// Try to determine architecture (assume x64 for modern systems)
	if result.Architecture == "" {
		result.Architecture = "x64"
	}

	return result
}

// formatNTLMTimestamp converts NTLM timestamp to readable format
func formatNTLMTimestamp(timestamp uint64) string {
	// NTLM timestamp is 100-nanosecond intervals since January 1, 1601
	const ntlmEpoch = 116444736000000000 // 100-nanosecond intervals between 1601 and 1970

	if timestamp == 0 {
		return ""
	}

	// Convert to Unix timestamp
	unixTimestamp := int64((timestamp - ntlmEpoch) / 10000000)
	t := time.Unix(unixTimestamp, 0)

	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// utf16ToString converts UTF-16 bytes to string
func utf16ToString(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}

	var result []rune
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			char := binary.LittleEndian.Uint16(data[i : i+2])
			if char != 0 {
				result = append(result, rune(char))
			}
		}
	}

	return string(result)
}

// parseWinRMResponse analyzes WinRM response and extracts information
func parseWinRMResponse(response string) plugins.ServiceWinRM {
	result := plugins.ServiceWinRM{
		Product:    "winrm",
		Anonymous:  false,
		Vulnerable: false,
	}

	// Check for Microsoft-HTTPAPI server header (strong WinRM indicator)
	if strings.Contains(response, "Microsoft-HTTPAPI") {
		serverRegex := regexp.MustCompile(`Server:\s*Microsoft-HTTPAPI/([0-9.]+)`)
		if matches := serverRegex.FindStringSubmatch(response); len(matches) > 1 {
			result.Version = matches[1]
			result.Product = fmt.Sprintf("winrm (Microsoft-HTTPAPI/%s)", matches[1])
		}
	}

	// Extract protocol information
	if strings.Contains(response, "HTTP/1.1") {
		result.Protocol = "HTTP"
	} else if strings.Contains(response, "HTTP/1.0") {
		result.Protocol = "HTTP"
	}

	// Check for authentication methods
	authMethods := []string{}
	if strings.Contains(response, "WWW-Authenticate:") {
		if strings.Contains(response, "NTLM") {
			authMethods = append(authMethods, "NTLM")
		}
		if strings.Contains(response, "Negotiate") {
			authMethods = append(authMethods, "Negotiate")
		}
		if strings.Contains(response, "Basic") {
			authMethods = append(authMethods, "Basic")
		}
		if strings.Contains(response, "Digest") {
			authMethods = append(authMethods, "Digest")
		}
	}
	result.AuthMethods = authMethods

	// Check response codes
	if strings.Contains(response, "401 Unauthorized") {
		// Normal for WinRM - requires authentication
	} else if strings.Contains(response, "404 Not Found") {
		// Also normal for WinRM when accessing wrong endpoint
	} else if strings.Contains(response, "200 OK") {
		// Might indicate anonymous access
		result.Anonymous = true
		result.Vulnerable = true
	}

	// Check for weak authentication over HTTP
	if result.Protocol == "HTTP" && len(authMethods) > 0 {
		for _, method := range authMethods {
			if method == "Basic" {
				result.Vulnerable = true
				break
			}
		}
	}

	return result
}

// isWinRMResponse checks if response indicates WinRM service
func isWinRMResponse(response string) bool {
	// Strong indicators of WinRM
	indicators := []string{
		"Microsoft-HTTPAPI",
		"WinRM",
		"WSMan",
		"wsman",
	}

	for _, indicator := range indicators {
		if strings.Contains(response, indicator) {
			return true
		}
	}

	// Check for typical WinRM response patterns
	if (strings.Contains(response, "401 Unauthorized") || strings.Contains(response, "404 Not Found")) &&
		strings.Contains(response, "NTLM") {
		return true
	}

	return false
}

// tryAlternativeEndpoints tests additional WinRM endpoints for more information
func tryAlternativeEndpoints(conn net.Conn, host string, timeout time.Duration) plugins.ServiceWinRM {
	result := plugins.ServiceWinRM{}

	// Try different endpoints that might reveal more information
	endpoints := []string{
		"/wsman",
		"/wsman/",
		"/WSMan",
		"/WSMan/",
		"/wsman/SubscriptionManager/WEC",
		"/wsman/SubscriptionManager",
	}

	for _, endpoint := range endpoints {
		request := fmt.Sprintf(`GET %s HTTP/1.1
Host: %s
User-Agent: Microsoft WinRM Client
Connection: close

`, endpoint, host)

		response, err := utils.SendRecv(conn, []byte(request), timeout)
		if err == nil && len(response) > 0 {
			responseStr := string(response)
			if strings.Contains(responseStr, "200 OK") {
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		}
	}

	return result
}

func (p *WinRMPlugin) PortPriority(port uint16) bool {
	return port == 5985 || port == 5986
}

func (p *WinRMPlugin) Name() string {
	return WINRM
}

func (p *WinRMPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *WinRMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	port := getPortFromConnection(conn)
	if port != 5985 && port != 5986 {
		return nil, nil
	}

	host := target.Host
	if port != 80 && port != 443 {
		host = fmt.Sprintf("%s:%d", target.Host, port)
	}

	// First, try a basic request to /wsman
	basicRequest := createBasicWinRMRequest(host)
	response, err := utils.SendRecv(conn, []byte(basicRequest), timeout)
	if err != nil {
		return nil, nil
	}

	responseStr := string(response)

	// Check if this looks like WinRM
	if !isWinRMResponse(responseStr) {
		return nil, nil
	}

	// Parse basic response
	result := parseWinRMResponse(responseStr)

	// If we see NTLM authentication, try to get detailed OS info
	if strings.Contains(responseStr, "NTLM") {
		ntlmRequest := createNTLMType1Request(host)
		ntlmResponse, err := utils.SendRecv(conn, []byte(ntlmRequest), timeout)
		if err == nil {
			ntlmResponseStr := string(ntlmResponse)
			ntlmInfo := parseNTLMType2Response(ntlmResponseStr)

			// Merge NTLM information with comprehensive OS details
			if ntlmInfo.ComputerName != "" {
				result.ComputerName = ntlmInfo.ComputerName
			}
			if ntlmInfo.Domain != "" {
				result.Domain = ntlmInfo.Domain
			}
			if ntlmInfo.NetBIOSName != "" {
				result.NetBIOSName = ntlmInfo.NetBIOSName
			}
			if ntlmInfo.NetBIOSDomain != "" {
				result.NetBIOSDomain = ntlmInfo.NetBIOSDomain
			}
			if ntlmInfo.DNSName != "" {
				result.DNSName = ntlmInfo.DNSName
			}
			if ntlmInfo.DNSDomain != "" {
				result.DNSDomain = ntlmInfo.DNSDomain
			}
			if ntlmInfo.FQDN != "" {
				result.FQDN = ntlmInfo.FQDN
			}
			if ntlmInfo.OSVersion != "" {
				result.OSVersion = ntlmInfo.OSVersion
			}
			if ntlmInfo.ServerType != "" {
				result.ServerType = ntlmInfo.ServerType
			}
			if ntlmInfo.Architecture != "" {
				result.Architecture = ntlmInfo.Architecture
			}
			if ntlmInfo.ServerTime != "" {
				result.ServerTime = ntlmInfo.ServerTime
			}
		}
	}

	// Try alternative endpoints for additional information
	endpointInfo := tryAlternativeEndpoints(conn, host, timeout)
	if len(endpointInfo.Endpoints) > 0 {
		result.Endpoints = endpointInfo.Endpoints
	}

	// Set protocol based on port
	if port == 5986 {
		result.Protocol = "HTTPS"
		result.Encryption = "SSL/TLS"
	} else {
		result.Protocol = "HTTP"
		result.Encryption = "None"
	}

	// Build comprehensive product banner
	productParts := []string{"winrm"}
	if result.Version != "" {
		productParts = append(productParts, fmt.Sprintf("(Microsoft-HTTPAPI/%s)", result.Version))
	}
	if result.OSVersion != "" {
		productParts = append(productParts, fmt.Sprintf("(%s)", result.OSVersion))
	}
	if result.ComputerName != "" {
		productParts = append(productParts, fmt.Sprintf("[%s]", result.ComputerName))
	}
	if result.Anonymous {
		productParts = append(productParts, "[ANONYMOUS]")
	}
	if result.Vulnerable {
		productParts = append(productParts, "[VULNERABLE]")
	}

	result.Product = strings.Join(productParts, " ")

	return plugins.CreateServiceFrom(target, result, port == 5986, "", plugins.TCP), nil
}

func (p *WinRMPlugin) Priority() int {
	return 900 // Higher priority than HTTP to catch WinRM before generic HTTP
}
