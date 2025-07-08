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
	"encoding/hex"
	"fmt"
	"log"
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

// Windows version mapping based on build numbers
var windowsVersionMap = map[string]string{
	"10.0.14393": "Windows Server 2016 (version 1607)",
	"10.0.17763": "Windows Server 2019 (version 1809)",
	"10.0.20348": "Windows Server 2022",
	"10.0.19041": "Windows 10 (version 2004)",
	"10.0.19042": "Windows 10 (version 20H2)",
	"10.0.19043": "Windows 10 (version 21H1)",
	"10.0.19044": "Windows 10 (version 21H2)",
	"10.0.22000": "Windows 11",
	"6.3.9600":   "Windows Server 2012 R2",
	"6.2.9200":   "Windows Server 2012",
	"6.1.7601":   "Windows Server 2008 R2",
	"6.0.6002":   "Windows Server 2008",
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

// createAuthTriggerRequests creates various requests that should trigger NTLM authentication
func createAuthTriggerRequests(host string) []string {
	requests := []string{
		// SOAP request that requires authentication
		fmt.Sprintf(`POST /wsman HTTP/1.1
Host: %s
Content-Type: application/soap+xml;charset=UTF-8
Content-Length: 574
User-Agent: Microsoft WinRM Client
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <soap:Header>
    <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.dmtf.org/wbem/wsman/1/wsman/Identify</wsa:Action>
    <wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
    <wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:12345678-1234-1234-1234-123456789012</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsmid:Identify/>
  </soap:Body>
</soap:Envelope>`, host),

		// Simple GET that might trigger auth
		fmt.Sprintf(`GET /wsman HTTP/1.1
Host: %s
User-Agent: Microsoft WinRM Client
Connection: close

`, host),
	}

	return requests
}

// createNTLMType1Request creates an NTLM Type 1 message request with proper flags
func createNTLMType1Request(host string) string {
	// Create a proper NTLM Type 1 message with flags requesting target info and version
	ntlmType1 := make([]byte, 40)                               // Extended to include version info
	copy(ntlmType1[0:8], "NTLMSSP\x00")                         // Signature
	binary.LittleEndian.PutUint32(ntlmType1[8:12], 1)           // Type 1
	binary.LittleEndian.PutUint32(ntlmType1[12:16], 0x62088207) // Flags: Request target info, Unicode, OEM, Version
	// Domain and workstation fields (empty)
	binary.LittleEndian.PutUint16(ntlmType1[16:18], 0) // Domain length
	binary.LittleEndian.PutUint16(ntlmType1[18:20], 0) // Domain max length
	binary.LittleEndian.PutUint32(ntlmType1[20:24], 0) // Domain offset
	binary.LittleEndian.PutUint16(ntlmType1[24:26], 0) // Workstation length
	binary.LittleEndian.PutUint16(ntlmType1[26:28], 0) // Workstation max length
	binary.LittleEndian.PutUint32(ntlmType1[28:32], 0) // Workstation offset
	// Version info (8 bytes)
	ntlmType1[32] = 0x06                                  // Major version (Windows Vista/2008+)
	ntlmType1[33] = 0x01                                  // Minor version
	binary.LittleEndian.PutUint16(ntlmType1[34:36], 7601) // Build number
	ntlmType1[36] = 0x00                                  // Reserved
	ntlmType1[37] = 0x00                                  // Reserved
	ntlmType1[38] = 0x00                                  // Reserved
	ntlmType1[39] = 0x0F                                  // NTLM revision

	ntlmType1B64 := base64.StdEncoding.EncodeToString(ntlmType1)

	log.Printf("WINRM DEBUG: Sending NTLM Type 1 message: %s", ntlmType1B64)

	return fmt.Sprintf(`GET /wsman HTTP/1.1
Host: %s
Authorization: NTLM %s
User-Agent: Microsoft WinRM Client
Connection: close

`, host, ntlmType1B64)
}

// parseNTLMType2Response extracts comprehensive information from NTLM Type 2 response
func parseNTLMType2Response(response string) plugins.ServiceWinRM {
	result := plugins.ServiceWinRM{
		Product:    "winrm",
		Anonymous:  false,
		Vulnerable: false,
	}

	log.Printf("WINRM DEBUG: Analyzing NTLM response")

	// Look for NTLM Type 2 message in WWW-Authenticate header
	ntlmRegex := regexp.MustCompile(`WWW-Authenticate:\s*NTLM\s+([A-Za-z0-9+/=]+)`)
	matches := ntlmRegex.FindStringSubmatch(response)
	if len(matches) < 2 {
		log.Printf("WINRM DEBUG: No NTLM Type 2 message found in response")
		return result
	}

	log.Printf("WINRM DEBUG: Found NTLM Type 2 message: %s", matches[1])

	// Decode base64 NTLM message
	ntlmData, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		log.Printf("WINRM DEBUG: Failed to decode NTLM message: %v", err)
		return result
	}

	log.Printf("WINRM DEBUG: NTLM Type 2 length: %d", len(ntlmData))
	log.Printf("WINRM DEBUG: NTLM Type 2 hex: %s", hex.EncodeToString(ntlmData))

	if len(ntlmData) < 32 {
		log.Printf("WINRM DEBUG: NTLM message too short")
		return result
	}

	// Parse NTLM Type 2 message structure
	if len(ntlmData) >= 8 && string(ntlmData[0:8]) == "NTLMSSP\x00" {
		messageType := binary.LittleEndian.Uint32(ntlmData[8:12])
		log.Printf("WINRM DEBUG: NTLM message type: %d", messageType)

		if messageType == 2 { // Type 2 message
			log.Printf("WINRM DEBUG: Processing NTLM Type 2 message")

			// Extract target name (domain/computer name)
			if len(ntlmData) >= 20 {
				targetNameLen := binary.LittleEndian.Uint16(ntlmData[12:14])
				targetNameOffset := binary.LittleEndian.Uint32(ntlmData[16:20])

				log.Printf("WINRM DEBUG: Target name length: %d, offset: %d", targetNameLen, targetNameOffset)

				if targetNameOffset < uint32(len(ntlmData)) && targetNameLen > 0 {
					endOffset := targetNameOffset + uint32(targetNameLen)
					if endOffset <= uint32(len(ntlmData)) {
						targetName := utf16ToString(ntlmData[targetNameOffset:endOffset])
						log.Printf("WINRM DEBUG: Target name: %s", targetName)
						if targetName != "" {
							result.ComputerName = targetName
							result.Domain = targetName
						}
					}
				}
			}

			// Extract flags
			if len(ntlmData) >= 24 {
				flags := binary.LittleEndian.Uint32(ntlmData[20:24])
				log.Printf("WINRM DEBUG: NTLM flags: 0x%08x", flags)

				// Check if version info is present
				if flags&0x02000000 != 0 { // NTLMSSP_NEGOTIATE_VERSION
					log.Printf("WINRM DEBUG: Version information is present in NTLM message")
					result = extractNTLMVersion(ntlmData, result)
				}
			}

			// Extract target info (if present) - this contains detailed OS information
			if len(ntlmData) >= 48 {
				targetInfoLen := binary.LittleEndian.Uint16(ntlmData[40:42])
				targetInfoOffset := binary.LittleEndian.Uint32(ntlmData[44:48])

				log.Printf("WINRM DEBUG: Target info length: %d, offset: %d", targetInfoLen, targetInfoOffset)

				if targetInfoOffset < uint32(len(ntlmData)) && targetInfoLen > 0 {
					endOffset := targetInfoOffset + uint32(targetInfoLen)
					if endOffset <= uint32(len(ntlmData)) {
						targetInfo := ntlmData[targetInfoOffset:endOffset]
						log.Printf("WINRM DEBUG: Target info hex: %s", hex.EncodeToString(targetInfo))
						result = parseTargetInfo(targetInfo, result)
					}
				}
			}
		}
	}

	return result
}

// extractNTLMVersion extracts OS version from NTLM version field
func extractNTLMVersion(ntlmData []byte, result plugins.ServiceWinRM) plugins.ServiceWinRM {
	// NTLM version info is typically at offset 48-56 in Type 2 message
	if len(ntlmData) >= 56 {
		majorVersion := ntlmData[48]
		minorVersion := ntlmData[49]
		buildNumber := binary.LittleEndian.Uint16(ntlmData[50:52])

		log.Printf("WINRM DEBUG: NTLM Version - Major: %d, Minor: %d, Build: %d", majorVersion, minorVersion, buildNumber)

		// Build OS version string
		versionStr := fmt.Sprintf("%d.%d.%d", majorVersion, minorVersion, buildNumber)
		result.OSBuild = versionStr

		// Look up known Windows versions
		if osName, exists := windowsVersionMap[versionStr]; exists {
			result.OSVersion = osName
			log.Printf("WINRM DEBUG: Mapped OS version: %s", osName)
		} else {
			// Generic version based on major.minor
			if majorVersion == 10 && minorVersion == 0 {
				if buildNumber >= 20348 {
					result.OSVersion = "Windows Server 2022"
				} else if buildNumber >= 17763 {
					result.OSVersion = "Windows Server 2019"
				} else if buildNumber >= 14393 {
					result.OSVersion = "Windows Server 2016"
				} else {
					result.OSVersion = "Windows 10"
				}
			} else if majorVersion == 6 && minorVersion == 3 {
				result.OSVersion = "Windows Server 2012 R2"
			} else if majorVersion == 6 && minorVersion == 2 {
				result.OSVersion = "Windows Server 2012"
			} else if majorVersion == 6 && minorVersion == 1 {
				result.OSVersion = "Windows Server 2008 R2"
			} else {
				result.OSVersion = fmt.Sprintf("Windows %d.%d", majorVersion, minorVersion)
			}
			log.Printf("WINRM DEBUG: Determined OS version: %s", result.OSVersion)
		}

		// Extract release version for Windows 10/Server 2016+
		if majorVersion == 10 && minorVersion == 0 {
			if buildNumber == 14393 {
				result.OSRelease = "1607"
			} else if buildNumber == 17763 {
				result.OSRelease = "1809"
			} else if buildNumber == 19041 {
				result.OSRelease = "2004"
			} else if buildNumber == 19042 {
				result.OSRelease = "20H2"
			} else if buildNumber == 20348 {
				result.OSRelease = "21H2"
			}

			if result.OSRelease != "" {
				log.Printf("WINRM DEBUG: Determined OS release: %s", result.OSRelease)
			}
		}
	}

	return result
}

// parseTargetInfo extracts detailed OS and system information from NTLM target info
func parseTargetInfo(targetInfo []byte, result plugins.ServiceWinRM) plugins.ServiceWinRM {
	log.Printf("WINRM DEBUG: Parsing target info (%d bytes)", len(targetInfo))

	offset := 0

	for offset+4 <= len(targetInfo) {
		avId := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4])
		offset += 4

		log.Printf("WINRM DEBUG: AV pair - ID: %d, Length: %d", avId, avLen)

		if avLen == 0 {
			if avId == 0 { // End of list
				log.Printf("WINRM DEBUG: End of AV pairs")
				break
			}
			continue
		}

		if offset+int(avLen) > len(targetInfo) {
			log.Printf("WINRM DEBUG: AV pair extends beyond target info")
			break
		}

		value := targetInfo[offset : offset+int(avLen)]

		switch avId {
		case 1: // MsvAvNbComputerName - NetBIOS computer name
			result.NetBIOSName = utf16ToString(value)
			log.Printf("WINRM DEBUG: NetBIOS computer name: %s", result.NetBIOSName)
			if result.ComputerName == "" {
				result.ComputerName = result.NetBIOSName
			}
		case 2: // MsvAvNbDomainName - NetBIOS domain name
			result.NetBIOSDomain = utf16ToString(value)
			log.Printf("WINRM DEBUG: NetBIOS domain name: %s", result.NetBIOSDomain)
			if result.Domain == "" {
				result.Domain = result.NetBIOSDomain
			}
		case 3: // MsvAvDnsComputerName - DNS computer name
			result.DNSName = utf16ToString(value)
			log.Printf("WINRM DEBUG: DNS computer name: %s", result.DNSName)
		case 4: // MsvAvDnsDomainName - DNS domain name
			result.DNSDomain = utf16ToString(value)
			log.Printf("WINRM DEBUG: DNS domain name: %s", result.DNSDomain)
		case 5: // MsvAvDnsTreeName - DNS tree name
			result.TreeName = utf16ToString(value)
			log.Printf("WINRM DEBUG: DNS tree name: %s", result.TreeName)
		case 7: // MsvAvTimestamp - Timestamp
			if len(value) >= 8 {
				timestamp := binary.LittleEndian.Uint64(value)
				result.ServerTime = formatNTLMTimestamp(timestamp)
				log.Printf("WINRM DEBUG: Server timestamp: %s", result.ServerTime)
			}
		case 9: // MsvAvTargetName - Target name
			targetName := utf16ToString(value)
			log.Printf("WINRM DEBUG: Target name: %s", targetName)
			if targetName != "" && result.ComputerName == "" {
				result.ComputerName = targetName
			}
		}

		offset += int(avLen)

		if avId == 0 { // End of list
			break
		}
	}

	// Build FQDN if we have DNS name and domain
	if result.DNSName != "" && result.DNSDomain != "" {
		result.FQDN = fmt.Sprintf("%s.%s", result.DNSName, result.DNSDomain)
		log.Printf("WINRM DEBUG: Built FQDN: %s", result.FQDN)
	}

	// Determine server type from computer name patterns
	result = determineServerType(result)

	return result
}

// determineServerType determines server type from available information
func determineServerType(result plugins.ServiceWinRM) plugins.ServiceWinRM {
	log.Printf("WINRM DEBUG: Determining server type")

	// Analyze computer name patterns
	computerName := strings.ToUpper(result.ComputerName)
	log.Printf("WINRM DEBUG: Computer name (upper): %s", computerName)

	// Common Windows Server naming patterns
	if strings.Contains(computerName, "WIN-") {
		result.ServerType = "Windows Server"
		log.Printf("WINRM DEBUG: Detected Windows Server from WIN- prefix")
	}

	// Analyze domain patterns
	domain := strings.ToUpper(result.Domain)
	log.Printf("WINRM DEBUG: Domain (upper): %s", domain)
	if strings.Contains(domain, "WORKGROUP") {
		if result.ServerType == "" {
			result.ServerType = "Windows Workstation"
			log.Printf("WINRM DEBUG: Detected Windows Workstation from WORKGROUP")
		}
	}

	// Try to determine architecture (assume x64 for modern systems)
	if result.Architecture == "" {
		result.Architecture = "x64"
		log.Printf("WINRM DEBUG: Assumed x64 architecture")
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
			log.Printf("WINRM DEBUG: Found Microsoft-HTTPAPI version: %s", matches[1])
		}
	}

	// Extract protocol information
	if strings.Contains(response, "HTTP/1.1") {
		result.Protocol = "HTTP"
	}

	// Check for authentication methods
	authMethods := []string{}
	if strings.Contains(response, "WWW-Authenticate:") {
		log.Printf("WINRM DEBUG: Found WWW-Authenticate header")
		if strings.Contains(response, "NTLM") {
			authMethods = append(authMethods, "NTLM")
			log.Printf("WINRM DEBUG: NTLM authentication supported")
		}
		if strings.Contains(response, "Negotiate") {
			authMethods = append(authMethods, "Negotiate")
			log.Printf("WINRM DEBUG: Negotiate authentication supported")
		}
		if strings.Contains(response, "Basic") {
			authMethods = append(authMethods, "Basic")
			log.Printf("WINRM DEBUG: Basic authentication supported")
		}
	}
	result.AuthMethods = authMethods

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
			log.Printf("WINRM DEBUG: Found WinRM indicator: %s", indicator)
			return true
		}
	}

	return false
}

// tryAuthTriggerRequests attempts various requests to trigger NTLM authentication
func tryAuthTriggerRequests(conn net.Conn, host string, timeout time.Duration) (string, bool) {
	requests := createAuthTriggerRequests(host)

	for i, request := range requests {
		log.Printf("WINRM DEBUG: Trying auth trigger request %d", i+1)
		response, err := utils.SendRecv(conn, []byte(request), timeout)
		if err == nil && len(response) > 0 {
			responseStr := string(response)
			if strings.Contains(responseStr, "WWW-Authenticate") && strings.Contains(responseStr, "NTLM") {
				log.Printf("WINRM DEBUG: Auth trigger request %d succeeded - found NTLM", i+1)
				return responseStr, true
			}
		}
	}

	log.Printf("WINRM DEBUG: No auth trigger requests succeeded")
	return "", false
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

	log.Printf("WINRM DEBUG: Starting WinRM detection on %s", host)

	// First, try basic detection
	basicRequest := fmt.Sprintf(`GET /wsman HTTP/1.1
Host: %s
User-Agent: Microsoft WinRM Client
Connection: close

`, host)

	response, err := utils.SendRecv(conn, []byte(basicRequest), timeout)
	if err != nil {
		log.Printf("WINRM DEBUG: Basic request failed: %v", err)
		return nil, nil
	}

	responseStr := string(response)
	log.Printf("WINRM DEBUG: Basic response length: %d", len(responseStr))

	// Check if this looks like WinRM
	if !isWinRMResponse(responseStr) {
		log.Printf("WINRM DEBUG: Response does not look like WinRM")
		return nil, nil
	}

	log.Printf("WINRM DEBUG: Confirmed WinRM service")

	// Parse basic response
	result := parseWinRMResponse(responseStr)

	// Try to trigger NTLM authentication with various requests
	authResponse, hasAuth := tryAuthTriggerRequests(conn, host, timeout)
	if hasAuth {
		log.Printf("WINRM DEBUG: Successfully triggered NTLM authentication")

		// Now send NTLM Type 1 to get detailed OS info
		ntlmRequest := createNTLMType1Request(host)
		ntlmResponse, err := utils.SendRecv(conn, []byte(ntlmRequest), timeout)
		if err == nil {
			ntlmResponseStr := string(ntlmResponse)
			log.Printf("WINRM DEBUG: NTLM response length: %d", len(ntlmResponseStr))
			ntlmInfo := parseNTLMType2Response(ntlmResponseStr)

			// Merge NTLM information
			if ntlmInfo.ComputerName != "" {
				result.ComputerName = ntlmInfo.ComputerName
				log.Printf("WINRM DEBUG: Set computer name: %s", result.ComputerName)
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
			if ntlmInfo.OSBuild != "" {
				result.OSBuild = ntlmInfo.OSBuild
			}
			if ntlmInfo.OSRelease != "" {
				result.OSRelease = ntlmInfo.OSRelease
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
		} else {
			log.Printf("WINRM DEBUG: NTLM Type 1 request failed: %v", err)
		}

		// Also parse auth methods from the trigger response
		triggerResult := parseWinRMResponse(authResponse)
		if len(triggerResult.AuthMethods) > 0 {
			result.AuthMethods = triggerResult.AuthMethods
		}
	} else {
		log.Printf("WINRM DEBUG: Could not trigger NTLM authentication")
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
		if result.OSRelease != "" {
			productParts = append(productParts, fmt.Sprintf("(%s)", result.OSVersion))
		} else {
			productParts = append(productParts, fmt.Sprintf("(%s)", result.OSVersion))
		}
	}
	if result.OSBuild != "" {
		productParts = append(productParts, fmt.Sprintf("[%s]", result.OSBuild))
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

	log.Printf("WINRM DEBUG: Final result - Product: %s", result.Product)
	log.Printf("WINRM DEBUG: Computer: %s, Domain: %s, OS: %s, Build: %s", result.ComputerName, result.Domain, result.OSVersion, result.OSBuild)

	return plugins.CreateServiceFrom(target, result, port == 5986, "", plugins.TCP), nil
}

func (p *WinRMPlugin) Priority() int {
	return 900 // Higher priority than HTTP to catch WinRM before generic HTTP
}
