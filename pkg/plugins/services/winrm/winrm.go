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

// createWinRMIdentifyRequest creates a WS-Management Identify request
func createWinRMIdentifyRequest() string {
	return `POST /wsman HTTP/1.1
Host: %s
Content-Type: application/soap+xml;charset=UTF-8
Content-Length: %d
User-Agent: Microsoft WinRM Client
Connection: Keep-Alive

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
</soap:Envelope>`
}

// createWinRMEnumerateRequest creates a WS-Management Enumerate request for system info
func createWinRMEnumerateRequest() string {
	return `POST /wsman HTTP/1.1
Host: %s
Content-Type: application/soap+xml;charset=UTF-8
Content-Length: %d
User-Agent: Microsoft WinRM Client
Connection: Keep-Alive

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <soap:Header>
    <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</wsa:Action>
    <wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
    <wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">uuid:12345678-1234-1234-1234-123456789013</wsa:MessageID>
    <wsman:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem</wsman:ResourceURI>
  </soap:Header>
  <soap:Body>
    <wsen:Enumerate/>
  </soap:Body>
</soap:Envelope>`
}

// createHTTPRequest formats a SOAP request as HTTP
func createHTTPRequest(host string, soapBody string) []byte {
	contentLength := len(soapBody)
	request := fmt.Sprintf(soapBody, host, contentLength)
	return []byte(request)
}

// parseWinRMResponse extracts information from WinRM SOAP response
func parseWinRMResponse(response string) plugins.ServiceWinRM {
	result := plugins.ServiceWinRM{
		Product:    "winrm",
		Anonymous:  false,
		Vulnerable: false,
	}

	// Extract protocol version from response
	if strings.Contains(response, "HTTP/1.1 200") || strings.Contains(response, "HTTP/1.0 200") {
		result.Protocol = "HTTP"
	}

	// Extract WS-Management version
	wsmanVersionRegex := regexp.MustCompile(`ProductVersion[">]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	if matches := wsmanVersionRegex.FindStringSubmatch(response); len(matches) > 1 {
		result.WSManVersion = matches[1]
		result.Version = matches[1]
	}

	// Extract product vendor (Microsoft)
	if strings.Contains(response, "Microsoft Corporation") {
		result.Product = "microsoft winrm"
	}

	// Extract OS version information
	osVersionRegex := regexp.MustCompile(`ProductVendor[">]*Microsoft Corporation[^<]*<[^>]*>([^<]+)`)
	if matches := osVersionRegex.FindStringSubmatch(response); len(matches) > 1 {
		result.OSVersion = strings.TrimSpace(matches[1])
	}

	// Look for Windows version in various places
	windowsVersionRegex := regexp.MustCompile(`Windows[^<]*([0-9]+\.[0-9]+)`)
	if matches := windowsVersionRegex.FindStringSubmatch(response); len(matches) > 1 {
		if result.OSVersion == "" {
			result.OSVersion = "Windows " + matches[1]
		}
	}

	// Extract computer name
	computerNameRegex := regexp.MustCompile(`<wsmid:ComputerName[^>]*>([^<]+)</wsmid:ComputerName>`)
	if matches := computerNameRegex.FindStringSubmatch(response); len(matches) > 1 {
		result.ComputerName = matches[1]
	}

	// Extract domain information
	domainRegex := regexp.MustCompile(`<wsmid:Domain[^>]*>([^<]+)</wsmid:Domain>`)
	if matches := domainRegex.FindStringSubmatch(response); len(matches) > 1 {
		result.Domain = matches[1]
	}

	// Check for SOAP version
	if strings.Contains(response, "soap-envelope") {
		result.SOAPVersion = "1.2"
	} else if strings.Contains(response, "soap:Envelope") {
		result.SOAPVersion = "1.1"
	}

	// Extract authentication methods from headers
	authMethods := []string{}
	if strings.Contains(response, "WWW-Authenticate:") {
		authHeaderRegex := regexp.MustCompile(`WWW-Authenticate:\s*([^\r\n]+)`)
		if matches := authHeaderRegex.FindAllStringSubmatch(response, -1); len(matches) > 0 {
			for _, match := range matches {
				if len(match) > 1 {
					authMethod := strings.TrimSpace(match[1])
					if strings.Contains(authMethod, "Negotiate") {
						authMethods = append(authMethods, "Negotiate")
					}
					if strings.Contains(authMethod, "NTLM") {
						authMethods = append(authMethods, "NTLM")
					}
					if strings.Contains(authMethod, "Basic") {
						authMethods = append(authMethods, "Basic")
					}
					if strings.Contains(authMethod, "Digest") {
						authMethods = append(authMethods, "Digest")
					}
					if strings.Contains(authMethod, "Kerberos") {
						authMethods = append(authMethods, "Kerberos")
					}
				}
			}
		}
	}
	result.AuthMethods = authMethods

	// Check if anonymous access is allowed (no auth required)
	if strings.Contains(response, "<wsmid:Identify") && !strings.Contains(response, "401") && !strings.Contains(response, "Unauthorized") {
		result.Anonymous = true
		result.Vulnerable = true // Anonymous access is a security concern
	}

	// Extract max envelope size
	maxEnvelopeRegex := regexp.MustCompile(`MaxEnvelopeSize[">]*([0-9]+)`)
	if matches := maxEnvelopeRegex.FindStringSubmatch(response); len(matches) > 1 {
		if size, err := strconv.Atoi(matches[1]); err == nil {
			result.MaxEnvelope = size
		}
	}

	// Extract timeout information
	timeoutRegex := regexp.MustCompile(`Timeout[">]*PT([0-9]+)S`)
	if matches := timeoutRegex.FindStringSubmatch(response); len(matches) > 1 {
		if timeout, err := strconv.Atoi(matches[1]); err == nil {
			result.MaxTimeout = timeout
		}
	}

	// Check for PowerShell remoting indicators
	if strings.Contains(response, "PowerShell") || strings.Contains(response, "Microsoft.PowerShell") {
		result.PowerShell = true
	}

	// Check for remote shell capabilities
	if strings.Contains(response, "cmd") || strings.Contains(response, "shell") {
		result.RemoteShell = true
	}

	// Determine server type
	if strings.Contains(response, "Windows Server") {
		result.ServerType = "Windows Server"
	} else if strings.Contains(response, "Windows") {
		result.ServerType = "Windows Workstation"
	}

	// Build comprehensive product banner
	result.Product = "winrm"
	if result.WSManVersion != "" {
		result.Product = fmt.Sprintf("winrm %s", result.WSManVersion)
	}
	if result.OSVersion != "" {
		result.Product += fmt.Sprintf(" (%s)", result.OSVersion)
	}
	if result.Anonymous {
		result.Product += " [ANONYMOUS]"
	}
	if result.Vulnerable {
		result.Product += " [VULNERABLE]"
	}

	return result
}

// testWinRMEndpoints tests various WinRM endpoints
func testWinRMEndpoints(conn net.Conn, host string, timeout time.Duration) ([]string, string) {
	endpoints := []string{"/wsman", "/wsman/", "/WSMan", "/WSMan/"}
	var bestResponse string
	var foundEndpoints []string

	for _, endpoint := range endpoints {
		// Create identify request for this endpoint
		soapBody := strings.Replace(createWinRMIdentifyRequest(), "/wsman", endpoint, 1)
		request := createHTTPRequest(host, soapBody)

		response, err := utils.SendRecv(conn, request, timeout)
		if err == nil && len(response) > 0 {
			responseStr := string(response)
			if strings.Contains(responseStr, "200 OK") || strings.Contains(responseStr, "wsmid:Identify") {
				foundEndpoints = append(foundEndpoints, endpoint)
				if len(responseStr) > len(bestResponse) {
					bestResponse = responseStr
				}
			}
		}
	}

	return foundEndpoints, bestResponse
}

// checkWinRMVulnerabilities performs additional vulnerability checks
func checkWinRMVulnerabilities(conn net.Conn, host string, timeout time.Duration, result *plugins.ServiceWinRM) {
	// Test for anonymous enumeration
	enumerateRequest := createHTTPRequest(host, createWinRMEnumerateRequest())
	response, err := utils.SendRecv(conn, enumerateRequest, timeout)
	if err == nil && len(response) > 0 {
		responseStr := string(response)
		if strings.Contains(responseStr, "200 OK") && strings.Contains(responseStr, "Win32_OperatingSystem") {
			result.Vulnerable = true
			result.Anonymous = true
		}
	}

	// Check for weak authentication
	if len(result.AuthMethods) > 0 {
		for _, method := range result.AuthMethods {
			if method == "Basic" {
				result.Vulnerable = true // Basic auth over HTTP is vulnerable
				break
			}
		}
	}
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

	// Test WinRM endpoints
	endpoints, response := testWinRMEndpoints(conn, host, timeout)
	if len(endpoints) == 0 || response == "" {
		return nil, nil
	}

	// Parse the response
	result := parseWinRMResponse(response)
	result.Endpoints = endpoints

	// Set protocol based on port
	if port == 5986 {
		result.Protocol = "HTTPS"
		result.Encryption = "SSL/TLS"
	} else {
		result.Protocol = "HTTP"
		result.Encryption = "None"
	}

	// Perform additional vulnerability checks
	checkWinRMVulnerabilities(conn, host, timeout, &result)

	return plugins.CreateServiceFrom(target, result, port == 5986, "", plugins.TCP), nil
}

func (p *WinRMPlugin) Priority() int {
	return 850
}
