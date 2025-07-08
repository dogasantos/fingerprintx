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

package winbox

import (
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

type WinboxPlugin struct{}

const WINBOX = "winbox"

func init() {
	plugins.RegisterPlugin(&WinboxPlugin{})
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

// createIndexRequest creates a simple HTTP-like request for the index file
func createIndexRequest() []byte {
	request := "GET /index HTTP/1.1\r\n"
	request += "Host: router\r\n"
	request += "User-Agent: fingerprintx\r\n"
	request += "Connection: close\r\n\r\n"
	return []byte(request)
}

// createListRequest creates a request for the list file (like Shodan uses)
func createListRequest() []byte {
	request := "GET /list HTTP/1.1\r\n"
	request += "Host: router\r\n"
	request += "User-Agent: fingerprintx\r\n"
	request += "Connection: close\r\n\r\n"
	return []byte(request)
}

// createWinboxListRequest creates a Winbox protocol message to read the list file
func createWinboxListRequest() []byte {
	// Based on Tenable research - Winbox message to system binary 2 (mproxy), handler 2
	packet := make([]byte, 32)

	// Winbox header structure (6 bytes)
	packet[0] = 0x00                                   // Chunk offset
	packet[1] = 0x01                                   // Message type
	binary.LittleEndian.PutUint16(packet[2:4], 32)     // Message length
	binary.LittleEndian.PutUint16(packet[4:6], 0x4D32) // Magic bytes "M2"

	// Simple payload requesting system info
	packet[6] = 0x02 // Binary ID (mproxy)
	packet[7] = 0x02 // Handler ID
	packet[8] = 0x00 // Session ID (new session)
	packet[9] = 0x00
	packet[10] = 0x00
	packet[11] = 0x00

	// Add some padding/data
	for i := 12; i < 32; i++ {
		packet[i] = 0x00
	}

	return packet
}

// isValidWinboxHTTPResponse checks if HTTP response is actually from RouterOS/Winbox
func isValidWinboxHTTPResponse(response []byte) bool {
	if len(response) < 20 {
		return false
	}

	responseStr := strings.ToLower(string(response))

	// Must be HTTP response
	if !strings.HasPrefix(responseStr, "http/") {
		return false
	}

	// Must contain specific RouterOS/MikroTik indicators
	requiredIndicators := []string{"routeros", "mikrotik"}
	hasRequired := false
	for _, indicator := range requiredIndicators {
		if strings.Contains(responseStr, indicator) {
			hasRequired = true
			break
		}
	}

	if !hasRequired {
		return false
	}

	// Additional validation - should contain RouterOS-specific content
	routerosIndicators := []string{
		"routerboard", "winbox", "webfig", "board-name",
		"architecture", "cpu-count", "cpu-frequency",
	}

	indicatorCount := 0
	for _, indicator := range routerosIndicators {
		if strings.Contains(responseStr, indicator) {
			indicatorCount++
		}
	}

	// Must have at least 2 RouterOS-specific indicators to be confident
	return indicatorCount >= 2
}

// isValidWinboxProtocolResponse checks if response is valid Winbox protocol
func isValidWinboxProtocolResponse(response []byte) bool {
	if len(response) < 6 {
		return false
	}

	// Look for Winbox magic bytes at proper positions
	for i := 0; i <= len(response)-6; i++ {
		// Check for Winbox header structure
		if i+6 <= len(response) {
			magic := binary.LittleEndian.Uint16(response[i+4 : i+6])

			// Check for known Winbox magic values
			if magic == 0x4D32 || magic == 0x324D { // "M2" or "2M"
				// Validate message length field
				if i+4 <= len(response) {
					msgLen := binary.LittleEndian.Uint16(response[i+2 : i+4])

					// Message length should be reasonable and consistent
					if msgLen >= 6 && msgLen <= 65535 {
						// Additional validation - check if this looks like proper Winbox structure
						chunkOffset := response[i]
						msgType := response[i+1]

						// Chunk offset should be reasonable (0-255)
						// Message type should be reasonable (1-255, not 0)
						if msgType > 0 && msgType < 255 {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// parseWinboxResponse analyzes response and extracts RouterOS information
func parseWinboxResponse(response []byte, isHTTP bool) (map[string]any, string) {
	info := make(map[string]any)
	responseStr := string(response)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))

	if isHTTP {
		info["Method"] = "HTTP_Request"

		// Extract RouterOS version with strict patterns
		versionPatterns := []string{
			`RouterOS\s+v?([\d\.]+(?:\.\d+)?)`,
			`routeros[:\s]+v?([\d\.]+(?:\.\d+)?)`,
			`([\d]+\.[\d]+\.[\d]+)`, // Generic version pattern
		}

		var version string
		for _, pattern := range versionPatterns {
			re := regexp.MustCompile(`(?i)` + pattern)
			if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
				version = matches[1]
				break
			}
		}

		// Extract board/model information with strict patterns
		boardPatterns := []string{
			`board-name[:\s]*([^\r\n,;]+)`,
			`routerboard[:\s]*([^\r\n,;]+)`,
			`model[:\s]*([^\r\n,;]+)`,
		}

		var board string
		for _, pattern := range boardPatterns {
			re := regexp.MustCompile(`(?i)` + pattern)
			if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
				board = strings.TrimSpace(matches[1])
				// Clean up common artifacts
				board = strings.Trim(board, `"'`)
				if board != "" {
					break
				}
			}
		}

		// Extract architecture
		archRe := regexp.MustCompile(`(?i)architecture[:\s]*([^\r\n,;]+)`)
		if matches := archRe.FindStringSubmatch(responseStr); len(matches) > 1 {
			arch := strings.TrimSpace(matches[1])
			arch = strings.Trim(arch, `"'`)
			if arch != "" {
				info["Architecture"] = arch
			}
		}

		// Extract build information
		buildRe := regexp.MustCompile(`(?i)build[:\s]+([\w\d\.]+)`)
		if matches := buildRe.FindStringSubmatch(responseStr); len(matches) > 1 {
			info["Build"] = matches[1]
		}

		if version != "" {
			info["RouterOS_Version"] = version
		}
		if board != "" {
			info["Board_Model"] = board
		}

		info["Vendor"] = "MikroTik"

	} else {
		// Parse Winbox protocol response
		info["Method"] = "Winbox_Protocol"

		// Find and parse Winbox header
		for i := 0; i <= len(response)-6; i++ {
			magic := binary.LittleEndian.Uint16(response[i+4 : i+6])
			if magic == 0x4D32 || magic == 0x324D {
				info["Winbox_Magic"] = fmt.Sprintf("0x%04X", magic)

				chunkOffset := response[i]
				msgType := response[i+1]
				msgLen := binary.LittleEndian.Uint16(response[i+2 : i+4])

				info["Chunk_Offset"] = fmt.Sprintf("%d", chunkOffset)
				info["Message_Type"] = fmt.Sprintf("%d", msgType)
				info["Message_Length"] = fmt.Sprintf("%d", msgLen)

				// Try to extract any RouterOS-specific data from payload
				if i+6 < len(response) {
					payload := response[i+6:]
					payloadStr := string(payload)

					// Look for RouterOS version in payload
					versionRe := regexp.MustCompile(`(?i)routeros[:\s]*v?([\d\.]+)`)
					if matches := versionRe.FindStringSubmatch(payloadStr); len(matches) > 1 {
						info["RouterOS_Version"] = matches[1]
					}
				}
				break
			}
		}

		info["Vendor"] = "MikroTik"
	}

	// Create product banner
	productBanner := "winbox MikroTik RouterOS"

	if version, exists := info["RouterOS_Version"]; exists {
		productBanner = fmt.Sprintf("winbox MikroTik RouterOS %s", version)
	}

	if board, exists := info["Board_Model"]; exists {
		if version, versionExists := info["RouterOS_Version"]; versionExists {
			productBanner = fmt.Sprintf("winbox MikroTik %s RouterOS %s", board, version)
		} else {
			productBanner = fmt.Sprintf("winbox MikroTik %s", board)
		}
	}

	if build, exists := info["Build"]; exists {
		productBanner += fmt.Sprintf(" (build %s)", build)
	}

	return info, productBanner
}

func (p *WinboxPlugin) PortPriority(port uint16) bool {
	// Winbox typically runs on port 8291
	return port == 8291
}

func (p *WinboxPlugin) Name() string {
	return WINBOX
}

func (p *WinboxPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *WinboxPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Verify we're running on the correct port
	port := getPortFromConnection(conn)
	if port != 8291 {
		return nil, nil // Only run on Winbox port 8291
	}

	log.Printf("WINBOX DEBUG: Starting Winbox detection for %s", conn.RemoteAddr().String())

	// Try Method 1: Index file request
	indexRequest := createIndexRequest()
	log.Printf("WINBOX DEBUG: Trying index request (%d bytes): %s", len(indexRequest), hex.EncodeToString(indexRequest))

	response, err := utils.SendRecv(conn, indexRequest, timeout)
	if err == nil && len(response) > 0 {
		log.Printf("WINBOX DEBUG: Index response (%d bytes): %s", len(response), hex.EncodeToString(response))
		log.Printf("WINBOX DEBUG: Index response ASCII: %q", string(response))

		if isValidWinboxHTTPResponse(response) {
			log.Printf("WINBOX DEBUG: Index response validated as Winbox")
			infoMap, productBanner := parseWinboxResponse(response, true)
			winboxInfo := fmt.Sprintf("%s", infoMap)
			payload := plugins.ServiceWinbox{
				Info:    winboxInfo,
				Product: productBanner,
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		} else {
			log.Printf("WINBOX DEBUG: Index response failed validation")
		}
	} else {
		log.Printf("WINBOX DEBUG: Index request failed: %v", err)
	}

	// Try Method 2: List file request (like Shodan)
	listRequest := createListRequest()
	log.Printf("WINBOX DEBUG: Trying list request (%d bytes): %s", len(listRequest), hex.EncodeToString(listRequest))

	response, err = utils.SendRecv(conn, listRequest, timeout)
	if err == nil && len(response) > 0 {
		log.Printf("WINBOX DEBUG: List response (%d bytes): %s", len(response), hex.EncodeToString(response))
		log.Printf("WINBOX DEBUG: List response ASCII: %q", string(response))

		// Check if this contains RouterOS version info (like Shodan data)
		responseStr := strings.ToLower(string(response))
		if strings.Contains(responseStr, ".jg:") || strings.Contains(responseStr, "routeros") || strings.Contains(responseStr, "mikrotik") {
			log.Printf("WINBOX DEBUG: List response contains RouterOS indicators")
			infoMap, productBanner := parseWinboxResponse(response, true)
			winboxInfo := fmt.Sprintf("%s", infoMap)
			payload := plugins.ServiceWinbox{
				Info:    winboxInfo,
				Product: productBanner,
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		} else {
			log.Printf("WINBOX DEBUG: List response failed validation")
		}
	} else {
		log.Printf("WINBOX DEBUG: List request failed: %v", err)
	}

	// Try Method 3: Winbox protocol message
	winboxRequest := createWinboxListRequest()
	log.Printf("WINBOX DEBUG: Trying Winbox protocol request (%d bytes): %s", len(winboxRequest), hex.EncodeToString(winboxRequest))

	response, err = utils.SendRecv(conn, winboxRequest, timeout)
	if err == nil && len(response) > 0 {
		log.Printf("WINBOX DEBUG: Winbox protocol response (%d bytes): %s", len(response), hex.EncodeToString(response))
		log.Printf("WINBOX DEBUG: Winbox protocol response ASCII: %q", string(response))

		if isValidWinboxProtocolResponse(response) {
			log.Printf("WINBOX DEBUG: Winbox protocol response validated")
			infoMap, productBanner := parseWinboxResponse(response, false)
			winboxInfo := fmt.Sprintf("%s", infoMap)
			payload := plugins.ServiceWinbox{
				Info:    winboxInfo,
				Product: productBanner,
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		} else {
			log.Printf("WINBOX DEBUG: Winbox protocol response failed validation")
		}
	} else {
		log.Printf("WINBOX DEBUG: Winbox protocol request failed: %v", err)
	}

	log.Printf("WINBOX DEBUG: No valid Winbox response detected")
	return nil, nil
}

func (p *WinboxPlugin) Priority() int {
	return 850
}
