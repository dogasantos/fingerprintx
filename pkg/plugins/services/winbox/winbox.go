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
	"fmt"
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

// createMalformedWinboxPackets creates various malformed Winbox packets to trigger errors
func createMalformedWinboxPackets() [][]byte {
	var packets [][]byte

	// 1. Malformed magic bytes
	packet1 := make([]byte, 16)
	packet1[0] = 0x00                                   // Chunk offset
	packet1[1] = 0x01                                   // Message type
	binary.LittleEndian.PutUint16(packet1[2:4], 16)     // Message length
	binary.LittleEndian.PutUint16(packet1[4:6], 0xDEAD) // Wrong magic bytes
	packets = append(packets, packet1)

	// 2. Invalid message length
	packet2 := make([]byte, 16)
	packet2[0] = 0x00
	packet2[1] = 0x01
	binary.LittleEndian.PutUint16(packet2[2:4], 65535)  // Huge length
	binary.LittleEndian.PutUint16(packet2[4:6], 0x4D32) // Correct magic
	packets = append(packets, packet2)

	// 3. Zero-length message
	packet3 := make([]byte, 6)
	packet3[0] = 0x00
	packet3[1] = 0x01
	binary.LittleEndian.PutUint16(packet3[2:4], 0) // Zero length
	binary.LittleEndian.PutUint16(packet3[4:6], 0x4D32)
	packets = append(packets, packet3)

	// 4. Invalid message type
	packet4 := make([]byte, 16)
	packet4[0] = 0x00
	packet4[1] = 0xFF // Invalid message type
	binary.LittleEndian.PutUint16(packet4[2:4], 16)
	binary.LittleEndian.PutUint16(packet4[4:6], 0x4D32)
	packets = append(packets, packet4)

	// 5. Corrupted header
	packet5 := make([]byte, 10)
	for i := range packet5 {
		packet5[i] = 0xFF // All 0xFF
	}
	packets = append(packets, packet5)

	return packets
}

// createMalformedHTTPRequests creates malformed HTTP requests that might trigger Winbox errors
func createMalformedHTTPRequests() [][]byte {
	var requests [][]byte

	// 1. Invalid HTTP method
	req1 := "WINBOX /index HTTP/1.1\r\nHost: router\r\n\r\n"
	requests = append(requests, []byte(req1))

	// 2. Invalid path
	req2 := "GET /winbox HTTP/1.1\r\nHost: router\r\n\r\n"
	requests = append(requests, []byte(req2))

	// 3. Malformed HTTP
	req3 := "GET /index WINBOX/1.0\r\nHost: router\r\n\r\n"
	requests = append(requests, []byte(req3))

	return requests
}

// isWinboxErrorResponse checks if response contains Winbox/RouterOS error indicators
func isWinboxErrorResponse(response []byte) bool {
	if len(response) == 0 {
		return false
	}

	responseStr := strings.ToLower(string(response))

	// Look for Winbox/RouterOS specific error indicators
	winboxIndicators := []string{
		"winbox", "routeros", "mikrotik", "routerboard",
	}

	indicatorCount := 0
	for _, indicator := range winboxIndicators {
		if strings.Contains(responseStr, indicator) {
			indicatorCount++
		}
	}

	// Must have at least one strong Winbox indicator
	if indicatorCount >= 1 {
		return true
	}

	// Check for binary patterns that might indicate Winbox protocol errors
	if len(response) >= 6 {
		// Look for potential Winbox magic bytes in error responses
		for i := 0; i <= len(response)-6; i++ {
			magic := binary.LittleEndian.Uint16(response[i : i+2])
			if magic == 0x4D32 || magic == 0x324D {
				return true
			}
		}
	}

	// Check for HTTP error responses that mention RouterOS/Winbox
	if strings.HasPrefix(responseStr, "http/") {
		if strings.Contains(responseStr, "routeros") ||
			strings.Contains(responseStr, "mikrotik") ||
			strings.Contains(responseStr, "winbox") {
			return true
		}
	}

	return false
}

// parseErrorResponse extracts information from error responses
func parseErrorResponse(response []byte, method string) (map[string]any, string) {
	info := make(map[string]any)
	responseStr := string(response)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))
	info["Detection_Method"] = method

	// Extract any version information from error messages
	versionPatterns := []string{
		`RouterOS\s+v?([\d\.]+)`,
		`version[:\s]+([\d\.]+)`,
		`v([\d\.]+)`,
	}

	var version string
	for _, pattern := range versionPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			version = matches[1]
			break
		}
	}

	// Look for error codes or messages
	errorPatterns := []string{
		`error[:\s]*([^\r\n]+)`,
		`invalid[:\s]*([^\r\n]+)`,
		`bad[:\s]*([^\r\n]+)`,
		`failed[:\s]*([^\r\n]+)`,
	}

	var errorMsg string
	for _, pattern := range errorPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			errorMsg = strings.TrimSpace(matches[1])
			break
		}
	}

	if version != "" {
		info["RouterOS_Version"] = version
	}
	if errorMsg != "" {
		info["Error_Message"] = errorMsg
	}

	// Check for specific Winbox/RouterOS indicators
	responseStrLower := strings.ToLower(responseStr)
	if strings.Contains(responseStrLower, "mikrotik") {
		info["Vendor"] = "MikroTik"
	}
	if strings.Contains(responseStrLower, "routeros") {
		info["OS"] = "RouterOS"
	}
	if strings.Contains(responseStrLower, "winbox") {
		info["Protocol"] = "Winbox"
	}

	// Create product banner
	productBanner := "winbox MikroTik RouterOS"
	if version != "" {
		productBanner = fmt.Sprintf("winbox MikroTik RouterOS %s", version)
	}

	return info, productBanner
}

func (p *WinboxPlugin) PortPriority(port uint16) bool {
	return port == 8291
}

func (p *WinboxPlugin) Name() string {
	return WINBOX
}

func (p *WinboxPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *WinboxPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	port := getPortFromConnection(conn)
	if port != 8291 {
		return nil, nil
	}

	// Try malformed Winbox packets to trigger error responses
	malformedPackets := createMalformedWinboxPackets()
	for i, packet := range malformedPackets {
		response, err := utils.SendRecv(conn, packet, timeout)
		if err == nil && len(response) > 0 && isWinboxErrorResponse(response) {
			infoMap, productBanner := parseErrorResponse(response, fmt.Sprintf("Malformed_Winbox_Packet_%d", i+1))
			winboxInfo := fmt.Sprintf("%s", infoMap)
			payload := plugins.ServiceWinbox{
				Info:    winboxInfo,
				Product: productBanner,
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		}
	}

	// Try malformed HTTP requests
	malformedHTTP := createMalformedHTTPRequests()
	for i, request := range malformedHTTP {
		response, err := utils.SendRecv(conn, request, timeout)
		if err == nil && len(response) > 0 && isWinboxErrorResponse(response) {
			infoMap, productBanner := parseErrorResponse(response, fmt.Sprintf("Malformed_HTTP_%d", i+1))
			winboxInfo := fmt.Sprintf("%s", infoMap)
			payload := plugins.ServiceWinbox{
				Info:    winboxInfo,
				Product: productBanner,
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		}
	}

	return nil, nil
}

func (p *WinboxPlugin) Priority() int {
	return 850
}
