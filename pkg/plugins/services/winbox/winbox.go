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

// createIndexRequest creates a simple HTTP-like request for the index file
func createIndexRequest() []byte {
	request := "GET /index HTTP/1.1\r\n"
	request += "Host: router\r\n"
	request += "User-Agent: fingerprintx\r\n"
	request += "Connection: close\r\n\r\n"
	return []byte(request)
}

// createWinboxListRequest creates a Winbox protocol message to read the list file
func createWinboxListRequest() []byte {
	// Based on Tenable research - Winbox message to system binary 2 (mproxy), handler 2
	// This is a simplified version of the list file request
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

// isValidWinboxResponse checks if response looks like Winbox
func isValidWinboxResponse(response []byte) bool {
	if len(response) < 6 {
		return false
	}

	// Check for HTTP response (index file method)
	if strings.HasPrefix(string(response), "HTTP/") {
		return true
	}

	// Check for Winbox protocol response
	// Look for potential Winbox magic bytes or structure
	for i := 0; i <= len(response)-6; i++ {
		// Check for common Winbox magic patterns
		magic := binary.LittleEndian.Uint16(response[i+4 : i+6])
		if magic == 0x4D32 || magic == 0x324D { // "M2" or "2M"
			return true
		}
	}

	// Check for RouterOS-specific strings
	responseStr := strings.ToLower(string(response))
	winboxIndicators := []string{
		"routeros", "mikrotik", "winbox", "routerboard",
		"version", "board", "architecture", "build",
	}

	for _, indicator := range winboxIndicators {
		if strings.Contains(responseStr, indicator) {
			return true
		}
	}

	return false
}

// parseWinboxResponse analyzes response and extracts RouterOS information
func parseWinboxResponse(response []byte) (map[string]any, string) {
	info := make(map[string]any)
	responseStr := string(response)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))

	// Parse HTTP response (index file method)
	if strings.HasPrefix(responseStr, "HTTP/") {
		info["Method"] = "Index_File_Request"

		// Extract RouterOS version from common patterns
		versionPatterns := []string{
			`RouterOS\s+v?([\d\.]+)`,
			`version[:\s]+([\d\.]+)`,
			`build[:\s]+([\d\.]+)`,
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

		// Extract board/model information
		boardPatterns := []string{
			`board[:\s]+([^\r\n]+)`,
			`model[:\s]+([^\r\n]+)`,
			`routerboard[:\s]+([^\r\n]+)`,
			`architecture[:\s]+([^\r\n]+)`,
		}

		var board string
		for _, pattern := range boardPatterns {
			re := regexp.MustCompile(`(?i)` + pattern)
			if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
				board = strings.TrimSpace(matches[1])
				break
			}
		}

		if version != "" {
			info["RouterOS_Version"] = version
		}
		if board != "" {
			info["Board_Model"] = board
		}

		// Look for other useful information
		if strings.Contains(strings.ToLower(responseStr), "mikrotik") {
			info["Vendor"] = "MikroTik"
		}

		// Extract any other version-like patterns
		buildRe := regexp.MustCompile(`(?i)build[:\s]+([\w\d\.]+)`)
		if matches := buildRe.FindStringSubmatch(responseStr); len(matches) > 1 {
			info["Build"] = matches[1]
		}

	} else {
		// Parse Winbox protocol response
		info["Method"] = "Winbox_Protocol"

		// Look for Winbox magic bytes and structure
		for i := 0; i <= len(response)-6; i++ {
			magic := binary.LittleEndian.Uint16(response[i+4 : i+6])
			if magic == 0x4D32 || magic == 0x324D {
				info["Winbox_Magic"] = fmt.Sprintf("0x%04X", magic)

				if i+2 < len(response) {
					msgLen := binary.LittleEndian.Uint16(response[i+2 : i+4])
					info["Message_Length"] = fmt.Sprintf("%d", msgLen)
				}
				break
			}
		}

		// Extract any readable strings that might contain version info
		stringRe := regexp.MustCompile(`[a-zA-Z0-9\.\-_]{4,}`)
		matches := stringRe.FindAll(response, -1)

		var extractedStrings []string
		for _, match := range matches {
			str := string(match)
			if len(str) >= 4 {
				extractedStrings = append(extractedStrings, str)
			}
		}

		if len(extractedStrings) > 0 {
			info["Extracted_Strings"] = strings.Join(extractedStrings, "; ")
		}
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

	// Try Method 1: Index file request (simpler, works on more versions)
	indexRequest := createIndexRequest()

	response, err := utils.SendRecv(conn, indexRequest, timeout)
	if err == nil && len(response) > 0 && isValidWinboxResponse(response) {
		infoMap, productBanner := parseWinboxResponse(response)
		winboxInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServiceWinbox{
			Info:    winboxInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	// Try Method 2: Winbox protocol message (if index request failed)
	winboxRequest := createWinboxListRequest()

	response, err = utils.SendRecv(conn, winboxRequest, timeout)
	if err == nil && len(response) > 0 && isValidWinboxResponse(response) {
		infoMap, productBanner := parseWinboxResponse(response)
		winboxInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServiceWinbox{
			Info:    winboxInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func (p *WinboxPlugin) Priority() int {
	return 850
}
