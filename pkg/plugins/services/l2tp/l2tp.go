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

package l2tp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type L2TPPlugin struct{}

const L2TP = "l2tp"

func init() {
	plugins.RegisterPlugin(&L2TPPlugin{})
}

// createNmapL2TPICRQPacket creates the exact L2TP_ICRQ packet that Nmap uses
func createNmapL2TPICRQPacket() []byte {
	// This is the exact payload from nmap-payloads for L2TP_ICRQ
	hexStr := "c802003c000000000000000080080000000000018008000000020100800e000000076e78702d7363616e800a00000003000000038008000000090000"
	payload, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil
	}
	return payload
}

// isL2TPResponse checks if response looks like L2TP
func isL2TPResponse(response []byte) bool {
	if len(response) < 8 {
		return false
	}

	// Look for L2TP header pattern anywhere in response
	for i := 0; i <= len(response)-8; i++ {
		flags := binary.BigEndian.Uint16(response[i : i+2])
		version := flags & 0x000F

		// Check for L2TP version 2 with control bit set
		if version == 2 && (flags&0x8000) != 0 {
			return true
		}
	}

	// Look for L2TP error messages or strings
	responseStr := strings.ToLower(string(response))
	l2tpIndicators := []string{
		"tunnel", "assigned", "specify", "l2tp", "ppp", "lac", "lns",
		"connection", "session", "call", "bearer", "framing",
	}

	for _, indicator := range l2tpIndicators {
		if strings.Contains(responseStr, indicator) {
			return true
		}
	}

	return false
}

// extractStringsFromResponse extracts printable strings from response
func extractStringsFromResponse(response []byte) []string {
	// Look for printable strings of 4+ characters
	re := regexp.MustCompile(`[a-zA-Z0-9\-\.\_]{4,}`)
	matches := re.FindAll(response, -1)

	var extractedStrings []string
	for _, match := range matches {
		str := string(match)
		if len(str) >= 4 {
			extractedStrings = append(extractedStrings, str)
		}
	}

	return extractedStrings
}

// identifyVendorFromStrings attempts to identify vendor from extracted strings
func identifyVendorFromStrings(extractedStrings []string, hostName string) (string, string) {
	combined := strings.ToLower(strings.Join(extractedStrings, " ") + " " + hostName)

	// Vendor patterns with version extraction
	vendorPatterns := map[string]struct {
		name         string
		versionRegex string
	}{
		"mikrotik":   {"MikroTik RouterOS", `routeros[\s\-]*([\d\.]+)`},
		"routeros":   {"MikroTik RouterOS", `([\d\.]+)`},
		"cisco":      {"Cisco", `ios[\s\-]*([\d\.]+)`},
		"microsoft":  {"Microsoft", `windows[\s\-]*([\d\.]+)`},
		"windows":    {"Microsoft Windows", `([\d\.]+)`},
		"linux":      {"Linux L2TP", `([\d\.]+)`},
		"strongswan": {"strongSwan", `([\d\.]+)`},
		"openswan":   {"Openswan", `([\d\.]+)`},
		"freeswan":   {"FreeS/WAN", `([\d\.]+)`},
		"xl2tpd":     {"xl2tpd", `([\d\.]+)`},
		"fortinet":   {"Fortinet FortiGate", `fortios[\s\-]*([\d\.]+)`},
		"fortigate":  {"Fortinet FortiGate", `([\d\.]+)`},
		"sonicwall":  {"SonicWall", `([\d\.]+)`},
		"watchguard": {"WatchGuard", `([\d\.]+)`},
		"zyxel":      {"ZyXEL", `([\d\.]+)`},
		"draytek":    {"DrayTek", `([\d\.]+)`},
		"huawei":     {"Huawei", `([\d\.]+)`},
		"juniper":    {"Juniper Networks", `junos[\s\-]*([\d\.]+)`},
		"ubiquiti":   {"Ubiquiti", `([\d\.]+)`},
		"pfsense":    {"pfSense", `([\d\.]+)`},
		"opnsense":   {"OPNsense", `([\d\.]+)`},
		"vyos":       {"VyOS", `([\d\.]+)`},
	}

	for keyword, pattern := range vendorPatterns {
		if strings.Contains(combined, keyword) {
			vendor := pattern.name

			// Try to extract version
			if pattern.versionRegex != "" {
				versionRe := regexp.MustCompile(pattern.versionRegex)
				if matches := versionRe.FindStringSubmatch(combined); len(matches) > 1 {
					return vendor, matches[1]
				}
			}

			return vendor, ""
		}
	}

	// Check for generic version patterns in hostname or strings
	versionRe := regexp.MustCompile(`[\-\.]v?([\d]+\.[\d]+(?:\.[\d]+)?)`)
	for _, str := range extractedStrings {
		if matches := versionRe.FindStringSubmatch(strings.ToLower(str)); len(matches) > 1 {
			return "Unknown", matches[1]
		}
	}

	return "", ""
}

// parseL2TPResponse analyzes L2TP response and extracts information
func parseL2TPResponse(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))

	// Look for L2TP headers and extract information
	headerCount := 0
	messageTypes := make(map[string]int)
	hostName := ""
	vendorName := ""
	protocolVersion := ""

	for i := 0; i <= len(response)-12; i++ {
		flags := binary.BigEndian.Uint16(response[i : i+2])
		version := flags & 0x000F

		if version == 2 && (flags&0x8000) != 0 {
			headerCount++
			length := binary.BigEndian.Uint16(response[i+2 : i+4])
			tunnelID := binary.BigEndian.Uint16(response[i+4 : i+6])
			sessionID := binary.BigEndian.Uint16(response[i+6 : i+8])

			if headerCount == 1 {
				info["L2TP_Version"] = "2"
				info["Tunnel_ID"] = fmt.Sprintf("%d", tunnelID)
				info["Session_ID"] = fmt.Sprintf("%d", sessionID)
			}

			// Try to parse AVPs with more robust parsing
			if i+12 < len(response) && int(length) > 12 {
				avpOffset := i + 12
				endOffset := i + int(length)
				if endOffset > len(response) {
					endOffset = len(response)
				}

				for avpOffset < endOffset-6 {
					avpFlags := binary.BigEndian.Uint16(response[avpOffset : avpOffset+2])
					avpLength := binary.BigEndian.Uint16(response[avpOffset+4 : avpOffset+6])
					avpType := avpFlags & 0x3FFF

					if avpLength < 6 || avpOffset+int(avpLength) > endOffset {
						break
					}

					if avpType == 0 && avpLength >= 8 { // Message Type
						msgType := binary.BigEndian.Uint16(response[avpOffset+6 : avpOffset+8])
						switch msgType {
						case 2:
							messageTypes["SCCRP"]++
						case 4:
							messageTypes["StopCCN"]++
						case 6:
							messageTypes["HELLO"]++
						case 9:
							messageTypes["ICRQ"]++
						case 10:
							messageTypes["ICRP"]++
						case 12:
							messageTypes["CDN"]++
						default:
							messageTypes[fmt.Sprintf("Type_%d", msgType)]++
						}
					} else if avpType == 2 && avpLength >= 8 { // Protocol Version
						versionBytes := response[avpOffset+6 : avpOffset+8]
						versionVal := binary.BigEndian.Uint16(versionBytes)
						protocolVersion = fmt.Sprintf("%d.%d", versionVal>>8, versionVal&0xFF)
					} else if avpType == 7 && avpLength > 6 { // Host Name
						nameBytes := response[avpOffset+6 : avpOffset+int(avpLength)]
						hostName = strings.TrimRight(string(nameBytes), "\x00")
					} else if avpType == 8 && avpLength > 6 { // Vendor Name
						nameBytes := response[avpOffset+6 : avpOffset+int(avpLength)]
						vendorName = strings.TrimRight(string(nameBytes), "\x00")
					}

					avpOffset += int(avpLength)
				}
			}
		}
	}

	if headerCount > 0 {
		info["L2TP_Headers"] = fmt.Sprintf("%d", headerCount)
	}

	for msgType, count := range messageTypes {
		info[fmt.Sprintf("Message_%s", msgType)] = fmt.Sprintf("%d", count)
	}

	// Extract strings from response
	extractedStrings := extractStringsFromResponse(response)

	if len(extractedStrings) > 0 {
		info["Extracted_Strings"] = strings.Join(extractedStrings, "; ")
	}

	if hostName != "" {
		info["Host_Name"] = hostName
	}
	if vendorName != "" {
		info["Vendor_Name"] = vendorName
	}
	if protocolVersion != "" {
		info["Protocol_Version"] = protocolVersion
	}

	// Identify vendor and version from all available information
	detectedVendor, detectedVersion := identifyVendorFromStrings(extractedStrings, hostName)

	// Override with explicit vendor name if found
	if vendorName != "" {
		detectedVendor = vendorName
	}

	// Create enhanced banner
	productBanner := "l2tp tunneling_protocol 2"

	// Check for specific error messages first
	responseStr := strings.ToLower(string(response))
	if strings.Contains(responseStr, "specify") && strings.Contains(responseStr, "tunnel") {
		productBanner = "l2tp server (tunnel_id_required)"
	} else if detectedVendor != "" {
		if detectedVersion != "" {
			productBanner = fmt.Sprintf("l2tp %s %s", detectedVendor, detectedVersion)
		} else {
			productBanner = fmt.Sprintf("l2tp %s", detectedVendor)
		}
	} else if hostName != "" {
		// Try to extract vendor info from hostname patterns
		hostLower := strings.ToLower(hostName)
		if strings.Contains(hostLower, "mikrotik") || strings.Contains(hostLower, "routeros") {
			productBanner = "l2tp MikroTik RouterOS"
		} else if strings.Contains(hostLower, "cisco") {
			productBanner = "l2tp Cisco"
		} else if strings.Contains(hostLower, "windows") || strings.Contains(hostLower, "win") {
			productBanner = "l2tp Microsoft Windows"
		} else if strings.Contains(hostLower, "linux") {
			productBanner = "l2tp Linux"
		} else {
			productBanner = fmt.Sprintf("l2tp server (%s)", hostName)
		}
	} else if len(messageTypes) > 0 {
		// Create banner based on message types seen
		var msgList []string
		for msgType := range messageTypes {
			msgList = append(msgList, msgType)
		}
		productBanner = fmt.Sprintf("l2tp server (%s)", strings.Join(msgList, ","))
	}

	return info, productBanner
}

func (p *L2TPPlugin) PortPriority(port uint16) bool {
	return port == 1701
}

func (p *L2TPPlugin) Name() string {
	return L2TP
}

func (p *L2TPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *L2TPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Use the exact same payload that Nmap uses
	nmapPayload := createNmapL2TPICRQPacket()
	if nmapPayload == nil {
		return nil, nil
	}

	response, err := utils.SendRecv(conn, nmapPayload, timeout)
	if err != nil {
		return nil, nil
	}

	if len(response) == 0 {
		return nil, nil
	}

	// Check if response looks like L2TP
	if isL2TPResponse(response) {
		infoMap, productBanner := parseL2TPResponse(response)
		l2tpInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServiceL2TP{
			Info:    l2tpInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	return nil, nil
}

func (p *L2TPPlugin) Priority() int {
	return 800
}
