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

package pptp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
	utils "github.com/vcore8/fingerprintx/pkg/plugins/pluginutils"
)

type PPTPPlugin struct{}

const PPTP = "pptp"

func init() {
	plugins.RegisterPlugin(&PPTPPlugin{})
}

/*
Point-to-Point Tunneling Protocol (PPTP) Detection with Banner Extraction

This plugin performs unauthenticated PPTP protocol fingerprinting and extracts
device/software information from PPTP responses to create informative banners.

PPTP SCCRP (Start-Control-Connection-Reply) messages contain:
- Host Name (64 bytes): DNS name of the PPTP server
- Vendor String (64 bytes): Vendor/software identification
- Firmware Revision: Version information
- Protocol Version: PPTP protocol version

The plugin extracts this information to identify:
- Device manufacturers (Cisco, Microsoft, MikroTik, etc.)
- Software versions (Windows RRAS, RouterOS, etc.)
- Firmware revisions and build numbers
*/

const (
	PPTP_MAGIC_COOKIE = 0x1A2B3C4D
	PPTP_CTRL_MESSAGE = 1
	PPTP_MGMT_MESSAGE = 2

	// Control Message Types
	SCCRQ    = 1 // Start-Control-Connection-Request
	SCCRP    = 2 // Start-Control-Connection-Reply
	StopCCRQ = 3 // Stop-Control-Connection-Request
	StopCCRP = 4 // Stop-Control-Connection-Reply
	ECHO_REQ = 5 // Echo-Request
	ECHO_REP = 6 // Echo-Reply
)

// createPPTPSCCRQPacket creates a Start-Control-Connection-Request packet
func createPPTPSCCRQPacket() []byte {
	var packet bytes.Buffer

	// PPTP Control Message Header
	length := uint16(156) // Standard SCCRQ length
	binary.Write(&packet, binary.BigEndian, length)

	pptpMsgType := uint16(PPTP_CTRL_MESSAGE)
	binary.Write(&packet, binary.BigEndian, pptpMsgType)

	magicCookie := uint32(PPTP_MAGIC_COOKIE)
	binary.Write(&packet, binary.BigEndian, magicCookie)

	ctrlMsgType := uint16(SCCRQ)
	binary.Write(&packet, binary.BigEndian, ctrlMsgType)

	reserved0 := uint16(0)
	binary.Write(&packet, binary.BigEndian, reserved0)

	// SCCRQ specific fields
	protocolVersion := uint16(0x0100) // Version 1.0
	binary.Write(&packet, binary.BigEndian, protocolVersion)

	reserved1 := uint16(0)
	binary.Write(&packet, binary.BigEndian, reserved1)

	framingCaps := uint32(0x00000003) // Async + Sync framing
	binary.Write(&packet, binary.BigEndian, framingCaps)

	bearerCaps := uint32(0x00000003) // Analog + Digital bearer
	binary.Write(&packet, binary.BigEndian, bearerCaps)

	maxChannels := uint16(1) // Maximum channels
	binary.Write(&packet, binary.BigEndian, maxChannels)

	firmwareRev := uint16(0x0100) // Firmware revision
	binary.Write(&packet, binary.BigEndian, firmwareRev)

	// Host Name (64 bytes, null-terminated)
	hostName := make([]byte, 64)
	copy(hostName, []byte("probe"))
	packet.Write(hostName)

	// Vendor String (64 bytes, null-terminated)
	vendorString := make([]byte, 64)
	copy(vendorString, []byte("fingerprintx"))
	packet.Write(vendorString)

	return packet.Bytes()
}

// isDefinitivePPTPResponse performs strict validation to ensure response is PPTP
func isDefinitivePPTPResponse(response []byte) bool {
	if len(response) < 12 {
		return false
	}

	// Parse PPTP header
	length := binary.BigEndian.Uint16(response[0:2])
	pptpMsgType := binary.BigEndian.Uint16(response[2:4])
	magicCookie := binary.BigEndian.Uint32(response[4:8])
	ctrlMsgType := binary.BigEndian.Uint16(response[8:10])
	reserved0 := binary.BigEndian.Uint16(response[10:12])

	// Strict PPTP header validation

	// 1. Magic Cookie must be exactly 0x1A2B3C4D
	if magicCookie != PPTP_MAGIC_COOKIE {
		return false
	}

	// 2. PPTP Message Type must be Control Message (1) or Management Message (2)
	if pptpMsgType != PPTP_CTRL_MESSAGE && pptpMsgType != PPTP_MGMT_MESSAGE {
		return false
	}

	// 3. Length should match actual packet length
	if int(length) != len(response) {
		return false
	}

	// 4. Reserved field should be 0
	if reserved0 != 0 {
		return false
	}

	// 5. Control Message Type should be valid and indicate PPTP service
	switch ctrlMsgType {
	case SCCRP: // Start-Control-Connection-Reply - server accepts
		return true
	case StopCCRQ: // Stop-Control-Connection-Request - server initiates disconnect
		return true
	case StopCCRP: // Stop-Control-Connection-Reply - server acknowledges disconnect
		return true
	case ECHO_REQ: // Echo-Request - server sends keepalive
		return true
	case ECHO_REP: // Echo-Reply - server responds to keepalive
		return true
	default:
		return false
	}
}

// extractStringField extracts null-terminated string from byte array
func extractStringField(data []byte) string {
	// Find null terminator
	nullIndex := bytes.IndexByte(data, 0)
	if nullIndex == -1 {
		nullIndex = len(data)
	}

	// Extract string and clean it
	str := string(data[:nullIndex])
	str = strings.TrimSpace(str)

	// Remove non-printable characters
	re := regexp.MustCompile(`[^\x20-\x7E]`)
	str = re.ReplaceAllString(str, "")

	return str
}

// identifyVendorFromString attempts to identify vendor/software from strings
func identifyVendorFromString(hostName, vendorString string) string {
	combined := strings.ToLower(hostName + " " + vendorString)

	// Common PPTP implementations and their identifiers
	vendors := map[string]string{
		"microsoft":  "Microsoft Windows",
		"windows":    "Microsoft Windows",
		"rras":       "Microsoft RRAS",
		"cisco":      "Cisco",
		"mikrotik":   "MikroTik RouterOS",
		"routeros":   "MikroTik RouterOS",
		"poptop":     "PoPToP PPTP Server",
		"pptpd":      "PPTP Daemon",
		"linux":      "Linux PPTP",
		"freebsd":    "FreeBSD PPTP",
		"openbsd":    "OpenBSD PPTP",
		"netbsd":     "NetBSD PPTP",
		"fortinet":   "Fortinet FortiGate",
		"fortigate":  "Fortinet FortiGate",
		"sonicwall":  "SonicWall",
		"watchguard": "WatchGuard",
		"zyxel":      "ZyXEL",
		"draytek":    "DrayTek",
		"tp-link":    "TP-Link",
		"netgear":    "Netgear",
		"linksys":    "Linksys",
		"asus":       "ASUS",
		"huawei":     "Huawei",
		"juniper":    "Juniper Networks",
		"pfsense":    "pfSense",
		"opnsense":   "OPNsense",
		"vyos":       "VyOS",
	}

	for keyword, vendor := range vendors {
		if strings.Contains(combined, keyword) {
			return vendor
		}
	}

	return "Unknown"
}

// parsePPTPInfo extracts PPTP information and creates banner from validated response
func parsePPTPInfo(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	// Parse PPTP header
	length := binary.BigEndian.Uint16(response[0:2])
	pptpMsgType := binary.BigEndian.Uint16(response[2:4])
	magicCookie := binary.BigEndian.Uint32(response[4:8])
	ctrlMsgType := binary.BigEndian.Uint16(response[8:10])

	info["PPTP_Length"] = fmt.Sprintf("%d", length)
	info["Message_Type"] = fmt.Sprintf("%d", pptpMsgType)
	info["Magic_Cookie"] = fmt.Sprintf("0x%08X", magicCookie)

	// Decode control message type
	messageTypeName := ""
	switch ctrlMsgType {
	case SCCRP:
		messageTypeName = "SCCRP"
		info["Response"] = "Start-Control-Connection-Reply"
	case StopCCRQ:
		messageTypeName = "StopCCRQ"
		info["Response"] = "Stop-Control-Connection-Request"
	case StopCCRP:
		messageTypeName = "StopCCRP"
		info["Response"] = "Stop-Control-Connection-Reply"
	case ECHO_REQ:
		messageTypeName = "ECHO_REQ"
		info["Response"] = "Echo-Request"
	case ECHO_REP:
		messageTypeName = "ECHO_REP"
		info["Response"] = "Echo-Reply"
	default:
		messageTypeName = fmt.Sprintf("Unknown(%d)", ctrlMsgType)
		info["Response"] = messageTypeName
	}
	info["Control_Message_Type"] = messageTypeName

	// Default banner
	productBanner := "pptp tunneling_protocol 1.0"

	// Parse additional fields for SCCRP (contains vendor information)
	if ctrlMsgType == SCCRP && len(response) >= 156 {
		protocolVersion := binary.BigEndian.Uint16(response[12:14])
		info["Protocol_Version"] = fmt.Sprintf("0x%04X", protocolVersion)

		if len(response) >= 28 {
			framingCaps := binary.BigEndian.Uint32(response[16:20])
			bearerCaps := binary.BigEndian.Uint32(response[20:24])
			maxChannels := binary.BigEndian.Uint16(response[24:26])
			firmwareRev := binary.BigEndian.Uint16(response[26:28])

			info["Framing_Capabilities"] = fmt.Sprintf("0x%08X", framingCaps)
			info["Bearer_Capabilities"] = fmt.Sprintf("0x%08X", bearerCaps)
			info["Max_Channels"] = fmt.Sprintf("%d", maxChannels)
			info["Firmware_Revision"] = fmt.Sprintf("0x%04X", firmwareRev)

			// Extract Host Name (64 bytes starting at offset 28)
			if len(response) >= 92 {
				hostNameBytes := response[28:92]
				hostName := extractStringField(hostNameBytes)
				if hostName != "" {
					info["Host_Name"] = hostName
				}

				// Extract Vendor String (64 bytes starting at offset 92)
				if len(response) >= 156 {
					vendorStringBytes := response[92:156]
					vendorString := extractStringField(vendorStringBytes)
					if vendorString != "" {
						info["Vendor_String"] = vendorString
					}

					// Create enhanced banner with vendor information
					vendor := identifyVendorFromString(hostName, vendorString)
					if vendor != "Unknown" {
						productBanner = fmt.Sprintf("pptp %s", vendor)

						// Add version information if available
						if firmwareRev != 0 && firmwareRev != 0x0100 {
							major := (firmwareRev >> 8) & 0xFF
							minor := firmwareRev & 0xFF
							if major > 0 || minor > 0 {
								productBanner = fmt.Sprintf("pptp %s %d.%d", vendor, major, minor)
							}
						}
					} else if hostName != "" || vendorString != "" {
						// Use raw vendor string if no known vendor identified
						if vendorString != "" {
							productBanner = fmt.Sprintf("pptp %s", vendorString)
						} else if hostName != "" {
							productBanner = fmt.Sprintf("pptp %s", hostName)
						}
					}
				}
			}
		}
	}

	return info, productBanner
}

func (p *PPTPPlugin) PortPriority(port uint16) bool {
	return port == 1723
}

func (p *PPTPPlugin) Name() string {
	return PPTP
}

func (p *PPTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *PPTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	request := createPPTPSCCRQPacket()

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Only return positive detection if we're 100% certain it's PPTP
	if isDefinitivePPTPResponse(response) {
		infoMap, productBanner := parsePPTPInfo(response)
		pptpInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServicePPTP{
			Info:    pptpInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	// Return nil if not definitively PPTP
	return nil, nil
}

func (p *PPTPPlugin) Priority() int {
	return 800
}
