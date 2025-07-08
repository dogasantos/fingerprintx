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
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
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

// createL2TPSCCRQPacket creates a Start-Control-Connection-Request packet
func createL2TPSCCRQPacket() []byte {
	var packet bytes.Buffer

	// L2TP Header
	// Flags: T=1 (control), L=1 (length present), S=1 (sequence present), Ver=2
	flags := uint16(0xC802) // 1100 1000 0000 0010
	binary.Write(&packet, binary.BigEndian, flags)

	// Length will be calculated and written later
	lengthPos := packet.Len()
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Tunnel ID (0 for initial connection)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Session ID (0 for control connection)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Ns (sequence number, starting at 0)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Nr (next expected sequence number, starting at 0)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Minimal required AVPs for SCCRQ

	// Message Type AVP (Type 0, Value 1 for SCCRQ) - Mandatory
	avp := createAVP(0, []byte{0x00, 0x01}, true)
	packet.Write(avp)

	// Protocol Version AVP (Type 2, Value 0x0100 for version 1.0) - Mandatory
	avp = createAVP(2, []byte{0x01, 0x00}, true)
	packet.Write(avp)

	// Host Name AVP (Type 7) - Mandatory
	hostname := "probe"
	avp = createAVP(7, []byte(hostname), true)
	packet.Write(avp)

	// Assigned Tunnel ID AVP (Type 9, Value 1) - Mandatory
	avp = createAVP(9, []byte{0x00, 0x01}, true)
	packet.Write(avp)

	// Update length field
	totalLength := packet.Len()
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:lengthPos+2], uint16(totalLength))

	return packetBytes
}

// createSimpleL2TPProbe creates a minimal L2TP probe packet
func createSimpleL2TPProbe() []byte {
	var packet bytes.Buffer

	// Minimal L2TP header - just flags, length, and tunnel/session IDs
	flags := uint16(0xC802) // T=1, L=1, S=1, Ver=2
	length := uint16(12)    // Just header, no AVPs

	binary.Write(&packet, binary.BigEndian, flags)
	binary.Write(&packet, binary.BigEndian, length)
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Tunnel ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Session ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Ns
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Nr

	return packet.Bytes()
}

// createL2TPHelloProbe creates an L2TP Hello packet
func createL2TPHelloProbe() []byte {
	var packet bytes.Buffer

	// L2TP Header
	flags := uint16(0xC802)
	binary.Write(&packet, binary.BigEndian, flags)

	// Length will be calculated and written later
	lengthPos := packet.Len()
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Tunnel ID (0 for initial connection)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Session ID (0 for control connection)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Ns (sequence number, starting at 0)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Nr (next expected sequence number, starting at 0)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Hello Message Type AVP (Type 0, Value 6 for Hello)
	avp := createAVP(0, []byte{0x00, 0x06}, true)
	packet.Write(avp)

	// Update length field
	totalLength := packet.Len()
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:lengthPos+2], uint16(totalLength))

	return packetBytes
}

// createAVP creates an Attribute Value Pair with proper L2TP format
func createAVP(avpType uint16, value []byte, mandatory bool) []byte {
	var avp bytes.Buffer

	// AVP Header: M H Reserved | Vendor ID | Attribute Type | Length
	flags := avpType
	if mandatory {
		flags |= 0x8000 // Set M bit
	}

	// Length includes the 6-byte header
	length := uint16(6 + len(value))

	binary.Write(&avp, binary.BigEndian, flags)
	binary.Write(&avp, binary.BigEndian, uint16(0)) // Vendor ID (0 for IETF)
	binary.Write(&avp, binary.BigEndian, length)
	avp.Write(value)

	return avp.Bytes()
}

// isL2TPResponse performs basic L2TP validation (less strict)
func isL2TPResponse(response []byte) bool {
	if len(response) < 8 {
		return false
	}

	// Parse L2TP header
	flags := binary.BigEndian.Uint16(response[0:2])

	// Check version (bits 0-3)
	version := flags & 0x000F
	if version != 2 {
		return false
	}

	// Check if it's a control message (T bit = 1) - this is the main indicator
	if (flags & 0x8000) == 0 {
		return false
	}

	return true
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

	// Remove non-printable characters except common ones
	re := regexp.MustCompile(`[^\x20-\x7E]`)
	str = re.ReplaceAllString(str, "")

	return str
}

// identifyVendorFromString attempts to identify vendor from strings
func identifyVendorFromString(hostName, vendorName string) string {
	combined := strings.ToLower(hostName + " " + vendorName)

	// Common L2TP implementations and their identifiers
	vendors := map[string]string{
		"mikrotik":   "MikroTik RouterOS",
		"routeros":   "MikroTik RouterOS",
		"cisco":      "Cisco",
		"microsoft":  "Microsoft",
		"windows":    "Microsoft Windows",
		"linux":      "Linux L2TP",
		"strongswan": "strongSwan",
		"openswan":   "Openswan",
		"freeswan":   "FreeS/WAN",
		"xl2tpd":     "xl2tpd",
		"rp-l2tp":    "Roaring Penguin L2TP",
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
		"ubiquiti":   "Ubiquiti",
		"unifi":      "Ubiquiti UniFi",
	}

	for keyword, vendor := range vendors {
		if strings.Contains(combined, keyword) {
			return vendor
		}
	}

	// If we have a vendor name but no match, return it as-is
	if vendorName != "" {
		return vendorName
	}

	return "Unknown"
}

// parseL2TPInfo extracts L2TP information from response
func parseL2TPInfo(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	// Parse L2TP header
	flags := binary.BigEndian.Uint16(response[0:2])

	if len(response) >= 4 {
		length := binary.BigEndian.Uint16(response[2:4])
		info["Packet_Length"] = fmt.Sprintf("%d", length)
	}

	if len(response) >= 8 {
		tunnelID := binary.BigEndian.Uint16(response[4:6])
		sessionID := binary.BigEndian.Uint16(response[6:8])
		info["Tunnel_ID"] = fmt.Sprintf("%d", tunnelID)
		info["Session_ID"] = fmt.Sprintf("%d", sessionID)
	}

	version := flags & 0x000F
	info["L2TP_Version"] = fmt.Sprintf("%d", version)

	// Try to parse AVPs if present
	hostName := ""
	vendorName := ""
	messageType := ""

	if len(response) > 12 {
		offset := 12

		for offset < len(response)-6 {
			// Parse AVP header
			avpFlags := binary.BigEndian.Uint16(response[offset : offset+2])
			binary.BigEndian.Uint16(response[offset+2 : offset+4]) // vendorID - read but not used
			avpLength := binary.BigEndian.Uint16(response[offset+4 : offset+6])

			if avpLength < 6 || offset+int(avpLength) > len(response) {
				break
			}

			avpType := avpFlags & 0x3FFF

			// Extract value
			if avpLength > 6 {
				valueBytes := response[offset+6 : offset+int(avpLength)]

				switch avpType {
				case 0: // Message Type
					if len(valueBytes) >= 2 {
						msgType := binary.BigEndian.Uint16(valueBytes[0:2])
						switch msgType {
						case 2:
							messageType = "SCCRP"
							info["Response"] = "Start-Control-Connection-Reply"
						case 3:
							messageType = "SCCCN"
							info["Response"] = "Start-Control-Connection-Connected"
						case 4:
							messageType = "StopCCN"
							info["Response"] = "Stop-Control-Connection-Notification"
						case 6:
							messageType = "HELLO"
							info["Response"] = "Hello"
						}
						info["Message_Type"] = messageType
					}
				case 7: // Host Name
					hostName = extractStringField(valueBytes)
					if hostName != "" {
						info["Host_Name"] = hostName
					}
				case 8: // Vendor Name
					vendorName = extractStringField(valueBytes)
					if vendorName != "" {
						info["Vendor_Name"] = vendorName
					}
				}
			}

			offset += int(avpLength)
		}
	}

	// Create enhanced banner with vendor information
	productBanner := fmt.Sprintf("l2tp tunneling_protocol %d", version)

	vendor := identifyVendorFromString(hostName, vendorName)
	if vendor != "Unknown" {
		productBanner = fmt.Sprintf("l2tp %s", vendor)
	} else if vendorName != "" {
		productBanner = fmt.Sprintf("l2tp %s", vendorName)
	} else if hostName != "" {
		productBanner = fmt.Sprintf("l2tp %s", hostName)
	}

	return info, productBanner
}

// tryL2TPProbe attempts to get a response using different probe methods
func tryL2TPProbe(conn net.Conn, timeout time.Duration) []byte {
	probes := []struct {
		name string
		data []byte
	}{
		{"SCCRQ", createL2TPSCCRQPacket()},
		{"Hello", createL2TPHelloProbe()},
		{"Simple", createSimpleL2TPProbe()},
	}

	for _, probe := range probes {
		log.Printf("L2TP DEBUG: Trying %s probe (%d bytes): %x", probe.name, len(probe.data), probe.data)

		response, err := utils.SendRecv(conn, probe.data, timeout)
		if err != nil {
			log.Printf("L2TP DEBUG: %s probe error: %v", probe.name, err)
			continue
		}

		log.Printf("L2TP DEBUG: %s probe response (%d bytes)", probe.name, len(response))
		if len(response) > 0 {
			log.Printf("L2TP DEBUG: %s response hex: %x", probe.name, response)
			return response
		}
	}

	return nil
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
	log.Printf("L2TP DEBUG: Starting aggressive L2TP detection for %s", target.Host)

	// Try multiple probe methods
	response := tryL2TPProbe(conn, timeout)

	if len(response) == 0 {
		log.Printf("L2TP DEBUG: No response from any probe method")
		return nil, nil
	}

	// Use less strict validation
	if isL2TPResponse(response) {
		log.Printf("L2TP DEBUG: Valid L2TP response detected")
		infoMap, productBanner := parseL2TPInfo(response)
		l2tpInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServiceL2TP{
			Info:    l2tpInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	log.Printf("L2TP DEBUG: Response not recognized as L2TP")
	return nil, nil
}

func (p *L2TPPlugin) Priority() int {
	return 800
}
