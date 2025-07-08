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

// isDefinitiveL2TPResponse performs validation with debug logging
func isDefinitiveL2TPResponse(response []byte) bool {
	log.Printf("L2TP DEBUG: Response length: %d bytes", len(response))
	if len(response) > 0 {
		log.Printf("L2TP DEBUG: Response hex: %x", response)
	}

	if len(response) < 12 {
		log.Printf("L2TP DEBUG: Response too short (< 12 bytes)")
		return false
	}

	// Parse L2TP header
	flags := binary.BigEndian.Uint16(response[0:2])
	length := binary.BigEndian.Uint16(response[2:4])

	log.Printf("L2TP DEBUG: Flags: 0x%04x, Length: %d", flags, length)

	// Check version
	version := flags & 0x000F
	log.Printf("L2TP DEBUG: Version: %d", version)
	if version != 2 {
		log.Printf("L2TP DEBUG: Invalid version (not 2)")
		return false
	}

	// Check control message bit
	isControl := (flags & 0x8000) != 0
	log.Printf("L2TP DEBUG: Is control message: %t", isControl)
	if !isControl {
		log.Printf("L2TP DEBUG: Not a control message")
		return false
	}

	// Check length bit
	hasLength := (flags & 0x4000) != 0
	log.Printf("L2TP DEBUG: Has length field: %t", hasLength)
	if !hasLength {
		log.Printf("L2TP DEBUG: Length bit not set")
		return false
	}

	// Check sequence bit
	hasSequence := (flags & 0x0800) != 0
	log.Printf("L2TP DEBUG: Has sequence fields: %t", hasSequence)
	if !hasSequence {
		log.Printf("L2TP DEBUG: Sequence bit not set")
		return false
	}

	// Check length matches
	lengthMatches := int(length) == len(response)
	log.Printf("L2TP DEBUG: Length matches packet size: %t (%d vs %d)", lengthMatches, length, len(response))
	if !lengthMatches {
		log.Printf("L2TP DEBUG: Length field doesn't match packet size")
		return false
	}

	// Check for AVPs
	if len(response) <= 12 {
		log.Printf("L2TP DEBUG: No AVPs present")
		return false
	}

	// Try to parse first AVP
	avpValid := parseFirstAVP(response[12:])
	log.Printf("L2TP DEBUG: First AVP valid: %t", avpValid)

	return avpValid
}

// parseFirstAVP validates the first AVP structure with debug logging
func parseFirstAVP(avpData []byte) bool {
	log.Printf("L2TP DEBUG: AVP data length: %d", len(avpData))
	if len(avpData) < 6 {
		log.Printf("L2TP DEBUG: AVP data too short")
		return false
	}

	avpFlags := binary.BigEndian.Uint16(avpData[0:2])
	vendorID := binary.BigEndian.Uint16(avpData[2:4])
	avpLength := binary.BigEndian.Uint16(avpData[4:6])

	avpType := avpFlags & 0x3FFF
	mandatory := (avpFlags & 0x8000) != 0

	log.Printf("L2TP DEBUG: First AVP - Type: %d, Mandatory: %t, Vendor: %d, Length: %d",
		avpType, mandatory, vendorID, avpLength)

	// Basic validation
	if avpLength < 6 || int(avpLength) > len(avpData) {
		log.Printf("L2TP DEBUG: Invalid AVP length")
		return false
	}

	// For IETF AVPs, vendor ID should be 0
	if vendorID != 0 {
		log.Printf("L2TP DEBUG: Non-IETF vendor ID: %d", vendorID)
		// Don't reject, just log
	}

	// Accept any reasonable AVP type for first AVP
	log.Printf("L2TP DEBUG: First AVP type %d accepted", avpType)
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

// parseL2TPInfo extracts L2TP information and creates banner from validated response
func parseL2TPInfo(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	// Parse L2TP header
	flags := binary.BigEndian.Uint16(response[0:2])
	length := binary.BigEndian.Uint16(response[2:4])
	tunnelID := binary.BigEndian.Uint16(response[4:6])
	sessionID := binary.BigEndian.Uint16(response[6:8])

	version := flags & 0x000F
	info["L2TP_Version"] = fmt.Sprintf("%d", version)
	info["Packet_Length"] = fmt.Sprintf("%d", length)
	info["Tunnel_ID"] = fmt.Sprintf("%d", tunnelID)
	info["Session_ID"] = fmt.Sprintf("%d", sessionID)

	// Parse AVPs
	offset := 12
	hostName := ""
	vendorName := ""
	messageType := ""

	log.Printf("L2TP DEBUG: Parsing AVPs starting at offset %d", offset)

	for offset < len(response)-6 {
		// Parse AVP header
		avpFlags := binary.BigEndian.Uint16(response[offset : offset+2])
		binary.BigEndian.Uint16(response[offset+2 : offset+4]) // vendorID - read but not used
		avpLength := binary.BigEndian.Uint16(response[offset+4 : offset+6])

		avpType := avpFlags & 0x3FFF

		log.Printf("L2TP DEBUG: AVP at offset %d - Type: %d, Length: %d", offset, avpType, avpLength)

		if avpLength < 6 || offset+int(avpLength) > len(response) {
			log.Printf("L2TP DEBUG: Invalid AVP length, breaking")
			break
		}

		// Extract value
		if avpLength > 6 {
			valueBytes := response[offset+6 : offset+int(avpLength)]
			log.Printf("L2TP DEBUG: AVP %d value: %x", avpType, valueBytes)

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
					}
					info["Message_Type"] = messageType
					log.Printf("L2TP DEBUG: Message Type: %d (%s)", msgType, messageType)
				}
			case 7: // Host Name
				hostName = extractStringField(valueBytes)
				if hostName != "" {
					info["Host_Name"] = hostName
					log.Printf("L2TP DEBUG: Host Name: %s", hostName)
				}
			case 8: // Vendor Name
				vendorName = extractStringField(valueBytes)
				if vendorName != "" {
					info["Vendor_Name"] = vendorName
					log.Printf("L2TP DEBUG: Vendor Name: %s", vendorName)
				}
			}
		}

		offset += int(avpLength)
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

	log.Printf("L2TP DEBUG: Final banner: %s", productBanner)
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
	log.Printf("L2TP DEBUG: Starting L2TP detection for %s", target.Host)

	request := createL2TPSCCRQPacket()
	log.Printf("L2TP DEBUG: Sending SCCRQ packet (%d bytes): %x", len(request), request)

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		log.Printf("L2TP DEBUG: SendRecv error: %v", err)
		return nil, err
	}

	log.Printf("L2TP DEBUG: Received response (%d bytes)", len(response))

	if len(response) == 0 {
		log.Printf("L2TP DEBUG: Empty response")
		return nil, nil
	}

	// Only return positive detection if we're 100% certain it's L2TP
	if isDefinitiveL2TPResponse(response) {
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
