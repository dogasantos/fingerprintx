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
	flags := uint16(0xC802) // T=1, L=1, S=1, Ver=2
	binary.Write(&packet, binary.BigEndian, flags)

	lengthPos := packet.Len()
	binary.Write(&packet, binary.BigEndian, uint16(0))

	binary.Write(&packet, binary.BigEndian, uint16(0)) // Tunnel ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Session ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Ns
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Nr

	// Message Type AVP (Type 0, Value 1 for SCCRQ)
	avp := createAVP(0, []byte{0x00, 0x01}, true)
	packet.Write(avp)

	// Protocol Version AVP (Type 2, Value 0x0100)
	avp = createAVP(2, []byte{0x01, 0x00}, true)
	packet.Write(avp)

	// Host Name AVP (Type 7)
	hostname := "probe"
	avp = createAVP(7, []byte(hostname), true)
	packet.Write(avp)

	// Assigned Tunnel ID AVP (Type 9, Value 1)
	avp = createAVP(9, []byte{0x00, 0x01}, true)
	packet.Write(avp)

	// Update length field
	totalLength := packet.Len()
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:lengthPos+2], uint16(totalLength))

	return packetBytes
}

// createMalformedL2TPPacket creates various malformed packets to trigger responses
func createMalformedL2TPPacket(variant int) []byte {
	var packet bytes.Buffer

	switch variant {
	case 1: // Wrong version
		flags := uint16(0xC801) // Version 1 instead of 2
		binary.Write(&packet, binary.BigEndian, flags)
		binary.Write(&packet, binary.BigEndian, uint16(12))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))

	case 2: // Invalid length
		flags := uint16(0xC802)
		binary.Write(&packet, binary.BigEndian, flags)
		binary.Write(&packet, binary.BigEndian, uint16(999)) // Wrong length
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))

	case 3: // Invalid tunnel ID
		flags := uint16(0xC802)
		binary.Write(&packet, binary.BigEndian, flags)
		binary.Write(&packet, binary.BigEndian, uint16(12))
		binary.Write(&packet, binary.BigEndian, uint16(65535)) // Invalid tunnel ID
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))

	case 4: // Just L2TP magic bytes
		packet.Write([]byte{0xC8, 0x02})

	case 5: // Random data that might trigger response
		packet.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})

	default: // Minimal valid header
		flags := uint16(0xC802)
		binary.Write(&packet, binary.BigEndian, flags)
		binary.Write(&packet, binary.BigEndian, uint16(12))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
		binary.Write(&packet, binary.BigEndian, uint16(0))
	}

	return packet.Bytes()
}

// createAVP creates an Attribute Value Pair
func createAVP(avpType uint16, value []byte, mandatory bool) []byte {
	var avp bytes.Buffer

	flags := avpType
	if mandatory {
		flags |= 0x8000
	}

	length := uint16(6 + len(value))

	binary.Write(&avp, binary.BigEndian, flags)
	binary.Write(&avp, binary.BigEndian, uint16(0)) // Vendor ID
	binary.Write(&avp, binary.BigEndian, length)
	avp.Write(value)

	return avp.Bytes()
}

// isAnyL2TPResponse checks if response could be L2TP-related
func isAnyL2TPResponse(response []byte) bool {
	if len(response) < 2 {
		return false
	}

	// Check for L2TP-like patterns
	// Look for version 2 in any position
	for i := 0; i < len(response)-1; i++ {
		flags := binary.BigEndian.Uint16(response[i : i+2])
		version := flags & 0x000F
		if version == 2 {
			// Check if control bit is set
			if (flags & 0x8000) != 0 {
				log.Printf("L2TP DEBUG: Found L2TP-like pattern at offset %d: 0x%04x", i, flags)
				return true
			}
		}
	}

	// Look for common L2TP error patterns or strings
	responseStr := strings.ToLower(string(response))
	l2tpIndicators := []string{"l2tp", "tunnel", "ppp", "lac", "lns"}

	for _, indicator := range l2tpIndicators {
		if strings.Contains(responseStr, indicator) {
			log.Printf("L2TP DEBUG: Found L2TP indicator string: %s", indicator)
			return true
		}
	}

	return false
}

// extractStringField extracts null-terminated string from byte array
func extractStringField(data []byte) string {
	nullIndex := bytes.IndexByte(data, 0)
	if nullIndex == -1 {
		nullIndex = len(data)
	}

	str := string(data[:nullIndex])
	str = strings.TrimSpace(str)

	re := regexp.MustCompile(`[^\x20-\x7E]`)
	str = re.ReplaceAllString(str, "")

	return str
}

// identifyVendorFromString attempts to identify vendor from strings
func identifyVendorFromString(hostName, vendorName string) string {
	combined := strings.ToLower(hostName + " " + vendorName)

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

	if vendorName != "" {
		return vendorName
	}

	return "Unknown"
}

// parseL2TPInfo extracts information from any L2TP-like response
func parseL2TPInfo(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))
	info["Response_Hex"] = fmt.Sprintf("%x", response)

	// Try to find L2TP header patterns
	for i := 0; i < len(response)-1; i++ {
		flags := binary.BigEndian.Uint16(response[i : i+2])
		version := flags & 0x000F
		if version == 2 && (flags&0x8000) != 0 {
			info["L2TP_Version"] = "2"
			info["L2TP_Flags"] = fmt.Sprintf("0x%04x", flags)
			break
		}
	}

	// Look for printable strings that might indicate vendor
	hostName := ""
	vendorName := ""

	// Extract any printable strings
	re := regexp.MustCompile(`[a-zA-Z0-9\-\. ]{4,}`)
	matches := re.FindAll(response, -1)
	for _, match := range matches {
		str := string(match)
		str = strings.TrimSpace(str)
		if len(str) > 3 {
			if strings.Contains(strings.ToLower(str), "mikrotik") {
				vendorName = "MikroTik"
			} else if hostName == "" {
				hostName = str
			}
		}
	}

	if hostName != "" {
		info["Host_Name"] = hostName
	}
	if vendorName != "" {
		info["Vendor_Name"] = vendorName
	}

	// Create banner
	productBanner := "l2tp tunneling_protocol 2"

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

// tryAllL2TPProbes attempts various probe methods
func tryAllL2TPProbes(conn net.Conn, timeout time.Duration) []byte {
	probes := []struct {
		name string
		data []byte
	}{
		{"SCCRQ", createL2TPSCCRQPacket()},
		{"Malformed_V1", createMalformedL2TPPacket(1)},
		{"Malformed_Len", createMalformedL2TPPacket(2)},
		{"Malformed_TID", createMalformedL2TPPacket(3)},
		{"Magic_Bytes", createMalformedL2TPPacket(4)},
		{"Random_Data", createMalformedL2TPPacket(5)},
		{"Minimal", createMalformedL2TPPacket(0)},
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
			log.Printf("L2TP DEBUG: %s response ascii: %q", probe.name, response)
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
	log.Printf("L2TP DEBUG: Starting passive L2TP detection for %s", target.Host)

	// Try all probe methods including malformed packets
	response := tryAllL2TPProbes(conn, timeout)

	if len(response) == 0 {
		log.Printf("L2TP DEBUG: No response from any probe method")
		return nil, nil
	}

	// Use very permissive validation
	if isAnyL2TPResponse(response) {
		log.Printf("L2TP DEBUG: L2TP-like response detected")
		infoMap, productBanner := parseL2TPInfo(response)
		l2tpInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServiceL2TP{
			Info:    l2tpInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	log.Printf("L2TP DEBUG: Response not recognized as L2TP-related")
	return nil, nil
}

func (p *L2TPPlugin) Priority() int {
	return 800
}
