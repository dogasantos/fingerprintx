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

	totalLength := packet.Len()
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:lengthPos+2], uint16(totalLength))

	return packetBytes
}

// createL2TPICRQPacket creates an Incoming-Call-Request packet (like Nmap uses)
func createL2TPICRQPacket() []byte {
	var packet bytes.Buffer

	flags := uint16(0xC802) // T=1, L=1, S=1, Ver=2
	binary.Write(&packet, binary.BigEndian, flags)

	lengthPos := packet.Len()
	binary.Write(&packet, binary.BigEndian, uint16(0))

	binary.Write(&packet, binary.BigEndian, uint16(1)) // Tunnel ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Session ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Ns
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Nr

	// Message Type AVP (Type 0, Value 9 for ICRQ)
	avp := createAVP(0, []byte{0x00, 0x09}, true)
	packet.Write(avp)

	// Assigned Session ID AVP (Type 14, Value 1)
	avp = createAVP(14, []byte{0x00, 0x01}, true)
	packet.Write(avp)

	// Call Serial Number AVP (Type 15, Value 1)
	avp = createAVP(15, []byte{0x00, 0x00, 0x00, 0x01}, true)
	packet.Write(avp)

	totalLength := packet.Len()
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:lengthPos+2], uint16(totalLength))

	return packetBytes
}

// createL2TPOCRQPacket creates an Outgoing-Call-Request packet
func createL2TPOCRQPacket() []byte {
	var packet bytes.Buffer

	flags := uint16(0xC802) // T=1, L=1, S=1, Ver=2
	binary.Write(&packet, binary.BigEndian, flags)

	lengthPos := packet.Len()
	binary.Write(&packet, binary.BigEndian, uint16(0))

	binary.Write(&packet, binary.BigEndian, uint16(1)) // Tunnel ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Session ID
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Ns
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Nr

	// Message Type AVP (Type 0, Value 7 for OCRQ)
	avp := createAVP(0, []byte{0x00, 0x07}, true)
	packet.Write(avp)

	// Assigned Session ID AVP (Type 14, Value 1)
	avp = createAVP(14, []byte{0x00, 0x01}, true)
	packet.Write(avp)

	// Call Serial Number AVP (Type 15, Value 1)
	avp = createAVP(15, []byte{0x00, 0x00, 0x00, 0x01}, true)
	packet.Write(avp)

	totalLength := packet.Len()
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:lengthPos+2], uint16(totalLength))

	return packetBytes
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
			log.Printf("L2TP DEBUG: Found L2TP header at offset %d: 0x%04x", i, flags)
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
			log.Printf("L2TP DEBUG: Found L2TP indicator: %s", indicator)
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

// parseL2TPResponse analyzes L2TP response and extracts information
func parseL2TPResponse(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))

	// Look for L2TP headers and extract information
	headerCount := 0
	messageTypes := make(map[string]int)

	for i := 0; i <= len(response)-12; i++ {
		flags := binary.BigEndian.Uint16(response[i : i+2])
		version := flags & 0x000F

		if version == 2 && (flags&0x8000) != 0 {
			headerCount++
			length := binary.BigEndian.Uint16(response[i+2 : i+4])
			tunnelID := binary.BigEndian.Uint16(response[i+4 : i+6])
			sessionID := binary.BigEndian.Uint16(response[i+6 : i+8])

			log.Printf("L2TP DEBUG: Header %d - Length: %d, Tunnel: %d, Session: %d",
				headerCount, length, tunnelID, sessionID)

			if headerCount == 1 {
				info["L2TP_Version"] = "2"
				info["Tunnel_ID"] = fmt.Sprintf("%d", tunnelID)
				info["Session_ID"] = fmt.Sprintf("%d", sessionID)
			}

			// Try to parse AVPs
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

	// Extract any readable text that might indicate vendor/error
	re := regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9\-\. ]{3,}`)
	matches := re.FindAll(response, -1)

	var textStrings []string
	for _, match := range matches {
		str := strings.TrimSpace(string(match))
		if len(str) > 3 {
			textStrings = append(textStrings, str)
		}
	}

	if len(textStrings) > 0 {
		info["Text_Content"] = strings.Join(textStrings, "; ")
	}

	// Create banner
	productBanner := "l2tp tunneling_protocol 2"

	// Check for specific error messages or vendor info
	responseStr := strings.ToLower(string(response))
	if strings.Contains(responseStr, "specify") && strings.Contains(responseStr, "tunnel") {
		productBanner = "l2tp server (tunnel_id_required)"
	} else if strings.Contains(responseStr, "mikrotik") {
		productBanner = "l2tp MikroTik RouterOS"
	} else if strings.Contains(responseStr, "cisco") {
		productBanner = "l2tp Cisco"
	} else if strings.Contains(responseStr, "microsoft") {
		productBanner = "l2tp Microsoft"
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

// tryL2TPProbes attempts various L2TP probe methods
func tryL2TPProbes(conn net.Conn, timeout time.Duration) []byte {
	probes := []struct {
		name string
		data []byte
	}{
		{"SCCRQ", createL2TPSCCRQPacket()},
		{"ICRQ", createL2TPICRQPacket()}, // This is what Nmap uses
		{"OCRQ", createL2TPOCRQPacket()},
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
	log.Printf("L2TP DEBUG: Starting L2TP detection with ICRQ support for %s", target.Host)

	// Try L2TP probes including ICRQ (like Nmap)
	response := tryL2TPProbes(conn, timeout)

	if len(response) == 0 {
		log.Printf("L2TP DEBUG: No response from any probe method")
		return nil, nil
	}

	// Check if response looks like L2TP
	if isL2TPResponse(response) {
		log.Printf("L2TP DEBUG: L2TP response detected")
		infoMap, productBanner := parseL2TPResponse(response)
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
