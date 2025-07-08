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

// createNmapL2TPICRQPacket creates the exact L2TP_ICRQ packet that Nmap uses
func createNmapL2TPICRQPacket() []byte {
	// This is the exact payload from nmap-payloads for L2TP_ICRQ
	hexStr := "c802003c000000000000000080080000000000018008000000020100800e000000076e78702d7363616e800a00000003000000038008000000090000"
	payload, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Printf("L2TP DEBUG: Error decoding Nmap payload: %v", err)
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

// parseL2TPResponse analyzes L2TP response and extracts information
func parseL2TPResponse(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))

	// Look for L2TP headers and extract information
	headerCount := 0
	messageTypes := make(map[string]int)
	hostName := ""
	vendorName := ""

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

	// Extract any readable text that might indicate vendor/error
	re := regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9\-\. ]{3,}`)
	matches := re.FindAll(response, -1)

	var textStrings []string
	for _, match := range matches {
		str := strings.TrimSpace(string(match))
		if len(str) > 3 {
			textStrings = append(textStrings, str)
			// Check for vendor indicators
			lowerStr := strings.ToLower(str)
			if strings.Contains(lowerStr, "mikrotik") {
				vendorName = "MikroTik"
			} else if strings.Contains(lowerStr, "cisco") {
				vendorName = "Cisco"
			} else if strings.Contains(lowerStr, "microsoft") {
				vendorName = "Microsoft"
			}
		}
	}

	if len(textStrings) > 0 {
		info["Text_Content"] = strings.Join(textStrings, "; ")
	}

	if hostName != "" {
		info["Host_Name"] = hostName
	}
	if vendorName != "" {
		info["Vendor_Name"] = vendorName
	}

	// Create banner
	productBanner := "l2tp tunneling_protocol 2"

	// Check for specific error messages or vendor info
	responseStr := strings.ToLower(string(response))
	if strings.Contains(responseStr, "specify") && strings.Contains(responseStr, "tunnel") {
		productBanner = "l2tp server (tunnel_id_required)"
	} else if vendorName == "MikroTik" {
		productBanner = "l2tp MikroTik RouterOS"
	} else if vendorName == "Cisco" {
		productBanner = "l2tp Cisco"
	} else if vendorName == "Microsoft" {
		productBanner = "l2tp Microsoft"
	} else if vendorName != "" {
		productBanner = fmt.Sprintf("l2tp %s", vendorName)
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
	log.Printf("L2TP DEBUG: Starting L2TP detection using exact Nmap L2TP_ICRQ payload for %s", target.Host)

	// Use the exact same payload that Nmap uses
	nmapPayload := createNmapL2TPICRQPacket()
	if nmapPayload == nil {
		log.Printf("L2TP DEBUG: Failed to create Nmap payload")
		return nil, nil
	}

	log.Printf("L2TP DEBUG: Sending Nmap L2TP_ICRQ payload (%d bytes): %x", len(nmapPayload), nmapPayload)

	response, err := utils.SendRecv(conn, nmapPayload, timeout)
	if err != nil {
		log.Printf("L2TP DEBUG: Error sending Nmap payload: %v", err)
		return nil, nil
	}

	log.Printf("L2TP DEBUG: Nmap payload response (%d bytes)", len(response))
	if len(response) > 0 {
		log.Printf("L2TP DEBUG: Response hex: %x", response)
		log.Printf("L2TP DEBUG: Response ascii: %q", response)
	}

	if len(response) == 0 {
		log.Printf("L2TP DEBUG: No response from Nmap L2TP_ICRQ payload")
		return nil, nil
	}

	// Check if response looks like L2TP
	if isL2TPResponse(response) {
		log.Printf("L2TP DEBUG: L2TP response detected using Nmap payload")
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
