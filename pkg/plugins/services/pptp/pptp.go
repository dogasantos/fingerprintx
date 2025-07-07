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
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type PPTPPlugin struct{}

const PPTP = "pptp"

func init() {
	plugins.RegisterPlugin(&PPTPPlugin{})
}

/*
Point-to-Point Tunneling Protocol (PPTP) Detection - Conservative Approach

This plugin performs unauthenticated PPTP protocol fingerprinting by sending
a Start-Control-Connection-Request (SCCRQ) and only returns positive detection
when receiving a definitive PPTP response.

PPTP operates over TCP port 1723 for control messages and uses specific
message formats with a magic cookie (0x1A2B3C4D) for synchronization.

The plugin only reports PPTP when it receives:
- SCCRP (Start-Control-Connection-Reply) - server accepts connection
- Stop-Control-Connection-Request/Reply - server rejects connection
- Other valid PPTP control messages with proper header structure

This conservative approach ensures 100% accuracy in PPTP detection.

PPTP Control Message Header Format (RFC 2637):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Length               |      PPTP Message Type        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Magic Cookie                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Control Message Type      |           Reserved0           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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
		// Don't accept other message types as they might be ambiguous
		// SCCRQ would be unexpected as a response
		// Call management messages require established connection
		return false
	}
}

// parsePPTPInfo extracts PPTP information from validated response
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

	// Parse additional fields for SCCRP
	if ctrlMsgType == SCCRP && len(response) >= 20 {
		protocolVersion := binary.BigEndian.Uint16(response[12:14])
		info["Protocol_Version"] = fmt.Sprintf("0x%04X", protocolVersion)

		if len(response) >= 24 {
			framingCaps := binary.BigEndian.Uint32(response[16:20])
			bearerCaps := binary.BigEndian.Uint32(response[20:24])
			info["Framing_Capabilities"] = fmt.Sprintf("0x%08X", framingCaps)
			info["Bearer_Capabilities"] = fmt.Sprintf("0x%08X", bearerCaps)
		}
	}

	// Create conservative product banner
	productBanner := "pptp tunneling_protocol 1.0"

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
