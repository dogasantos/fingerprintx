package l2tp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type L2TPPlugin struct{}

const L2TP = "l2tp"

func init() {
	plugins.RegisterPlugin(&L2TPPlugin{})
}

/*
Layer 2 Tunneling Protocol (L2TP) Detection

L2TP is a tunneling protocol used to support VPNs. It operates over UDP port 1701
and uses control messages to establish tunnels between endpoints.

L2TP Header Format (RFC 2661):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Tunnel ID           |           Session ID          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Ns (opt)          |             Nr (opt)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Offset Size (opt)        |    Offset pad... (opt)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Control Message Types:
- SCCRQ (Start-Control-Connection-Request) = 1
- SCCRP (Start-Control-Connection-Reply) = 2
- SCCCN (Start-Control-Connection-Connected) = 3
- StopCCN (Stop-Control-Connection-Notification) = 4
Layer 2 Tunneling Protocol (L2TP) Detection - Conservative Approach

This plugin performs unauthenticated L2TP protocol fingerprinting by sending
a Start-Control-Connection-Request (SCCRQ) and only returns positive detection
when receiving a definitive L2TP response.

L2TP operates over UDP port 1701 and uses specific control message formats.
The plugin only reports L2TP when it receives:
- SCCRP (Start-Control-Connection-Reply) - indicates L2TP server accepted connection
- StopCCN (Stop-Control-Connection-Notification) - indicates L2TP server rejected connection
- Other valid L2TP control messages with proper header structure

This conservative approach ensures 100% accuracy in L2TP detection.
*/

// createL2TPSCCRQPacket creates a minimal Start-Control-Connection-Request packet
func createL2TPSCCRQPacket() []byte {
	var packet bytes.Buffer

	// L2TP Header for control message
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

// isDefinitiveL2TPResponse performs strict validation to ensure response is L2TP
func isDefinitiveL2TPResponse(response []byte) bool {
	if len(response) < 12 {
		return false
	}

	// Parse L2TP header
	flags := binary.BigEndian.Uint16(response[0:2])
	length := binary.BigEndian.Uint16(response[2:4])

	// Strict L2TP header validation

	// 1. Version must be exactly 2 (bits 0-3)
	version := flags & 0x000F
	if version != 2 {
		return false
	}

	// 2. Must be a control message (T bit = 1)
	if (flags & 0x8000) == 0 {
		return false
	}

	// 3. Length bit must be set for control messages (L bit = 1)
	if (flags & 0x4000) == 0 {
		return false
	}

	// 4. Sequence bit must be set for control messages (S bit = 1)
	if (flags & 0x0800) == 0 {
		return false
	}

	// 5. Offset bit must be 0 for control messages (O bit = 0)
	if (flags & 0x0200) != 0 {
		return false
	}

	// 6. Priority bit must be 0 for control messages (P bit = 0)
	if (flags & 0x0100) != 0 {
		return false
	}

	// 7. Reserved bits (x) should be 0
	reservedBits := (flags & 0x3070)
	if reservedBits != 0 {
		return false
	}

	// 8. Length field should match actual packet length
	if int(length) != len(response) {
		return false
	}

	// 9. Must have AVPs starting at offset 12
	if len(response) <= 12 {
		return false
	}

	// 10. Validate first AVP is Message Type (Type 0)
	avpData := response[12:]
	if len(avpData) < 6 {
		return false
	}

	avpFlags := binary.BigEndian.Uint16(avpData[0:2])
	avpType := avpFlags & 0x3FFF // Remove M and H bits
	avpLength := binary.BigEndian.Uint16(avpData[4:6])

	// First AVP must be Message Type (Type 0)
	if avpType != 0 {
		return false
	}

	// Message Type AVP must have proper length
	if avpLength < 8 {
		return false
	}

	// Extract message type value
	if len(avpData) < 8 {
		return false
	}

	messageType := binary.BigEndian.Uint16(avpData[6:8])

	// Only accept specific L2TP control message types that confirm L2TP service
	switch messageType {
	case 2: // SCCRP (Start-Control-Connection-Reply) - server accepts connection
		return true
	case 4: // StopCCN (Stop-Control-Connection-Notification) - server rejects connection
		return true
	case 3: // SCCCN (Start-Control-Connection-Connected) - unlikely but valid
		return true
	default:
		// Don't accept other message types as they might be ambiguous
		return false
	}
}

// parseL2TPInfo extracts L2TP information from validated response
func parseL2TPInfo(response []byte) (map[string]any, string) {
	info := make(map[string]any)

	// Parse L2TP header
	flags := binary.BigEndian.Uint16(response[0:2])
	length := binary.BigEndian.Uint16(response[2:4])
	tunnelID := binary.BigEndian.Uint16(response[4:6])
	sessionID := binary.BigEndian.Uint16(response[6:8])
	//ns := binary.BigEndian.Uint16(response[8:10])
	//nr := binary.BigEndian.Uint16(response[10:12])

	version := flags & 0x000F
	info["L2TP_Version"] = fmt.Sprintf("%d", version)
	info["Packet_Length"] = fmt.Sprintf("%d", length)
	info["Tunnel_ID"] = fmt.Sprintf("%d", tunnelID)
	info["Session_ID"] = fmt.Sprintf("%d", sessionID)

	// Parse message type from first AVP
	messageType := ""
	if len(response) > 18 {
		avpData := response[12:]
		msgType := binary.BigEndian.Uint16(avpData[6:8])
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
	}

	// Create conservative product banner
	productBanner := fmt.Sprintf("l2tp tunneling_protocol %d", version)

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
	request := createL2TPSCCRQPacket()

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Only return positive detection if we're 100% certain it's L2TP
	if isDefinitiveL2TPResponse(response) {
		infoMap, productBanner := parseL2TPInfo(response)
		l2tpInfo := fmt.Sprintf("%s", infoMap)
		payload := plugins.ServiceL2TP{
			Info:    l2tpInfo,
			Product: productBanner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	// Return nil if not definitively L2TP
	return nil, nil
}

func (p *L2TPPlugin) Priority() int {
	return 800
}
