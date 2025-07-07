package openvpn

import (
	"crypto/rand"
	"net"
	"reflect"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

const OPENVPN = "openvpn"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * Based on the original working OpenVPN plugin
	 * https://build.openvpn.net/doxygen/ssl__pkt_8h_source.html
	 * https://openvpn.net/community-resources/openvpn-protocol/
	 *
	 * Send CLIENT_RESET control message, expect back valid SERVER_RESET message from server
	 * Checks if SERVER_RESET opcode is received, along with whether remote session ID is contained in response
	 * NOTE: Does not work if tls-auth is enabled in OpenVPN config (drops connection due to HMAC error)
	 */

	var POpcodeShift uint8 = 3
	var PControlHardResetClientV2 uint8 = 7
	var PControlHardResetServerV2 uint8 = 8
	var SessionIDLength = 8

	InitialConnectionPackage := []byte{
		PControlHardResetClientV2 << POpcodeShift, // opcode/key_id
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID (64-bit),
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x0, // Message Packet-ID
	}
	_, err := rand.Read(
		InitialConnectionPackage[1 : 1+SessionIDLength],
	) // generate random session ID
	if err != nil {
		return nil, &utils.RandomizeError{Message: "session ID"}
	}

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check if response is valid OpenVPN packet
	if (response[0] >> POpcodeShift) == PControlHardResetServerV2 {
		for i := 0; i < len(response)-SessionIDLength; i++ {
			if reflect.DeepEqual(
				response[i:i+SessionIDLength],
				InitialConnectionPackage[1:1+SessionIDLength],
			) {
				// Create service result using ServiceOpenVPN struct
				serviceOpenVPN := plugins.ServiceOpenVPN{
					// Vendor information
					VendorName:        "OpenVPN",
					VendorProduct:     "OpenVPN Server",
					VendorVersion:     "2.0+",
					VendorConfidence:  95,
					VendorMethod:      "OpenVPN Protocol Detection",
					VendorDescription: "OpenVPN server detected via control packet exchange",

					// Basic OpenVPN information
					ResponseSize:     len(response),
					HandshakePattern: "CLIENT_RESET_SERVER_RESET",
					PacketStructure:  "OpenVPN_Control_Packet",
					SupportsAuth:     false, // tls-auth would block this detection
					OpcodeSequence:   []uint8{PControlHardResetServerV2},

					// Protocol information
					StandardPort:   1194,
					Transport:      "UDP",
					Encryption:     "OpenVPN",
					Authentication: []string{"None"}, // No auth detected via this method
					Compression:    []string{"Unknown"},
					SessionID:      "",
				}

				return plugins.CreateServiceFrom(target, serviceOpenVPN, false, "", plugins.UDP), nil
			}
		}
	}
	return nil, nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 1194 || port == 1723
}

func (p *Plugin) Name() string {
	return OPENVPN
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 580
}
