// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const DNS = "dns"

type UDPPlugin struct{}
type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
}

func CheckDNS(conn net.Conn, timeout time.Duration) (bool, string, error) {
	for attempts := 0; attempts < 3; attempts++ {
		transactionID := make([]byte, 2)
		_, err := rand.Read(transactionID)
		if err != nil {
			return false, "", &utils.RandomizeError{Message: "Transaction ID"}
		}

		InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
			// Transaction ID
			0x01, 0x00, // Flags: 0x0100 Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // Name: version.bind
			0x00, 0x10, // Type: TXT (Text strings) (16)
			0x00, 0x03, // Class: CH (0x0003)
		}...)

		if conn.RemoteAddr().Network() == "tcp" {
			InitialConnectionPackage = append([]byte{0x00, 0x1e}, InitialConnectionPackage...)
		}

		response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
		if err != nil {
			log.Printf("Error sending/receiving DNS query: %v", err)
			return false, "", err
		}

		if len(response) == 0 {
			log.Printf("Received empty response")
			return false, "", nil
		}

		if conn.RemoteAddr().Network() == "udp" {
			if !bytes.Equal(transactionID[0:1], response[0:1]) {
				log.Printf("Transaction ID mismatch for UDP response")
				return false, "", nil
			}
		}

		if conn.RemoteAddr().Network() == "tcp" {
			if !bytes.Equal(transactionID[0:1], response[2:3]) {
				log.Printf("Transaction ID mismatch for TCP response")
				return false, "", nil
			}
		}

		// Parse the response manually
		banner, err := parseDNSResponse(response)
		if err != nil {
			log.Printf("Error parsing DNS response: %v", err)
			return false, "", err
		}

		if banner != "" {
			return true, banner, nil
		}
	}

	return true, "", nil
}

func parseDNSResponse(response []byte) (string, error) {
	reader := bytes.NewReader(response)

	// Skip the header (12 bytes)
	if _, err := reader.Seek(12, 0); err != nil {
		return "", err
	}

	// Skip the question section (variable length)
	for {
		var length byte
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return "", err
		}

		if length == 0 {
			break
		}

		if _, err := reader.Seek(int64(length), 1); err != nil {
			return "", err
		}
	}

	// Skip the question type and class (4 bytes)
	if _, err := reader.Seek(4, 1); err != nil {
		return "", err
	}

	// Read the answer section
	var answerType uint16
	if err := binary.Read(reader, binary.BigEndian, &answerType); err != nil {
		return "", err
	}

	if answerType != 0x0010 { // Check if the answer type is TXT (0x0010)
		return "", nil
	}

	// Skip the answer class, TTL, and RDLength (8 bytes)
	if _, err := reader.Seek(8, 1); err != nil {
		return "", err
	}

	var rdLength uint16
	if err := binary.Read(reader, binary.BigEndian, &rdLength); err != nil {
		return "", err
	}

	txtData := make([]byte, rdLength)
	if _, err := reader.Read(txtData); err != nil {
		return "", err
	}

	return string(txtData[1:]), nil
}

func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, banner, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		return plugins.CreateServiceFrom(target, payload, false, banner, plugins.UDP), nil
	}

	return nil, nil
}

func (p *UDPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p UDPPlugin) Name() string {
	return DNS
}

func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, banner, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		return plugins.CreateServiceFrom(target, payload, false, banner, plugins.TCP), nil
	}

	return nil, nil
}

func (p TCPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p TCPPlugin) Name() string {
	return DNS
}

func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}
