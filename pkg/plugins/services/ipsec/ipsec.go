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

package ipsec

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

const IPSEC = "IPsec"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (f *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	initiator := make([]byte, 8)
	_, err := rand.Read(initiator)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "initiator SPI"}
	}
	InitialConnectionPackage := append(initiator, []byte{ //nolint:gocritic
		// 8 bit Initiator SPI
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Responder SPI
		0x01, 0x10, // Version: 1.0
		0x02, // Exchange type
		0x00,
		0x00, 0x00, 0x00, 0x00, // ID
		0x00, 0x00, 0x01, 0x50, // Message Length
		0x00, 0x00, 0x01, 0x34, // Payload Length
		0x00, 0x00, 0x00, 0x01, // Domain of interpretation: IPSEC (1)
		0x00, 0x00, 0x00, 0x01, // Situation: identity only
		0x00, 0x00, 0x01, 0x28, // Payload Length
		0x01,       // Proposal number: 1
		0x01,       // Protocol ID: ISAKMP (1)
		0x00, 0x08, // Proposal transforms: 8

		// SHA 3DES-CBC 1024 bit
		0x03, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x02,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// MD5 3DES-CBC 1024 bit
		0x03, 0x00, 0x00, 0x24, 0x02, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x01,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// SHA DES-CBC 1024 bit
		0x03, 0x00, 0x00, 0x24, 0x03, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x01, 0x80, 0x02, 0x00, 0x02,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// MD5 3DES-CBC 1024 bit
		0x03, 0x00, 0x00, 0x24, 0x04, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x01, 0x80, 0x02, 0x00, 0x01,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// SHA 3DES-CBC 768 bit
		0x03, 0x00, 0x00, 0x24, 0x05, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x02,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// MD5 3DES-CBC 768 bit
		0x03, 0x00, 0x00, 0x24, 0x06, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x01,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// SHA DES-CBC 1024 bit
		0x03, 0x00, 0x00, 0x24, 0x07, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x01, 0x80, 0x02, 0x00, 0x02,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,

		// MD5 3DES-CBC 1024 bit
		0x00, 0x00, 0x00, 0x24, 0x08, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x01, 0x80, 0x02, 0x00, 0x01,
		0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x01, 0x80, 0x0b, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x04,
		0x00, 0x00, 0x70, 0x80,
	}...)

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	responderISP := hex.EncodeToString(response[8:16])
	messageID := hex.EncodeToString(response[20:24])
	if bytes.Equal(initiator, response[0:8]) {
		payload := plugins.ServiceIPSEC{
			ResponderISP: responderISP,
			MessageID:    messageID,
		}

		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}
	return nil, nil
}

func (f *Plugin) PortPriority(i uint16) bool {
	return i == 500
}

func (f *Plugin) Name() string {
	return IPSEC
}

func (f *Plugin) Priority() int {
	return 198
}

func (f *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}
