// nfs_plugin.go

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

package nfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type NFSPlugin struct{}

const NFS = "nfs"

// NFS Program and Version constants
const (
	ProgramID = 100003
	Version2  = 2
	Version3  = 3
	Version4  = 4
)

// Port mapper request structure
type PortMapperRequest struct {
	Program uint32
	Version uint32
	Proto   uint32
	Port    uint32
}

// Port mapper response structure
type PortMapperResponse struct {
	Port uint32
}

// NFS Procedure request structure
type NFSProcedureRequest struct {
	Credential [32]byte // Simplified; actual structure is more complex
	Verifier   [32]byte // Simplified; actual structure is more complex
}

// NFS Procedure response structure
type NFSProcedureResponse struct {
	Status uint32
}

func init() {
	plugins.RegisterPlugin(&NFSPlugin{})
}

func (p *NFSPlugin) PortPriority(port uint16) bool {
	return port == 2049
}

func DetectNFS(conn net.Conn, timeout time.Duration) (*plugins.ServiceNFS, error) {
	info := plugins.ServiceNFS{}

	// Port mapper request for NFS
	request := PortMapperRequest{
		Program: ProgramID,
		Version: Version3, // Start with Version 3
		Proto:   6,        // TCP protocol
		Port:    0,        // Port is not specified
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, request)
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, buf.Bytes(), timeout)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		return nil, err
	}

	if len(response) < 4 {
		return nil, nil
	}

	var portMapperResponse PortMapperResponse
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.BigEndian, &portMapperResponse)
	if err != nil {
		return nil, err
	}

	if portMapperResponse.Port != 0 {
		info.Version = Version3
		info.Port = portMapperResponse.Port
	} else {
		// Try NFS Version 2
		request.Version = Version2
		buf.Reset()
		err = binary.Write(&buf, binary.BigEndian, request)
		if err != nil {
			return nil, err
		}

		response, err := utils.SendRecv(conn, buf.Bytes(), timeout)
		if err != nil {
			return nil, err
		}

		if len(response) >= 4 {
			responseBuf = bytes.NewBuffer(response)
			err = binary.Read(responseBuf, binary.BigEndian, &portMapperResponse)
			if err == nil && portMapperResponse.Port != 0 {
				info.Version = Version2
				info.Port = portMapperResponse.Port
			}
		}
	}

	if info.Port == 0 {
		return nil, nil
	}

	// Additional metadata collection for supported procedures
	procedures, err := DetectSupportedProcedures(conn, timeout, info.Version)
	if err != nil {
		return nil, err
	}
	info.SupportedProcedures = procedures

	// Add policy detection if needed (example: checking for specific NFS policies)
	info.Policies = DetectNFSPolicies(conn, timeout)

	return &info, nil
}

func DetectSupportedProcedures(conn net.Conn, timeout time.Duration, version uint32) ([]string, error) {
	var procedures []string

	// Example procedure request for detecting NFS procedures
	request := NFSProcedureRequest{
		// Fill with appropriate credentials and verifiers
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, request)
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, buf.Bytes(), timeout)
	if err != nil {
		return nil, err
	}

	var procedureResponse NFSProcedureResponse
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.BigEndian, &procedureResponse)
	if err != nil {
		return nil, err
	}

	// Parse the response to extract supported procedures
	// Simplified example, actual implementation depends on the NFS version and details
	if procedureResponse.Status == 0 {
		procedures = append(procedures, "ProcedureX")
		// Add more procedures based on response parsing
	}

	return procedures, nil
}

func DetectNFSPolicies(conn net.Conn, timeout time.Duration) []string {
	var policies []string

	// Example policy detection (actual implementation depends on specific NFS policies)
	policies = append(policies, "Policy1")
	policies = append(policies, "Policy2")

	return policies
}

func (p *NFSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, err := DetectNFS(conn, timeout)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, info, false, fmt.Sprintf("NFSv%d", info.Version), plugins.TCP), nil
}

func (p *NFSPlugin) Name() string {
	return NFS
}

func (p *NFSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *NFSPlugin) Priority() int {
	return 310
}
