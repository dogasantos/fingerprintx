package nfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
	utils "github.com/vcore8/fingerprintx/pkg/plugins/pluginutils"
)

type NFSPlugin struct{}

const (
	NFS            = "nfs"
	ProgramID      = 100003
	Version2       = 2
	Version3       = 3
	Version4       = 4
	MountProgramID = 100005
	MountProc3     = 3
	MountPort      = 111
)

type PortMapperRequest struct {
	Program uint32
	Version uint32
	Proto   uint32
	Port    uint32
}

type PortMapperResponse struct {
	Port uint32
}

type MountExport struct {
	DirPath  string
	HostList []string
}

func init() {
	plugins.RegisterPlugin(&NFSPlugin{})
}

func (p *NFSPlugin) PortPriority(port uint16) bool {
	return port == 2049
}

func DetectNFS(conn net.Conn, timeout time.Duration) (*plugins.ServiceNFS, error) {
	info := plugins.ServiceNFS{}

	// Get NFS version details
	versionDetails, err := GetNFSVersionDetails(conn, timeout)
	if err != nil {
		return nil, err
	}
	info.VersionDetails = versionDetails

	// Get NFS mount exports
	exports, err := GetNFSMountExports(conn, timeout)
	if err != nil {
		return nil, err
	}
	info.SharedContent = exports

	return &info, nil
}

func GetNFSVersionDetails(conn net.Conn, timeout time.Duration) (string, error) {
	var versions []string

	// Check NFS v2
	if checkNFSVersion(conn, timeout, Version2) {
		versions = append(versions, "NFSv2")
	}

	// Check NFS v3
	if checkNFSVersion(conn, timeout, Version3) {
		versions = append(versions, "NFSv3")
	}

	// Check NFS v4
	if checkNFSVersion(conn, timeout, Version4) {
		versions = append(versions, "NFSv4")
	}

	if len(versions) == 0 {
		return "", errors.New("no supported NFS versions detected")
	}

	return strings.Join(versions, ", "), nil
}

func checkNFSVersion(conn net.Conn, timeout time.Duration, version uint32) bool {
	request := PortMapperRequest{
		Program: ProgramID,
		Version: version,
		Proto:   6, // TCP
		Port:    0,
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, request)
	if err != nil {
		return false
	}

	response, err := utils.SendRecv(conn, buf.Bytes(), timeout)
	if err != nil {
		return false
	}

	if len(response) < 4 {
		return false
	}

	var portMapperResponse PortMapperResponse
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.BigEndian, &portMapperResponse)
	if err != nil {
		return false
	}

	return portMapperResponse.Port != 0
}

func GetNFSMountExports(conn net.Conn, timeout time.Duration) ([]string, error) {
	// Send port mapper request to get the mount port
	portMapperRequest := PortMapperRequest{
		Program: MountProgramID,
		Version: MountProc3,
		Proto:   6, // TCP
		Port:    0,
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, portMapperRequest)
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, buf.Bytes(), timeout)
	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, errors.New("invalid response length")
	}

	var portMapperResponse PortMapperResponse
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.BigEndian, &portMapperResponse)
	if err != nil {
		return nil, err
	}

	if portMapperResponse.Port == 0 {
		return nil, errors.New("failed to get mount port")
	}

	// Now, get the mount exports
	mountExports, err := FetchMountExports(conn.RemoteAddr().String(), portMapperResponse.Port, timeout)
	if err != nil {
		return nil, err
	}

	return mountExports, nil
}

func FetchMountExports(remoteAddr string, port uint32, timeout time.Duration) ([]string, error) {
	rpcMsg := struct {
		XID     uint32
		Message uint32
		Program uint32
		Version uint32
		Proc    uint32
		Cred    uint32
		Verf    uint32
	}{
		XID:     0x12345678, // Random transaction ID
		Message: 0,          // Call message
		Program: MountProgramID,
		Version: MountProc3,
		Proc:    1, // MOUNT_PROC_EXPORT (procedure to get export list)
		Cred:    0, // AUTH_NULL
		Verf:    0, // AUTH_NULL
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, rpcMsg)
	if err != nil {
		return nil, err
	}

	// Connect to the mount port
	mountConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", strings.Split(remoteAddr, ":")[0], port), timeout)
	if err != nil {
		return nil, err
	}
	defer mountConn.Close()

	// Sending the request to the mount daemon
	response, err := utils.SendRecv(mountConn, buf.Bytes(), timeout)
	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, errors.New("invalid response length")
	}

	// Parse the response to extract the export list
	var exports []string
	responseBuf := bytes.NewBuffer(response)
	for responseBuf.Len() > 0 {
		var export MountExport
		err := binary.Read(responseBuf, binary.BigEndian, &export)
		if err != nil {
			return nil, err
		}
		exports = append(exports, export.DirPath)
	}

	return exports, nil
}

func (p *NFSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, err := DetectNFS(conn, timeout)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, info, false, info.VersionDetails, plugins.TCP), nil
}

func (p *NFSPlugin) Name() string {
	return NFS
}

func (p *NFSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *NFSPlugin) Priority() int {
	return 1000 // High priority value to ensure it runs first
}
