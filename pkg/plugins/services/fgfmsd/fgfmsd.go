package fgfmsd

import (
	"bytes"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type FGFMSDPlugin struct{}

const FGFMSD = "fgfmsd"

var (
	// Port 541 is the standard port for Fortinet FGFMSD
	commonFGFMSDPorts = map[int]struct{}{
		541: {},
	}
)

// Register the plugin during initialization
func init() {
	plugins.RegisterPlugin(&FGFMSDPlugin{})
}

func DetectFortinetVersion(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	const expectedPrefix = "\x16\x03\x01"    // TLS handshake prefix
	const fortinetIdentifier = "fortinet-ca" // Identifier specific to Fortinet

	// Send a basic handshake request
	request := []byte{0x16, 0x01, 0x00, 0x00, 0x00} // Request
	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Check if the response contains the expected prefix and Fortinet identifier
	if bytes.HasPrefix(response, []byte(expectedPrefix)) && bytes.Contains(response, []byte(fortinetIdentifier)) {
		info := plugins.Service{
			IP:        target.Address.Addr().String(),
			Port:      int(target.Address.Port()),
			Protocol:  "tcp",
			TLS:       true,
			Transport: "tcp",
			Version:   "Fortinet FortiManager FGFMSD",
		}
		return &info, nil
	}

	return nil, nil
}

// Run is the main execution function of the plugin
func (p *FGFMSDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, err := DetectFortinetVersion(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If no specific version info is detected, create a generic service entry
	if info == nil {
		return plugins.CreateServiceFrom(target, nil, false, "", plugins.TCP), nil
	}

	// Return the service information detected for Fortinet
	return plugins.CreateServiceFrom(target, info, false, info.Version, plugins.TCP), nil
}

// PortPriority specifies that port 541 is prioritized for this plugin
func (p *FGFMSDPlugin) PortPriority(port uint16) bool {
	_, ok := commonFGFMSDPorts[int(port)]
	return ok
}

// Name returns the name of the plugin (FGFMSD)
func (p *FGFMSDPlugin) Name() string {
	return FGFMSD
}

// Type specifies that this plugin handles the TCP protocol
func (p *FGFMSDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority assigns a priority to this plugin
func (p *FGFMSDPlugin) Priority() int {
	return 500
}
