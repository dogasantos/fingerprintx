package rmi

import (
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

const RMI = "java-rmi"

// RMIPlugin defines the plugin structure
type RMIPlugin struct{}

// init function to register the plugin
func init() {
	plugins.RegisterPlugin(&RMIPlugin{})
}

// PortPriority prioritizes common Java RMI port (1099)
func (p *RMIPlugin) PortPriority(port uint16) bool {
	return port == 1099
}

// Run executes the Java RMI detection logic
func (p *RMIPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {

	// Step 1: Perform handshake
	handshake := []byte{
		0x4A, 0x52, 0x4D, 0x49, // "JRMI" magic
		0x00, 0x02, // Version 2
		0x4B, // StreamProtocol
	}

	response, err := utils.SendRecv(conn, handshake, timeout)
	if err != nil || len(response) == 0 || response[0] != 0x4E {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, plugins.ServiceRMI{
		Provider: "Java RMI",
	}, false, "", plugins.TCP), nil
}

// Name returns the name of the plugin
func (p *RMIPlugin) Name() string {
	return RMI
}

// Type specifies the protocol type handled by this plugin
func (p *RMIPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *RMIPlugin) Priority() int {
	return 450
}
