package epmd

import (
	"fmt"
	"net"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
	utils "github.com/vcore8/fingerprintx/pkg/plugins/pluginutils"
)

const EPMD = "epmd"

// EPMDPlugin defines the plugin structure
type EPMDPlugin struct{}

// Common ports for EPMD
var commonEPMDPorts = map[int]struct{}{
	4369: {}, // Default port for EPMD
}

// init function to register the plugin
func init() {
	plugins.RegisterPlugin(&EPMDPlugin{})
}

// DetectEPMD checks if the service is EPMD by sending a names command
func DetectEPMD(conn net.Conn, timeout time.Duration) (*plugins.ServiceEPMD, error) {
	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Send the EPMD names command: \x00\x01\x6e
	request := []byte{0x00, 0x01, 0x6e} // EPMD "names" command
	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, fmt.Errorf("error during EPMD response: %w", err)
	}

	// Validate the response format
	if len(response) >= 4 && response[0] == 0x00 {
		return &plugins.ServiceEPMD{
			Provider: "Erlang Port Mapper Daemon",
		}, nil
	}

	return nil, nil
}

// Run executes the EPMD detection logic
func (p *EPMDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Check for EPMD service
	serviceEPMD, err := DetectEPMD(conn, timeout)
	if err != nil {
		return nil, fmt.Errorf("error during EPMD detection: %w", err)
	}

	// If no EPMD service is detected, return nil
	if serviceEPMD == nil {
		return nil, nil
	}

	// Return the detected EPMD service
	return plugins.CreateServiceFrom(target, serviceEPMD, false, "", plugins.TCP), nil
}

// PortPriority prioritizes known EPMD ports
func (p *EPMDPlugin) PortPriority(port uint16) bool {
	_, ok := commonEPMDPorts[int(port)]
	return ok
}

// Name returns the name of the plugin
func (p *EPMDPlugin) Name() string {
	return EPMD
}

// Type specifies the protocol type handled by this plugin
func (p *EPMDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *EPMDPlugin) Priority() int {
	return 500
}
