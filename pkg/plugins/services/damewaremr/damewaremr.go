package damewaremr

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type DameWareMRPlugin struct{}

const DamewareMR = "damewaremr"

var (
	commonDamewarePorts = map[int]struct{}{
		6129: {}, // Standard port for DameWare Mini Remote Control
	}
)

func init() {
	plugins.RegisterPlugin(&DameWareMRPlugin{})
}

// DetectDameware attempts to identify the DameWare Mini Remote Control service
func DetectDameware(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.ServiceDameware, error) {
	// Regular expression from Nmap match
	regex := regexp.MustCompile(`^0\x11\0\0.{11}@.{9}\0\0\0\x01\0\0\0\0\0\0\0.\0\0\0$`)

	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Read the response from the server
	buffer := make([]byte, 4096) // Adjust buffer size if needed
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Apply the regex to the response
	if regex.Match(buffer[:n]) {
		//fmt.Println("Match found for DameWare Mini Remote Control service!")
		/*
			return &plugins.ServiceDameware{
				Banner: string(buffer[:n]), // Capture the banner for analysis
			}, nil
		*/
		return &plugins.ServiceDameware{}, nil
	}

	// Log that no match was found
	//fmt.Println("No match for DameWare Mini Remote Control service")
	return nil, nil
}

// Run is the main execution function for the DameWareMRPlugin
func (p *DameWareMRPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Validate the connection
	if conn == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	// Validate the target
	if target.Address == (plugins.Target{}.Address) {
		return nil, fmt.Errorf("invalid or uninitialized target address")
	}

	//fmt.Println("Running Dameware detection...")

	// Detect the Dameware service
	serviceMetadata, err := DetectDameware(conn, timeout, target)
	if err != nil {
		return nil, fmt.Errorf("error during Dameware detection: %w", err)
	}

	// If detection succeeded, create and return the service
	if serviceMetadata != nil {
		return plugins.CreateServiceFrom(
			target,
			serviceMetadata,
			false, // TLS not used
			"SolarWinds DameWare Mini Remote Control", // Version
			plugins.TCP, // Protocol type
		), nil
	}

	// Return nil if no match was found
	return nil, nil
}

// PortPriority prioritizes port 6129 for this plugin
func (p *DameWareMRPlugin) PortPriority(port uint16) bool {
	_, ok := commonDamewarePorts[int(port)]
	return ok
}

// Name returns the plugin name
func (p *DameWareMRPlugin) Name() string {
	return DamewareMR
}

// Type specifies the protocol type handled by this plugin
func (p *DameWareMRPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *DameWareMRPlugin) Priority() int {
	return 500
}
