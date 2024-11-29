package fgfmsd

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type FGFMSDPlugin struct{}

const FGFMSD = "fgfmsd"

var (
	commonFGFMSDPorts = map[int]struct{}{
		541: {}, // Standard port for Fortinet FGFMSD
	}
)

func init() {
	plugins.RegisterPlugin(&FGFMSDPlugin{})
}

// ExtractHumanReadableText parses a TLS ClientHello message to extract human-readable text
func ExtractHumanReadableText(response []byte) string {
	// Check for SNI (Server Name Indication)
	if len(response) > 0 {
		sniStart := bytes.Index(response, []byte("fortinet"))
		if sniStart != -1 {
			end := sniStart + bytes.IndexByte(response[sniStart:], 0)
			if end > sniStart {
				return string(response[sniStart:end])
			}
		}
	}
	return "Unknown"
}

// DetectFortinetVersion attempts to identify the Fortinet FGFMSD service
func DetectFortinetVersion(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.ServiceFGFMSD, error) {
	// Expected TLS prefix (from observed responses)
	const expectedTLSPrefix = "\x16\x03\x01"

	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Send a generic TLS ClientHello request
	request := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to send/receive: %w", err)
	}

	// Check if response is valid and contains the expected prefix
	if bytes.HasPrefix(response, []byte(expectedTLSPrefix)) {
		humanReadable := ExtractHumanReadableText(response)

		return &plugins.ServiceFGFMSD{
			String: humanReadable, // Human-readable extracted text
		}, nil
	}

	return nil, nil
}

// Run is the main execution function for the FGFMSDPlugin
func (p *FGFMSDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Validate the connection
	if conn == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	// Validate the target
	if target.Address.Port() == 0 {
		return nil, fmt.Errorf("invalid or uninitialized target address")
	}

	// Detect the FGFMSD service
	serviceMetadata, err := DetectFortinetVersion(conn, timeout, target)
	if err != nil {
		return nil, fmt.Errorf("error during FGFMSD detection: %w", err)
	}

	// Return a service object based on detection result
	if serviceMetadata != nil {
		return plugins.CreateServiceFrom(
			target,
			serviceMetadata,
			true,                           // TLS is used for FGFMSD
			"Fortinet FortiManager FGFMSD", // Version
			plugins.TCP,                    // Protocol type
		), nil
	}

	return nil, nil
}

// PortPriority prioritizes port 541 for this plugin
func (p *FGFMSDPlugin) PortPriority(port uint16) bool {
	_, ok := commonFGFMSDPorts[int(port)]
	return ok
}

// Name returns the plugin name
func (p *FGFMSDPlugin) Name() string {
	return FGFMSD
}

// Type specifies the protocol type handled by this plugin
func (p *FGFMSDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *FGFMSDPlugin) Priority() int {
	return 500
}
