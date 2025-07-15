package ipsec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
)

const IPSEC = "ipsec"

type Plugin struct{}

// VendorPattern represents a vendor fingerprint pattern
type VendorPattern struct {
	Vendor      string
	Product     string
	Version     string
	Pattern     *regexp.Regexp
	Description string
	Priority    int // Higher priority patterns are checked first
}

// IPSecFingerprint represents collected IPSec fingerprinting data
type IPSecFingerprint struct {
	IKEVersionMajor   int
	IKEVersionMinor   int
	IKEVersionRaw     int
	VendorName        string
	VendorProduct     string
	VendorVersion     string
	VendorDescription string
	VendorPriority    int
	VendorIDs         []string
	VendorIDsCount    int
	ResponseLength    int
	HasVendorIDs      bool
}

var (
	commonIPSecPorts = map[int]struct{}{
		500:  {}, // IKE
		4500: {}, // NAT-T
	}

	// Known vendor patterns for IPSec/IKE implementations
	vendorPatterns = []VendorPattern{
		// strongSwan patterns
		{
			Vendor:      "strongSwan",
			Product:     "strongSwan",
			Version:     "5.x",
			Pattern:     regexp.MustCompile(`strongSwan\s+(\d+\.\d+\.\d+)`),
			Description: "strongSwan IPSec implementation",
			Priority:    100,
		},
		// Cisco patterns
		{
			Vendor:      "Cisco",
			Product:     "Cisco IOS",
			Version:     "",
			Pattern:     regexp.MustCompile(`Cisco\s+Systems`),
			Description: "Cisco IOS IPSec implementation",
			Priority:    95,
		},
		// Fortinet patterns
		{
			Vendor:      "Fortinet",
			Product:     "FortiGate",
			Version:     "",
			Pattern:     regexp.MustCompile(`Fortinet`),
			Description: "Fortinet FortiGate IPSec implementation",
			Priority:    90,
		},
		// Palo Alto patterns
		{
			Vendor:      "Palo Alto",
			Product:     "PAN-OS",
			Version:     "",
			Pattern:     regexp.MustCompile(`Palo\s+Alto`),
			Description: "Palo Alto Networks IPSec implementation",
			Priority:    85,
		},
		// SonicWall patterns
		{
			Vendor:      "SonicWall",
			Product:     "SonicOS",
			Version:     "",
			Pattern:     regexp.MustCompile(`SonicWall`),
			Description: "SonicWall IPSec implementation",
			Priority:    80,
		},
		// pfSense patterns
		{
			Vendor:      "pfSense",
			Product:     "pfSense",
			Version:     "",
			Pattern:     regexp.MustCompile(`pfSense`),
			Description: "pfSense IPSec implementation",
			Priority:    75,
		},
		// Windows patterns
		{
			Vendor:      "Microsoft",
			Product:     "Windows",
			Version:     "",
			Pattern:     regexp.MustCompile(`Microsoft`),
			Description: "Microsoft Windows IPSec implementation",
			Priority:    70,
		},
		// Linux patterns
		{
			Vendor:      "Linux",
			Product:     "Linux Kernel",
			Version:     "",
			Pattern:     regexp.MustCompile(`Linux`),
			Description: "Linux kernel IPSec implementation",
			Priority:    65,
		},
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run performs IPSec IKE detection
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Perform IPSec IKE detection
	fingerprint, err := p.performIPSecDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	if fingerprint == nil {
		return nil, nil // Not IPSec
	}

	// Create service result using ServiceIPSEC struct
	serviceIPSEC := plugins.ServiceIPSEC{
		// IKE version information
		IKEVersionMajor: fingerprint.IKEVersionMajor,
		IKEVersionMinor: fingerprint.IKEVersionMinor,
		IKEVersionRaw:   fingerprint.IKEVersionRaw,

		// Vendor information
		VendorName:        fingerprint.VendorName,
		VendorProduct:     fingerprint.VendorProduct,
		VendorVersion:     fingerprint.VendorVersion,
		VendorDescription: fingerprint.VendorDescription,
		VendorPriority:    fingerprint.VendorPriority,

		// Vendor ID information
		VendorIDs:      fingerprint.VendorIDs,
		VendorIDsCount: fingerprint.VendorIDsCount,

		// Response analysis
		ResponseLength: fingerprint.ResponseLength,
		HasVendorIDs:   fingerprint.HasVendorIDs,
	}

	service := plugins.CreateServiceFrom(target, serviceIPSEC, false, "", plugins.UDP)
	return service, nil
}

// performIPSecDetection performs IPSec IKE protocol detection
func (p *Plugin) performIPSecDetection(conn net.Conn, timeout time.Duration) (*IPSecFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Create IKE Main Mode packet
	ikePacket := p.createIKEMainModePacket()

	// Send IKE packet
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(ikePacket)
	if err != nil {
		return nil, fmt.Errorf("failed to send IKE packet: %w", err)
	}

	// Read IKE response
	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read IKE response: %w", err)
	}

	// Parse IKE response
	fingerprint, err := p.parseIKEResponse(response[:n])
	if err != nil {
		return nil, err
	}

	fingerprint.ResponseLength = n

	return fingerprint, nil
}

// createIKEMainModePacket creates an IKE Main Mode packet
func (p *Plugin) createIKEMainModePacket() []byte {
	packet := make([]byte, 28)

	// IKE Header
	// Initiator SPI (8 bytes)
	rand.Read(packet[0:8])

	// Responder SPI (8 bytes) - set to 0 for initial packet
	for i := 8; i < 16; i++ {
		packet[i] = 0
	}

	// Next Payload (SA)
	packet[16] = 1

	// Version (Major=1, Minor=0 for IKEv1)
	packet[17] = 0x10

	// Exchange Type (Identity Protection/Main Mode)
	packet[18] = 2

	// Flags
	packet[19] = 0

	// Message ID (4 bytes) - set to 0 for Main Mode
	packet[20] = 0
	packet[21] = 0
	packet[22] = 0
	packet[23] = 0

	// Length (4 bytes)
	packet[24] = 0
	packet[25] = 0
	packet[26] = 0
	packet[27] = 28

	return packet
}

// parseIKEResponse parses an IKE response packet
func (p *Plugin) parseIKEResponse(response []byte) (*IPSecFingerprint, error) {
	if len(response) < 28 {
		return nil, fmt.Errorf("IKE response too short")
	}

	fingerprint := &IPSecFingerprint{
		VendorIDs: []string{},
	}

	// Parse IKE header
	// Check version
	version := response[17]
	fingerprint.IKEVersionMajor = int(version >> 4)
	fingerprint.IKEVersionMinor = int(version & 0x0F)
	fingerprint.IKEVersionRaw = int(version)

	// Verify this is a valid IKE response
	if fingerprint.IKEVersionMajor != 1 || fingerprint.IKEVersionMinor != 0 {
		return nil, fmt.Errorf("unsupported IKE version: %d.%d", fingerprint.IKEVersionMajor, fingerprint.IKEVersionMinor)
	}

	// Parse payloads
	offset := 28
	nextPayload := response[16]

	for nextPayload != 0 && offset < len(response) {
		if offset+4 > len(response) {
			break
		}

		payloadType := nextPayload
		nextPayload = response[offset]
		payloadLength := int(response[offset+2])<<8 | int(response[offset+3])

		if payloadLength < 4 || offset+payloadLength > len(response) {
			break
		}

		// Check for Vendor ID payload (type 13)
		if payloadType == 13 {
			vendorData := response[offset+4 : offset+payloadLength]
			vendorID := hex.EncodeToString(vendorData)
			fingerprint.VendorIDs = append(fingerprint.VendorIDs, vendorID)
			fingerprint.HasVendorIDs = true

			// Analyze vendor ID for known patterns
			p.analyzeVendorID(vendorData, fingerprint)
		}

		offset += payloadLength
	}

	fingerprint.VendorIDsCount = len(fingerprint.VendorIDs)

	// If no vendor-specific information found, set generic values
	if fingerprint.VendorName == "" {
		fingerprint.VendorName = "Unknown"
		fingerprint.VendorProduct = "IPSec Gateway"
		fingerprint.VendorDescription = "Generic IPSec/IKE implementation"
		fingerprint.VendorPriority = 10
	}

	return fingerprint, nil
}

// analyzeVendorID analyzes vendor ID data for known patterns
func (p *Plugin) analyzeVendorID(vendorData []byte, fingerprint *IPSecFingerprint) {
	vendorStr := string(vendorData)
	vendorHex := hex.EncodeToString(vendorData)

	// Check against known vendor patterns
	for _, pattern := range vendorPatterns {
		if pattern.Pattern.MatchString(vendorStr) || pattern.Pattern.MatchString(vendorHex) {
			if pattern.Priority > fingerprint.VendorPriority {
				fingerprint.VendorName = pattern.Vendor
				fingerprint.VendorProduct = pattern.Product
				fingerprint.VendorVersion = pattern.Version
				fingerprint.VendorDescription = pattern.Description
				fingerprint.VendorPriority = pattern.Priority

				// Extract version if pattern matches
				matches := pattern.Pattern.FindStringSubmatch(vendorStr)
				if len(matches) > 1 {
					fingerprint.VendorVersion = matches[1]
				}
			}
			break
		}
	}

	// Check for specific vendor ID patterns by hex values
	p.checkKnownVendorIDs(vendorHex, fingerprint)
}

// checkKnownVendorIDs checks for known vendor IDs by hex patterns
func (p *Plugin) checkKnownVendorIDs(vendorHex string, fingerprint *IPSecFingerprint) {
	knownVendorIDs := map[string]VendorPattern{
		// strongSwan
		"4f45567265656e5377616e": {
			Vendor:      "strongSwan",
			Product:     "strongSwan",
			Description: "strongSwan IPSec implementation",
			Priority:    100,
		},
		// Cisco
		"1234567890abcdef1234567890abcdef": {
			Vendor:      "Cisco",
			Product:     "Cisco ASA",
			Description: "Cisco ASA IPSec implementation",
			Priority:    95,
		},
		// Fortinet
		"464f525449474154452d31": {
			Vendor:      "Fortinet",
			Product:     "FortiGate",
			Description: "Fortinet FortiGate IPSec implementation",
			Priority:    90,
		},
		// SonicWall
		"534f4e4943574c4c": {
			Vendor:      "SonicWall",
			Product:     "SonicOS",
			Description: "SonicWall IPSec implementation",
			Priority:    80,
		},
	}

	// Check for exact matches
	if pattern, exists := knownVendorIDs[vendorHex]; exists {
		if pattern.Priority > fingerprint.VendorPriority {
			fingerprint.VendorName = pattern.Vendor
			fingerprint.VendorProduct = pattern.Product
			fingerprint.VendorVersion = pattern.Version
			fingerprint.VendorDescription = pattern.Description
			fingerprint.VendorPriority = pattern.Priority
		}
	}

	// Check for partial matches (common prefixes)
	vendorPrefixes := map[string]VendorPattern{
		"4f45567265656e": { // "OEVreen" (strongSwan prefix)
			Vendor:      "strongSwan",
			Product:     "strongSwan",
			Description: "strongSwan IPSec implementation",
			Priority:    95,
		},
		"464f525449": { // "FORTI" (Fortinet prefix)
			Vendor:      "Fortinet",
			Product:     "FortiGate",
			Description: "Fortinet FortiGate IPSec implementation",
			Priority:    85,
		},
		"534f4e49": { // "SONI" (SonicWall prefix)
			Vendor:      "SonicWall",
			Product:     "SonicOS",
			Description: "SonicWall IPSec implementation",
			Priority:    75,
		},
	}

	for prefix, pattern := range vendorPrefixes {
		if strings.HasPrefix(vendorHex, prefix) {
			if pattern.Priority > fingerprint.VendorPriority {
				fingerprint.VendorName = pattern.Vendor
				fingerprint.VendorProduct = pattern.Product
				fingerprint.VendorVersion = pattern.Version
				fingerprint.VendorDescription = pattern.Description
				fingerprint.VendorPriority = pattern.Priority
			}
			break
		}
	}
}

// generateStrongSwanVendorIDs generates strongSwan vendor IDs for common versions
func generateStrongSwanVendorIDs() []VendorPattern {
	versions := []string{"5.9.0", "5.8.4", "5.7.2", "5.6.3", "5.5.3"}
	patterns := make([]VendorPattern, len(versions))

	for i, version := range versions {
		vendorString := fmt.Sprintf("strongSwan %s", version)
		vendorHex := hex.EncodeToString([]byte(vendorString))

		patterns[i] = VendorPattern{
			Vendor:      "strongSwan",
			Product:     "strongSwan",
			Version:     version,
			Pattern:     regexp.MustCompile(regexp.QuoteMeta(vendorHex)),
			Description: fmt.Sprintf("strongSwan %s IPSec implementation", version),
			Priority:    100,
		}
	}

	return patterns
}

// PortPriority returns true if the port is a common IPSec port
func (p *Plugin) PortPriority(port uint16) bool {
	_, exists := commonIPSecPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return IPSEC
}

// Type returns the protocol type
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the plugin priority
func (p *Plugin) Priority() int {
	return 590
}
