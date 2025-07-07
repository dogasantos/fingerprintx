package radius

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

const RADIUS = "radius"

// RADIUSPlugin implements the RADIUS detection plugin
type RADIUSPlugin struct{}

// VendorInfo represents detected RADIUS vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	ID          uint32
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// RADIUSFingerprint represents collected RADIUS fingerprinting data
type RADIUSFingerprint struct {
	AttributeCount           int
	AttributeTypes           []uint8
	VendorSpecificAttributes []VSAInfo
	StandardPorts            []int
	LegacyPorts              []int
	Transport                string
}

// VSAInfo represents Vendor-Specific Attribute information
type VSAInfo struct {
	VendorID   uint32
	VendorName string
	VendorType uint8
	DataLength int
}

var (
	commonRADIUSPorts = map[int]struct{}{
		1812: {}, // RADIUS Authentication
		1813: {}, // RADIUS Accounting
		1645: {}, // Legacy RADIUS Authentication
		1646: {}, // Legacy RADIUS Accounting
	}

	// Known RADIUS vendor IDs
	vendorIDs = map[uint32]string{
		9:     "Cisco",
		311:   "Microsoft",
		2636:  "Juniper",
		3076:  "Alteon",
		5842:  "Quintum",
		8164:  "Starent",
		10415: "Nokia",
		14179: "Airespace",
		25506: "H3C",
		26895: "Fortinet",
		35265: "Aruba",
	}
)

func init() {
	plugins.RegisterPlugin(&RADIUSPlugin{})
}

// Run performs RADIUS detection
func (p *RADIUSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Perform RADIUS detection
	fingerprint, err := p.performRADIUSDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	if fingerprint == nil {
		return nil, nil // Not RADIUS
	}

	// Create vendor information
	vendor := p.createVendorInfo(fingerprint)

	// Create service result using ServiceRADIUS struct
	serviceRADIUS := plugins.ServiceRADIUS{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorID:          vendor.ID,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// Attribute analysis
		AttributeCount: fingerprint.AttributeCount,
		AttributeTypes: fingerprint.AttributeTypes,

		// Vendor-Specific Attributes (VSAs)
		VendorSpecificAttributes: fingerprint.VendorSpecificAttributes,

		// Protocol information
		StandardPorts: fingerprint.StandardPorts,
		LegacyPorts:   fingerprint.LegacyPorts,
		Transport:     fingerprint.Transport,
	}

	service := plugins.CreateServiceFrom(target, serviceRADIUS, false, "", plugins.UDP)
	return service, nil
}

// performRADIUSDetection performs RADIUS protocol detection
func (p *RADIUSPlugin) performRADIUSDetection(conn net.Conn, timeout time.Duration) (*RADIUSFingerprint, error) {
	// Create RADIUS Access-Request packet
	radiusPacket := p.createRADIUSAccessRequest()

	// Send RADIUS packet
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(radiusPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to send RADIUS packet: %w", err)
	}

	// Read RADIUS response
	conn.SetReadDeadline(time.Now().Add(timeout))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read RADIUS response: %w", err)
	}

	// Parse RADIUS response
	fingerprint, err := p.parseRADIUSResponse(response[:n])
	if err != nil {
		return nil, err
	}

	// Set transport and port information
	fingerprint.Transport = "UDP"
	fingerprint.StandardPorts = []int{1812, 1813}
	fingerprint.LegacyPorts = []int{1645, 1646}

	return fingerprint, nil
}

// createRADIUSAccessRequest creates a RADIUS Access-Request packet
func (p *RADIUSPlugin) createRADIUSAccessRequest() []byte {
	var packet bytes.Buffer

	// RADIUS Header
	packet.WriteByte(1)                                // Code: Access-Request
	packet.WriteByte(1)                                // Identifier
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Length (will be updated)

	// Request Authenticator (16 bytes)
	authenticator := make([]byte, 16)
	for i := range authenticator {
		authenticator[i] = byte(i + 1) // Simple pattern
	}
	packet.Write(authenticator)

	// Add User-Name attribute
	p.addRADIUSAttribute(&packet, 1, []byte("test"))

	// Add User-Password attribute (encrypted with shared secret)
	p.addRADIUSAttribute(&packet, 2, []byte("test"))

	// Add NAS-IP-Address attribute
	p.addRADIUSAttribute(&packet, 4, []byte{192, 168, 1, 1})

	// Add NAS-Port attribute
	nasPort := make([]byte, 4)
	binary.BigEndian.PutUint32(nasPort, 1234)
	p.addRADIUSAttribute(&packet, 5, nasPort)

	// Add Service-Type attribute
	serviceType := make([]byte, 4)
	binary.BigEndian.PutUint32(serviceType, 2) // Framed-User
	p.addRADIUSAttribute(&packet, 6, serviceType)

	// Add Calling-Station-Id attribute
	p.addRADIUSAttribute(&packet, 31, []byte("00-11-22-33-44-55"))

	// Update packet length
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[2:4], uint16(len(packetBytes)))

	return packetBytes
}

// addRADIUSAttribute adds a RADIUS attribute to the packet
func (p *RADIUSPlugin) addRADIUSAttribute(packet *bytes.Buffer, attrType uint8, value []byte) {
	packet.WriteByte(attrType)              // Attribute Type
	packet.WriteByte(uint8(len(value) + 2)) // Attribute Length
	packet.Write(value)                     // Attribute Value
}

// parseRADIUSResponse parses a RADIUS response packet
func (p *RADIUSPlugin) parseRADIUSResponse(response []byte) (*RADIUSFingerprint, error) {
	if len(response) < 20 {
		return nil, fmt.Errorf("RADIUS response too short")
	}

	// Verify RADIUS header
	code := response[0]
	if code < 1 || code > 5 {
		return nil, fmt.Errorf("invalid RADIUS response code: %d", code)
	}

	length := binary.BigEndian.Uint16(response[2:4])
	if len(response) < int(length) {
		return nil, fmt.Errorf("incomplete RADIUS response")
	}

	fingerprint := &RADIUSFingerprint{
		VendorSpecificAttributes: []VSAInfo{},
		AttributeTypes:           []uint8{},
	}

	// Parse attributes
	offset := 20 // Skip RADIUS header
	for offset < int(length) {
		if offset+2 > len(response) {
			break
		}

		attrType := response[offset]
		attrLength := response[offset+1]

		if attrLength < 2 || offset+int(attrLength) > len(response) {
			break
		}

		fingerprint.AttributeTypes = append(fingerprint.AttributeTypes, attrType)
		fingerprint.AttributeCount++

		// Check for Vendor-Specific Attributes (Type 26)
		if attrType == 26 && attrLength >= 6 {
			vendorID := binary.BigEndian.Uint32(response[offset+2 : offset+6])
			vendorType := response[offset+6]
			vendorLength := response[offset+7]

			vsa := VSAInfo{
				VendorID:   vendorID,
				VendorType: vendorType,
				DataLength: int(vendorLength) - 2,
			}

			if vendorName, exists := vendorIDs[vendorID]; exists {
				vsa.VendorName = vendorName
			} else {
				vsa.VendorName = fmt.Sprintf("Unknown (%d)", vendorID)
			}

			fingerprint.VendorSpecificAttributes = append(fingerprint.VendorSpecificAttributes, vsa)
		}

		offset += int(attrLength)
	}

	return fingerprint, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *RADIUSPlugin) createVendorInfo(fingerprint *RADIUSFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "Unknown",
		Product:    "RADIUS Server",
		Confidence: 60,
		Method:     "RADIUS Protocol Analysis",
	}

	// Analyze VSAs for vendor detection
	vendorCounts := make(map[uint32]int)
	for _, vsa := range fingerprint.VendorSpecificAttributes {
		vendorCounts[vsa.VendorID]++
	}

	// Find most common vendor
	var maxCount int
	var primaryVendorID uint32
	for vendorID, count := range vendorCounts {
		if count > maxCount {
			maxCount = count
			primaryVendorID = vendorID
		}
	}

	if maxCount > 0 {
		if vendorName, exists := vendorIDs[primaryVendorID]; exists {
			vendor.Name = vendorName
			vendor.Product = fmt.Sprintf("%s RADIUS Server", vendorName)
			vendor.ID = primaryVendorID
			vendor.Confidence = 85
			vendor.Method = "Vendor-Specific Attribute Analysis"
			vendor.Description = fmt.Sprintf("Detected via %d VSAs from vendor ID %d", maxCount, primaryVendorID)
		}
	}

	// Enhance detection based on attribute patterns
	if len(fingerprint.AttributeTypes) > 10 {
		vendor.Confidence += 10
	}

	// Specific vendor detection patterns
	switch primaryVendorID {
	case 9: // Cisco
		vendor.Product = "Cisco RADIUS Server (ISE/ACS)"
		vendor.Version = "Detected via Cisco VSAs"
	case 311: // Microsoft
		vendor.Product = "Microsoft NPS/IAS"
		vendor.Version = "Windows RADIUS Server"
	case 26895: // Fortinet
		vendor.Product = "FortiAuthenticator"
		vendor.Version = "Fortinet RADIUS Server"
	case 35265: // Aruba
		vendor.Product = "Aruba ClearPass"
		vendor.Version = "Aruba RADIUS Server"
	}

	return vendor
}

// PortPriority returns true if the port is a common RADIUS port
func (p *RADIUSPlugin) PortPriority(port uint16) bool {
	_, exists := commonRADIUSPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *RADIUSPlugin) Name() string {
	return RADIUS
}

// Type returns the protocol type
func (p *RADIUSPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the plugin priority
func (p *RADIUSPlugin) Priority() int {
	return 600
}
