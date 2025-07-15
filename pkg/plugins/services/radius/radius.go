package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
)

type RADIUSPlugin struct{}

const RADIUS = "radius"

// VendorInfo represents detected RADIUS vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// RADIUSFingerprint represents collected RADIUS fingerprinting data
type RADIUSFingerprint struct {
	VendorSpecificAttributes []plugins.VSAInfo // Use plugins.VSAInfo type
	ResponseCode             uint8
	ResponseTime             time.Duration
	Attributes               map[uint8][]byte
	VendorConfidence         map[string]int
	DetectedVendors          []string
	AuthenticationMethods    []string
	SupportedPorts           []int
	AttributeCount           int
	AttributeTypes           []uint8
	VendorID                 uint32
}

var (
	commonRADIUSPorts = map[int]struct{}{
		1812: {}, // Authentication
		1813: {}, // Accounting
		1645: {}, // Legacy Authentication
		1646: {}, // Legacy Accounting
	}

	// Known RADIUS vendor IDs
	vendorIDs = map[uint32]string{
		9:     "Cisco",
		311:   "Microsoft",
		12356: "Fortinet",
		14823: "Aruba",
		3076:  "Alcatel-Lucent",
		2636:  "Juniper",
		25506: "H3C",
		2011:  "Huawei",
		10415: "Nokia",
		35265: "Ruckus",
	}
)

func init() {
	plugins.RegisterPlugin(&RADIUSPlugin{})
}

// getPortFromConnection extracts port number from connection
func getPortFromConnection(conn net.Conn) uint16 {
	addr := conn.RemoteAddr().String()
	parts := strings.Split(addr, ":")
	if len(parts) >= 2 {
		portStr := parts[len(parts)-1]
		if port, err := strconv.Atoi(portStr); err == nil {
			return uint16(port)
		}
	}
	return 0
}

// isValidRADIUSResponse validates if response is actually RADIUS
func (p *RADIUSPlugin) isValidRADIUSResponse(response []byte) bool {
	if len(response) < 20 {
		return false
	}

	// Check RADIUS code (must be 1-5 for valid RADIUS responses)
	code := response[0]
	if code < 1 || code > 5 {
		return false
	}

	// Check packet length consistency
	packetLength := binary.BigEndian.Uint16(response[2:4])
	if int(packetLength) != len(response) {
		return false
	}

	// Minimum RADIUS packet is 20 bytes (header only)
	if packetLength < 20 {
		return false
	}

	// Maximum reasonable RADIUS packet size
	if packetLength > 4096 {
		return false
	}

	// Validate attributes structure if present
	if len(response) > 20 {
		offset := 20
		for offset < len(response) {
			if offset+2 > len(response) {
				return false // Incomplete attribute header
			}

			attrType := response[offset]
			attrLen := response[offset+1]

			// Attribute length must be at least 2 (type + length)
			if attrLen < 2 {
				return false
			}

			// Attribute must not extend beyond packet
			if offset+int(attrLen) > len(response) {
				return false
			}

			// Check for valid attribute types (1-255, but some are reserved)
			if attrType == 0 {
				return false // Type 0 is invalid
			}

			offset += int(attrLen)
		}
	}

	return true
}

// Run performs RADIUS detection
func (p *RADIUSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Get port from connection and only run on standard RADIUS ports for conservative detection
	port := getPortFromConnection(conn)
	if !p.PortPriority(port) {
		return nil, nil
	}

	startTime := time.Now()

	// Perform RADIUS detection
	fingerprint, err := p.performRADIUSDetection(conn, timeout)
	if err != nil {
		return nil, nil // Return nil instead of error for failed detection
	}

	// If detection failed, this is not RADIUS
	if fingerprint == nil {
		return nil, nil
	}

	fingerprint.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(fingerprint)

	// Create service result using ServiceRADIUS struct with exact field names
	serviceRADIUS := plugins.ServiceRADIUS{
		// Vendor information (exact field names from types.go)
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorID:          fingerprint.VendorID,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// Attribute analysis (exact field names from types.go)
		AttributeCount: fingerprint.AttributeCount,
		AttributeTypes: fingerprint.AttributeTypes,

		// Vendor-Specific Attributes (exact field names from types.go)
		VendorSpecificAttributes: fingerprint.VendorSpecificAttributes, // Direct assignment - no conversion needed

		// Protocol information (exact field names from types.go)
		StandardPorts: []int{1812, 1813},
		LegacyPorts:   []int{1645, 1646},
		Transport:     "UDP",
	}

	service := plugins.CreateServiceFrom(target, serviceRADIUS, false, "", plugins.UDP)
	return service, nil
}

// performRADIUSDetection performs RADIUS protocol detection
func (p *RADIUSPlugin) performRADIUSDetection(conn net.Conn, timeout time.Duration) (*RADIUSFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Create RADIUS Access-Request packet
	packet := p.createAccessRequestPacket()

	// Send RADIUS packet
	_, err := conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send RADIUS packet: %w", err)
	}

	// Read RADIUS response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read RADIUS response: %w", err)
	}

	response = response[:n]

	// Strict RADIUS validation - this is the key fix
	if !p.isValidRADIUSResponse(response) {
		return nil, fmt.Errorf("response is not valid RADIUS")
	}

	// Parse RADIUS response
	fingerprint, err := p.parseRADIUSResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RADIUS response: %w", err)
	}

	// Analyze vendor-specific attributes
	p.analyzeVendorSpecificAttributes(fingerprint)

	// Set supported ports
	fingerprint.SupportedPorts = []int{1812, 1813, 1645, 1646}

	// Set authentication methods
	fingerprint.AuthenticationMethods = []string{"PAP", "CHAP", "EAP", "MS-CHAP"}

	return fingerprint, nil
}

// createAccessRequestPacket creates a RADIUS Access-Request packet
func (p *RADIUSPlugin) createAccessRequestPacket() []byte {
	var packet bytes.Buffer

	// RADIUS header
	packet.WriteByte(1)                                // Code: Access-Request
	packet.WriteByte(1)                                // Identifier
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Length (will be updated)

	// Request Authenticator (16 bytes)
	authenticator := make([]byte, 16)
	for i := range authenticator {
		authenticator[i] = byte(i + 1)
	}
	packet.Write(authenticator)

	// Add User-Name attribute
	p.addRADIUSAttribute(&packet, 1, []byte("test"))

	// Add User-Password attribute (encrypted)
	password := p.encryptPassword("test", authenticator)
	p.addRADIUSAttribute(&packet, 2, password)

	// Add NAS-IP-Address attribute
	p.addRADIUSAttribute(&packet, 4, []byte{192, 168, 1, 1})

	// Add Service-Type attribute
	p.addRADIUSAttribute(&packet, 6, []byte{0, 0, 0, 1}) // Login

	// Update packet length
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[2:4], uint16(len(packetBytes)))

	return packetBytes
}

// addRADIUSAttribute adds a RADIUS attribute to the packet
func (p *RADIUSPlugin) addRADIUSAttribute(packet *bytes.Buffer, attrType uint8, value []byte) {
	packet.WriteByte(attrType)
	packet.WriteByte(uint8(len(value) + 2))
	packet.Write(value)
}

// encryptPassword encrypts RADIUS password using MD5
func (p *RADIUSPlugin) encryptPassword(password string, authenticator []byte) []byte {
	secret := "testing123" // Standard test secret

	// Pad password to 16-byte boundary
	padded := []byte(password)
	for len(padded)%16 != 0 {
		padded = append(padded, 0)
	}

	// Encrypt password
	encrypted := make([]byte, len(padded))
	hash := md5.New()
	hash.Write([]byte(secret))
	hash.Write(authenticator)
	key := hash.Sum(nil)

	for i := 0; i < len(padded); i += 16 {
		for j := 0; j < 16; j++ {
			encrypted[i+j] = padded[i+j] ^ key[j]
		}
		if i+16 < len(padded) {
			hash.Reset()
			hash.Write([]byte(secret))
			hash.Write(encrypted[i : i+16])
			key = hash.Sum(nil)
		}
	}

	return encrypted
}

// parseRADIUSResponse parses RADIUS response packet
func (p *RADIUSPlugin) parseRADIUSResponse(response []byte) (*RADIUSFingerprint, error) {
	if len(response) < 20 {
		return nil, fmt.Errorf("RADIUS response too short")
	}

	fingerprint := &RADIUSFingerprint{
		VendorSpecificAttributes: []plugins.VSAInfo{}, // Initialize with plugins.VSAInfo
		Attributes:               make(map[uint8][]byte),
		VendorConfidence:         make(map[string]int),
		DetectedVendors:          []string{},
		AttributeTypes:           []uint8{},
	}

	// Parse RADIUS header
	fingerprint.ResponseCode = response[0]

	// Parse attributes
	offset := 20 // Skip RADIUS header
	for offset < len(response) {
		if offset+2 > len(response) {
			break
		}

		attrType := response[offset]
		attrLen := response[offset+1]

		if attrLen < 2 || offset+int(attrLen) > len(response) {
			break
		}

		attrValue := response[offset+2 : offset+int(attrLen)]
		fingerprint.Attributes[attrType] = attrValue
		fingerprint.AttributeTypes = append(fingerprint.AttributeTypes, attrType)
		fingerprint.AttributeCount++

		// Check for Vendor-Specific Attribute (type 26)
		if attrType == 26 && len(attrValue) >= 6 {
			vendorID := binary.BigEndian.Uint32(attrValue[0:4])
			vendorType := attrValue[4]
			vendorLength := attrValue[5]

			if vendorLength >= 2 && len(attrValue) >= int(vendorLength)+4 {
				vendorData := attrValue[6 : 4+int(vendorLength)]

				// Create plugins.VSAInfo with only the fields that exist
				vsa := plugins.VSAInfo{
					VendorID:   vendorID,
					VendorType: vendorType,
					DataLength: len(vendorData), // Set DataLength instead of Data
				}

				if vendorName, exists := vendorIDs[vendorID]; exists {
					vsa.VendorName = vendorName
					fingerprint.VendorID = vendorID // Set primary vendor ID
				}

				fingerprint.VendorSpecificAttributes = append(fingerprint.VendorSpecificAttributes, vsa)
			}
		}

		offset += int(attrLen)
	}

	return fingerprint, nil
}

// analyzeVendorSpecificAttributes analyzes VSAs for vendor identification
func (p *RADIUSPlugin) analyzeVendorSpecificAttributes(fingerprint *RADIUSFingerprint) {
	vendorCounts := make(map[string]int)

	for _, vsa := range fingerprint.VendorSpecificAttributes {
		if vsa.VendorName != "" {
			vendorCounts[vsa.VendorName]++
			fingerprint.VendorConfidence[vsa.VendorName] += 25
		}
	}

	// Determine detected vendors
	for vendor, count := range vendorCounts {
		if count > 0 {
			fingerprint.DetectedVendors = append(fingerprint.DetectedVendors, vendor)
		}
	}
}

// createVendorInfo creates vendor information based on detection results
func (p *RADIUSPlugin) createVendorInfo(fingerprint *RADIUSFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:        "Unknown",
		Product:     "RADIUS Server",
		Method:      "RADIUS Protocol Analysis",
		Description: "RADIUS server detected via protocol communication",
	}

	// Determine primary vendor
	maxConfidence := 0
	for vendorName, confidence := range fingerprint.VendorConfidence {
		if confidence > maxConfidence {
			maxConfidence = confidence
			vendor.Name = vendorName
			vendor.Confidence = confidence
		}
	}

	// Set vendor-specific product information
	switch vendor.Name {
	case "Cisco":
		vendor.Product = "Cisco RADIUS Server"
		vendor.Description = "Cisco RADIUS server with vendor-specific attributes"
	case "Microsoft":
		vendor.Product = "Microsoft NPS/IAS"
		vendor.Description = "Microsoft Network Policy Server or Internet Authentication Service"
	case "Fortinet":
		vendor.Product = "FortiAuthenticator"
		vendor.Description = "Fortinet RADIUS authentication server"
	case "Aruba":
		vendor.Product = "Aruba ClearPass"
		vendor.Description = "Aruba ClearPass Policy Manager"
	default:
		if len(fingerprint.DetectedVendors) > 0 {
			vendor.Name = fingerprint.DetectedVendors[0]
			vendor.Confidence = 50
		} else {
			vendor.Confidence = 30
		}
	}

	// Adjust confidence based on response
	if fingerprint.ResponseCode == 2 { // Access-Accept
		vendor.Confidence += 20
	} else if fingerprint.ResponseCode == 3 { // Access-Reject
		vendor.Confidence += 15
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
	return 650
}
