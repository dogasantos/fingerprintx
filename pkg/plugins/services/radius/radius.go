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

package radius

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const RADIUS = "RADIUS"

type Plugin struct{}

// VendorInfo represents detected vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	VendorID    uint32
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// RADIUSAttribute represents a RADIUS attribute
type RADIUSAttribute struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// VendorSpecificAttribute represents a VSA (Attribute 26)
type VendorSpecificAttribute struct {
	VendorID   uint32
	VendorType uint8
	VendorData []byte
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Known vendor IDs and their characteristics
var knownVendors = map[uint32]VendorInfo{
	9: {
		Name:        "Cisco",
		Product:     "ISE/ACS",
		VendorID:    9,
		Confidence:  90,
		Description: "Cisco RADIUS Server (ISE/ACS)",
	},
	311: {
		Name:        "Microsoft",
		Product:     "NPS",
		VendorID:    311,
		Confidence:  95,
		Description: "Microsoft Network Policy Server",
	},
	529: {
		Name:        "Ascend",
		Product:     "RADIUS",
		VendorID:    529,
		Confidence:  85,
		Description: "Ascend RADIUS Server",
	},
	1991: {
		Name:        "Foundry",
		Product:     "RADIUS",
		VendorID:    1991,
		Confidence:  80,
		Description: "Foundry/Brocade RADIUS Server",
	},
	6527: {
		Name:        "Nokia",
		Product:     "RADIUS",
		VendorID:    6527,
		Confidence:  85,
		Description: "Nokia/Alcatel-Lucent RADIUS Server",
	},
	12356: {
		Name:        "Fortinet",
		Product:     "FortiAuthenticator",
		VendorID:    12356,
		Confidence:  90,
		Description: "Fortinet FortiAuthenticator",
	},
	25053: {
		Name:        "Ruckus",
		Product:     "RADIUS",
		VendorID:    25053,
		Confidence:  85,
		Description: "Ruckus RADIUS Server",
	},
	25461: {
		Name:        "Palo Alto",
		Product:     "RADIUS",
		VendorID:    25461,
		Confidence:  85,
		Description: "Palo Alto Networks RADIUS",
	},
}

// Response pattern fingerprints for vendor identification
var responsePatterns = []struct {
	Pattern     *regexp.Regexp
	VendorInfo  VendorInfo
	Description string
}{
	{
		Pattern: regexp.MustCompile(`(?i)freeradius`),
		VendorInfo: VendorInfo{
			Name:        "FreeRADIUS",
			Product:     "FreeRADIUS",
			Confidence:  95,
			Description: "FreeRADIUS Open Source Server",
		},
		Description: "FreeRADIUS server identification",
	},
	{
		Pattern: regexp.MustCompile(`(?i)microsoft.*nps`),
		VendorInfo: VendorInfo{
			Name:        "Microsoft",
			Product:     "NPS",
			Confidence:  90,
			Description: "Microsoft Network Policy Server",
		},
		Description: "Microsoft NPS identification",
	},
	{
		Pattern: regexp.MustCompile(`(?i)cisco.*ise`),
		VendorInfo: VendorInfo{
			Name:        "Cisco",
			Product:     "ISE",
			Confidence:  90,
			Description: "Cisco Identity Services Engine",
		},
		Description: "Cisco ISE identification",
	},
}

// createRADIUSPacket creates a RADIUS packet with specified parameters
func createRADIUSPacket(code uint8, identifier uint8, attributes []RADIUSAttribute, secret string) ([]byte, error) {
	// Calculate total length
	totalLength := 20 // Header size
	for _, attr := range attributes {
		totalLength += int(attr.Length)
	}

	packet := make([]byte, totalLength)

	// RADIUS Header
	packet[0] = code                                             // Code
	packet[1] = identifier                                       // Identifier
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength)) // Length

	// Generate Request Authenticator (16 random bytes for Access-Request)
	requestAuth := packet[4:20]
	if code == 1 { // Access-Request
		_, err := rand.Read(requestAuth)
		if err != nil {
			return nil, err
		}
	}

	// Add attributes
	offset := 20
	for _, attr := range attributes {
		packet[offset] = attr.Type
		packet[offset+1] = attr.Length
		copy(packet[offset+2:offset+int(attr.Length)], attr.Value)
		offset += int(attr.Length)
	}

	// Calculate Response Authenticator if needed
	if code != 1 && secret != "" {
		hash := md5.New()
		hash.Write(packet[:4])            // Code + ID + Length
		hash.Write(requestAuth)           // Request Authenticator
		hash.Write(packet[20:])           // Attributes
		hash.Write([]byte(secret))        // Shared Secret
		copy(packet[4:20], hash.Sum(nil)) // Response Authenticator
	}

	return packet, nil
}

// createStatusServerPacket creates a Status-Server packet (Code 12)
func createStatusServerPacket() ([]byte, error) {
	identifier := uint8(time.Now().Unix() & 0xFF)
	return createRADIUSPacket(12, identifier, nil, "")
}

// createAccessRequestPacket creates an Access-Request packet for testing
func createAccessRequestPacket() ([]byte, error) {
	identifier := uint8(time.Now().Unix() & 0xFF)

	// Create basic attributes for testing
	attributes := []RADIUSAttribute{
		{
			Type:   1, // User-Name
			Length: 11,
			Value:  []byte("testuser"),
		},
		{
			Type:   2, // User-Password (placeholder)
			Length: 18,
			Value:  make([]byte, 16), // Will be encrypted properly in real implementation
		},
		{
			Type:   4, // NAS-IP-Address
			Length: 6,
			Value:  []byte{127, 0, 0, 1}, // localhost
		},
	}

	return createRADIUSPacket(1, identifier, attributes, "testing123")
}

// parseRADIUSPacket parses a RADIUS response packet
func parseRADIUSPacket(data []byte) (uint8, uint8, []RADIUSAttribute, error) {
	if len(data) < 20 {
		return 0, 0, nil, fmt.Errorf("packet too short")
	}

	code := data[0]
	identifier := data[1]
	length := binary.BigEndian.Uint16(data[2:4])

	if int(length) != len(data) {
		return 0, 0, nil, fmt.Errorf("length mismatch")
	}

	var attributes []RADIUSAttribute
	offset := 20

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		attrType := data[offset]
		attrLength := data[offset+1]

		if attrLength < 2 || offset+int(attrLength) > len(data) {
			break
		}

		attr := RADIUSAttribute{
			Type:   attrType,
			Length: attrLength,
			Value:  make([]byte, attrLength-2),
		}

		copy(attr.Value, data[offset+2:offset+int(attrLength)])
		attributes = append(attributes, attr)
		offset += int(attrLength)
	}

	return code, identifier, attributes, nil
}

// parseVendorSpecificAttribute parses a Vendor-Specific Attribute (Type 26)
func parseVendorSpecificAttribute(data []byte) (*VendorSpecificAttribute, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("VSA too short")
	}

	vsa := &VendorSpecificAttribute{
		VendorID: binary.BigEndian.Uint32(data[0:4]),
	}

	// Some VSAs have sub-attributes, others are just data
	if len(data) > 6 {
		vsa.VendorType = data[4]
		vsa.VendorData = data[5:]
	} else {
		vsa.VendorData = data[4:]
	}

	return vsa, nil
}

// analyzeVendorSpecificAttributes analyzes VSAs for vendor identification
func analyzeVendorSpecificAttributes(attributes []RADIUSAttribute) *VendorInfo {
	for _, attr := range attributes {
		if attr.Type == 26 { // Vendor-Specific Attribute
			vsa, err := parseVendorSpecificAttribute(attr.Value)
			if err != nil {
				continue
			}

			if vendorInfo, exists := knownVendors[vsa.VendorID]; exists {
				vendorInfo.Method = "VSA Analysis"
				vendorInfo.Confidence = 95 // High confidence from VSA
				return &vendorInfo
			}
		}
	}
	return nil
}

// analyzeResponsePatterns analyzes response content for vendor patterns
func analyzeResponsePatterns(attributes []RADIUSAttribute) *VendorInfo {
	// Look for text attributes that might contain vendor information
	for _, attr := range attributes {
		if attr.Type == 18 || attr.Type == 6 { // Reply-Message or Service-Type
			content := string(attr.Value)
			for _, pattern := range responsePatterns {
				if pattern.Pattern.MatchString(content) {
					vendorInfo := pattern.VendorInfo
					vendorInfo.Method = "Response Pattern"
					return &vendorInfo
				}
			}
		}
	}
	return nil
}

// analyzeTimingBehavior analyzes response timing for vendor identification
func analyzeTimingBehavior(responseTime time.Duration) *VendorInfo {
	// Different implementations have characteristic response times
	if responseTime < 10*time.Millisecond {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Fast Implementation",
			Confidence:  30,
			Method:      "Timing Analysis",
			Description: "Very fast response suggests optimized implementation",
		}
	} else if responseTime > 100*time.Millisecond {
		return &VendorInfo{
			Name:        "Unknown",
			Product:     "Slow Implementation",
			Confidence:  30,
			Method:      "Timing Analysis",
			Description: "Slow response suggests complex processing or high load",
		}
	}
	return nil
}

// detectRADIUSVendor performs comprehensive vendor detection
func detectRADIUSVendor(conn net.Conn, timeout time.Duration) (*VendorInfo, []RADIUSAttribute, error) {
	var bestVendor *VendorInfo
	var responseAttrs []RADIUSAttribute

	// Method 1: Status-Server probe (most reliable)
	statusPacket, err := createStatusServerPacket()
	if err == nil {
		start := time.Now()
		response, err := utils.SendRecv(conn, statusPacket, timeout)
		responseTime := time.Since(start)

		if err == nil && len(response) >= 20 {
			code, _, attributes, parseErr := parseRADIUSPacket(response)
			if parseErr == nil && (code == 2 || code == 3) { // Access-Accept or Access-Reject
				responseAttrs = attributes

				// Analyze VSAs first (highest confidence)
				if vendor := analyzeVendorSpecificAttributes(attributes); vendor != nil {
					bestVendor = vendor
				}

				// Analyze response patterns
				if bestVendor == nil {
					if vendor := analyzeResponsePatterns(attributes); vendor != nil {
						bestVendor = vendor
					}
				}

				// Analyze timing if no other method worked
				if bestVendor == nil {
					if vendor := analyzeTimingBehavior(responseTime); vendor != nil {
						bestVendor = vendor
					}
				}
			}
		}
	}

	// Method 2: Access-Request probe (if Status-Server failed)
	if bestVendor == nil {
		accessPacket, err := createAccessRequestPacket()
		if err == nil {
			start := time.Now()
			response, err := utils.SendRecv(conn, accessPacket, timeout)
			responseTime := time.Since(start)

			if err == nil && len(response) >= 20 {
				code, _, attributes, parseErr := parseRADIUSPacket(response)
				if parseErr == nil && (code == 2 || code == 3 || code == 11) { // Accept/Reject/Challenge
					responseAttrs = attributes

					// Analyze VSAs
					if vendor := analyzeVendorSpecificAttributes(attributes); vendor != nil {
						bestVendor = vendor
					}

					// Analyze response patterns
					if bestVendor == nil {
						if vendor := analyzeResponsePatterns(attributes); vendor != nil {
							bestVendor = vendor
						}
					}

					// Analyze timing
					if bestVendor == nil {
						if vendor := analyzeTimingBehavior(responseTime); vendor != nil {
							bestVendor = vendor
						}
					}
				}
			}
		}
	}

	return bestVendor, responseAttrs, nil
}

// createServiceWithVendorInfo creates a service object with vendor information
func createServiceWithVendorInfo(target plugins.Target, vendor *VendorInfo, attributes []RADIUSAttribute) *plugins.Service {
	serviceName := RADIUS
	if vendor != nil {
		serviceName = fmt.Sprintf("%s (%s %s)", RADIUS, vendor.Name, vendor.Product)
		if vendor.Version != "" {
			serviceName = fmt.Sprintf("%s (%s %s %s)", RADIUS, vendor.Name, vendor.Product, vendor.Version)
		}
	}

	service := &plugins.Service{
		Name:     serviceName,
		Protocol: plugins.UDP,
		Port:     target.Port,
		Host:     target.Host,
		TLS:      false,
		Details:  make(map[string]interface{}),
	}

	// Add vendor information
	if vendor != nil {
		service.Details["vendor"] = map[string]interface{}{
			"name":        vendor.Name,
			"product":     vendor.Product,
			"version":     vendor.Version,
			"vendor_id":   vendor.VendorID,
			"confidence":  vendor.Confidence,
			"method":      vendor.Method,
			"description": vendor.Description,
		}
	}

	// Add attribute analysis
	if len(attributes) > 0 {
		service.Details["attributes"] = map[string]interface{}{
			"count": len(attributes),
			"types": getAttributeTypes(attributes),
		}

		// Add VSA information
		vsas := extractVSAs(attributes)
		if len(vsas) > 0 {
			service.Details["vendor_specific_attributes"] = vsas
		}
	}

	// Add protocol information
	service.Details["protocol_info"] = map[string]interface{}{
		"standard_ports": []int{1812, 1813},
		"legacy_ports":   []int{1645, 1646},
		"transport":      "UDP",
	}

	return service
}

// getAttributeTypes extracts attribute types from response
func getAttributeTypes(attributes []RADIUSAttribute) []uint8 {
	var types []uint8
	for _, attr := range attributes {
		types = append(types, attr.Type)
	}
	return types
}

// extractVSAs extracts vendor-specific attribute information
func extractVSAs(attributes []RADIUSAttribute) []map[string]interface{} {
	var vsas []map[string]interface{}

	for _, attr := range attributes {
		if attr.Type == 26 { // Vendor-Specific Attribute
			vsa, err := parseVendorSpecificAttribute(attr.Value)
			if err == nil {
				vsaInfo := map[string]interface{}{
					"vendor_id":   vsa.VendorID,
					"vendor_type": vsa.VendorType,
					"data_length": len(vsa.VendorData),
				}

				// Add vendor name if known
				if vendorInfo, exists := knownVendors[vsa.VendorID]; exists {
					vsaInfo["vendor_name"] = vendorInfo.Name
				}

				vsas = append(vsas, vsaInfo)
			}
		}
	}

	return vsas
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * Comprehensive RADIUS Server Detection and Vendor Identification
	 *
	 * This plugin performs multi-stage RADIUS detection and vendor identification:
	 * 1. Status-Server probe (Code 12) for basic detection
	 * 2. Access-Request probe for detailed analysis
	 * 3. Vendor-Specific Attribute (VSA) analysis
	 * 4. Response pattern matching
	 * 5. Timing behavior analysis
	 *
	 * Supported vendor detection:
	 * - Microsoft NPS (Network Policy Server)
	 * - Cisco ISE/ACS (Identity Services Engine/Access Control Server)
	 * - FreeRADIUS (Open Source)
	 * - Fortinet FortiAuthenticator
	 * - And many others through VSA analysis
	 */

	// Attempt vendor detection
	vendor, attributes, err := detectRADIUSVendor(conn, timeout)
	if err != nil {
		// If vendor detection failed, try basic RADIUS detection
		statusPacket, packetErr := createStatusServerPacket()
		if packetErr != nil {
			return nil, packetErr
		}

		response, sendErr := utils.SendRecv(conn, statusPacket, timeout)
		if sendErr != nil {
			return nil, sendErr
		}

		if len(response) < 20 {
			return nil, nil // Not a RADIUS server
		}

		code, _, _, parseErr := parseRADIUSPacket(response)
		if parseErr != nil {
			return nil, nil
		}

		// Valid RADIUS response codes
		if code == 2 || code == 3 || code == 5 { // Accept, Reject, or Accounting-Response
			return createServiceWithVendorInfo(target, nil, nil), nil
		}

		return nil, nil
	}

	// Create service with detected vendor information
	return createServiceWithVendorInfo(target, vendor, attributes), nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 1812 || i == 1813 || i == 1645 || i == 1646
}

func (p *Plugin) Name() string {
	return RADIUS
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 600
}
