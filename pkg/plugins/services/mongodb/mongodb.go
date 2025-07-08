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

package mongodb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type MongoDBPlugin struct{}

const MONGODB = "mongodb"

func init() {
	plugins.RegisterPlugin(&MongoDBPlugin{})
}

// BSON element types
const (
	BSONTypeDouble     = 0x01
	BSONTypeString     = 0x02
	BSONTypeDocument   = 0x03
	BSONTypeArray      = 0x04
	BSONTypeBinary     = 0x05
	BSONTypeObjectID   = 0x07
	BSONTypeBoolean    = 0x08
	BSONTypeDateTime   = 0x09
	BSONTypeNull       = 0x0A
	BSONTypeRegex      = 0x0B
	BSONTypeJavaScript = 0x0D
	BSONTypeSymbol     = 0x0E
	BSONTypeInt32      = 0x10
	BSONTypeTimestamp  = 0x11
	BSONTypeInt64      = 0x12
	BSONTypeDecimal128 = 0x13
)

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

// createBSONElement creates a BSON element with proper encoding
func createBSONElement(elementType byte, name string, value []byte) []byte {
	var element []byte
	element = append(element, elementType)
	element = append(element, []byte(name)...)
	element = append(element, 0x00) // null terminator for name
	element = append(element, value...)
	return element
}

// createBSONInt32 creates a BSON int32 element
func createBSONInt32(name string, value int32) []byte {
	valueBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueBytes, uint32(value))
	return createBSONElement(0x10, name, valueBytes)
}

// createBSONString creates a BSON string element
func createBSONString(name, value string) []byte {
	// String length (including null terminator)
	strLen := len(value) + 1
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(strLen))

	var valueBytes []byte
	valueBytes = append(valueBytes, lenBytes...)
	valueBytes = append(valueBytes, []byte(value)...)
	valueBytes = append(valueBytes, 0x00) // null terminator

	return createBSONElement(0x02, name, valueBytes)
}

// createBSONDocument creates a proper BSON document
func createBSONDocument(elements [][]byte) []byte {
	// Calculate elements size
	var elementsData []byte
	for _, element := range elements {
		elementsData = append(elementsData, element...)
	}

	// Document length = 4 bytes (length) + elements + 1 byte (terminator)
	docLength := 4 + len(elementsData) + 1

	// Create document
	var doc []byte
	lengthBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lengthBytes, uint32(docLength))
	doc = append(doc, lengthBytes...)
	doc = append(doc, elementsData...)
	doc = append(doc, 0x00) // document terminator

	return doc
}

// createMongoDBQuery creates a MongoDB OP_QUERY message
func createMongoDBQuery(command string, requestID int32) []byte {
	var elements [][]byte

	// Add main command
	if command == "hello" {
		elements = append(elements, createBSONInt32("hello", 1))
	} else if command == "isMaster" {
		elements = append(elements, createBSONInt32("isMaster", 1))
	} else if command == "buildInfo" {
		elements = append(elements, createBSONInt32("buildInfo", 1))
	} else if command == "listDatabases" {
		elements = append(elements, createBSONInt32("listDatabases", 1))
	} else {
		return nil
	}

	// Add client information for better compatibility
	elements = append(elements, createBSONString("client", "fingerprintx"))

	// Create BSON document
	bsonDoc := createBSONDocument(elements)

	// OP_QUERY structure:
	// header(16) + flags(4) + collection(variable) + skip(4) + limit(4) + query(variable)

	flags := make([]byte, 4)               // no flags
	collection := []byte("admin.$cmd\x00") // admin.$cmd collection
	skip := make([]byte, 4)                // skip 0
	limit := make([]byte, 4)               // limit 1
	binary.LittleEndian.PutUint32(limit, 1)

	// Calculate message length
	messageLength := 16 + 4 + len(collection) + 4 + 4 + len(bsonDoc)

	// Create header
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(messageLength)) // message length
	binary.LittleEndian.PutUint32(header[4:8], uint32(requestID))     // request ID
	binary.LittleEndian.PutUint32(header[8:12], 0)                    // response to
	binary.LittleEndian.PutUint32(header[12:16], 2004)                // OP_QUERY opcode

	// Combine message
	var message []byte
	message = append(message, header...)
	message = append(message, flags...)
	message = append(message, collection...)
	message = append(message, skip...)
	message = append(message, limit...)
	message = append(message, bsonDoc...)

	return message
}

// parseBSONString parses a BSON string from data at offset
func parseBSONString(data []byte, offset int) (string, int, error) {
	if offset+4 >= len(data) {
		return "", 0, fmt.Errorf("insufficient data for string length")
	}

	// Read string length (including null terminator)
	strLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	if strLen == 0 || strLen > 1024*1024 { // Sanity check
		return "", 0, fmt.Errorf("invalid string length: %d", strLen)
	}

	offset += 4
	if offset+int(strLen) > len(data) {
		return "", 0, fmt.Errorf("insufficient data for string content")
	}

	// Read string content (excluding null terminator)
	strValue := string(data[offset : offset+int(strLen)-1])

	return strValue, offset + int(strLen), nil
}

// parseBSONInt32 parses a BSON int32 from data at offset
func parseBSONInt32(data []byte, offset int) (int32, int, error) {
	if offset+4 > len(data) {
		return 0, 0, fmt.Errorf("insufficient data for int32")
	}

	value := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
	return value, offset + 4, nil
}

// parseBSONDocument parses a BSON document and returns key-value pairs
func parseBSONDocument(data []byte, offset int) (map[string]interface{}, int, error) {
	if offset+4 >= len(data) {
		return nil, 0, fmt.Errorf("insufficient data for document length")
	}

	// Read document length
	docLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	log.Printf("MONGODB DEBUG: Document length: %d", docLen)

	if docLen < 5 || docLen > 16*1024*1024 { // Sanity check
		return nil, 0, fmt.Errorf("invalid document length: %d", docLen)
	}

	docEnd := offset + int(docLen)
	if docEnd > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for document content")
	}

	result := make(map[string]interface{})
	currentOffset := offset + 4

	log.Printf("MONGODB DEBUG: Starting to parse document elements from offset %d to %d", currentOffset, docEnd)

	// Parse document elements
	elementCount := 0
	for currentOffset < docEnd-1 { // -1 for terminator
		if currentOffset >= len(data) {
			break
		}

		elementType := data[currentOffset]
		if elementType == 0 { // Document terminator
			log.Printf("MONGODB DEBUG: Found document terminator at offset %d", currentOffset)
			break
		}

		log.Printf("MONGODB DEBUG: Element %d - Type: 0x%02x at offset %d", elementCount, elementType, currentOffset)
		currentOffset++

		// Read element name
		nameStart := currentOffset
		nameEnd := currentOffset
		for nameEnd < docEnd && data[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= docEnd {
			log.Printf("MONGODB DEBUG: Element name extends beyond document end")
			break
		}

		elementName := string(data[nameStart:nameEnd])
		currentOffset = nameEnd + 1 // Skip null terminator

		log.Printf("MONGODB DEBUG: Element name: '%s'", elementName)

		// Parse element value based on type
		var value interface{}
		var err error

		switch elementType {
		case BSONTypeString:
			value, currentOffset, err = parseBSONString(data, currentOffset)
			if err == nil {
				log.Printf("MONGODB DEBUG: String value: '%s'", value)
			}
		case BSONTypeInt32:
			value, currentOffset, err = parseBSONInt32(data, currentOffset)
			if err == nil {
				log.Printf("MONGODB DEBUG: Int32 value: %d", value)
			}
		default:
			log.Printf("MONGODB DEBUG: Skipping unknown element type 0x%02x", elementType)
			// Skip unknown element types
			// Try to find next element by looking for next type byte
			for currentOffset < docEnd && currentOffset < len(data) {
				if data[currentOffset] >= 0x01 && data[currentOffset] <= 0x13 {
					break
				}
				currentOffset++
			}
			continue
		}

		if err != nil {
			log.Printf("MONGODB DEBUG: Error parsing element '%s': %v", elementName, err)
			continue
		}

		result[elementName] = value
		elementCount++
	}

	log.Printf("MONGODB DEBUG: Parsed %d elements total", elementCount)
	log.Printf("MONGODB DEBUG: Final result keys: %v", getKeys(result))

	return result, docEnd, nil
}

// getKeys returns the keys of a map for debugging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// isValidMongoDBResponse validates MongoDB response
func isValidMongoDBResponse(response []byte) bool {
	if len(response) < 36 { // Minimum OP_REPLY size
		return false
	}

	// Parse header
	messageLength := binary.LittleEndian.Uint32(response[0:4])
	opCode := binary.LittleEndian.Uint32(response[12:16])

	log.Printf("MONGODB DEBUG: Response validation - Length: %d, OpCode: %d", messageLength, opCode)

	// Validate message length
	if messageLength < 36 || messageLength > 48*1024*1024 {
		return false
	}

	// Check opcode (OP_REPLY = 1)
	if opCode != 1 {
		return false
	}

	// Parse OP_REPLY structure
	responseFlags := binary.LittleEndian.Uint32(response[16:20])
	numberReturned := binary.LittleEndian.Uint32(response[32:36])

	log.Printf("MONGODB DEBUG: Response flags: %d, Number returned: %d", responseFlags, numberReturned)

	// Check for query failure
	if responseFlags&0x02 != 0 {
		return false
	}

	// Should have at least one document
	if numberReturned == 0 {
		return false
	}

	return true
}

// parseMongoDBResponse extracts information from MongoDB response and populates structured fields
func parseMongoDBResponse(response []byte, command string, conn net.Conn, timeout time.Duration) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	log.Printf("MONGODB DEBUG: Parsing response for command '%s', length: %d", command, len(response))
	log.Printf("MONGODB DEBUG: Response hex (first 100 bytes): %s", hex.EncodeToString(response[:min(100, len(response))]))

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		result.Product = "mongodb"
		return result
	}

	log.Printf("MONGODB DEBUG: Skipping OP_REPLY header, starting BSON parsing at offset 36")

	// Parse BSON document
	bsonDoc, _, err := parseBSONDocument(response, 36)
	if err != nil {
		log.Printf("MONGODB DEBUG: BSON parsing error: %v", err)
		result.Product = "mongodb"
		return result
	}

	log.Printf("MONGODB DEBUG: Successfully parsed BSON document with %d fields", len(bsonDoc))

	// Debug: Print all found fields
	for key, value := range bsonDoc {
		log.Printf("MONGODB DEBUG: Found field '%s' = %v (type: %T)", key, value, value)
	}

	// Extract basic information
	if v, ok := bsonDoc["version"]; ok {
		if str, ok := v.(string); ok {
			result.Version = str
			log.Printf("MONGODB DEBUG: Extracted version: %s", str)
		}
	}

	if v, ok := bsonDoc["gitVersion"]; ok {
		if str, ok := v.(string); ok {
			result.GitVersion = str
			log.Printf("MONGODB DEBUG: Extracted gitVersion: %s", str)
		}
	}

	if v, ok := bsonDoc["allocator"]; ok {
		if str, ok := v.(string); ok {
			result.Allocator = str
			log.Printf("MONGODB DEBUG: Extracted allocator: %s", str)
		}
	}

	// Determine server type
	result.ServerType = "mongod"
	if v, ok := bsonDoc["msg"]; ok {
		if str, ok := v.(string); ok && strings.Contains(str, "mongos") {
			result.ServerType = "mongos"
		}
	}

	// Check authentication status
	result.Authentication = "disabled"
	if _, ok := bsonDoc["authInfo"]; ok {
		result.Authentication = "enabled"
	} else if _, ok := bsonDoc["saslSupportedMechs"]; ok {
		result.Authentication = "partially enabled"
	}

	// Create product banner
	result.Product = "mongodb"
	if result.Version != "" {
		result.Product = fmt.Sprintf("mongodb %s", result.Version)
	}
	if result.ServerType != "" {
		result.Product += fmt.Sprintf(" (%s)", result.ServerType)
	}
	if result.Allocator != "" {
		result.Product += fmt.Sprintf(" [%s]", result.Allocator)
	}

	log.Printf("MONGODB DEBUG: Final result - Version: '%s', Allocator: '%s', Product: '%s'", result.Version, result.Allocator, result.Product)

	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (p *MongoDBPlugin) PortPriority(port uint16) bool {
	return port == 27017
}

func (p *MongoDBPlugin) Name() string {
	return MONGODB
}

func (p *MongoDBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MongoDBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	port := getPortFromConnection(conn)
	if port != 27017 {
		return nil, nil
	}

	log.Printf("MONGODB DEBUG: Starting MongoDB detection for %s", conn.RemoteAddr().String())

	// Try different MongoDB commands
	commands := []string{"hello", "isMaster", "buildInfo"}

	for i, command := range commands {
		log.Printf("MONGODB DEBUG: Trying command '%s'", command)
		requestID := int32(i + 1)
		message := createMongoDBQuery(command, requestID)
		if message == nil {
			continue
		}

		log.Printf("MONGODB DEBUG: Sending %s command (%d bytes)", command, len(message))
		response, err := utils.SendRecv(conn, message, timeout)
		if err != nil {
			log.Printf("MONGODB DEBUG: Command '%s' failed: %v", command, err)
			continue
		}

		log.Printf("MONGODB DEBUG: Received response for '%s' (%d bytes)", command, len(response))

		if len(response) > 0 && isValidMongoDBResponse(response) {
			log.Printf("MONGODB DEBUG: Valid MongoDB response detected for command '%s'", command)
			payload := parseMongoDBResponse(response, command, conn, timeout)
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		} else {
			log.Printf("MONGODB DEBUG: Invalid or empty response for command '%s'", command)
		}
	}

	log.Printf("MONGODB DEBUG: No valid MongoDB responses received")
	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
