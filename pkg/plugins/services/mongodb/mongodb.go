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

// createSimpleMongoDBQuery creates a simple MongoDB OP_QUERY message
func createSimpleMongoDBQuery(command string, requestID int32) []byte {
	var bsonDoc []byte

	if command == "isMaster" {
		// Simple isMaster command: { "isMaster": 1 }
		bsonDoc = []byte{
			0x16, 0x00, 0x00, 0x00, // document length (22 bytes)
			0x10,                                         // int32 type
			'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // field name "isMaster"
			0x01, 0x00, 0x00, 0x00, // value 1
			0x00, // document terminator
		}
	} else if command == "hello" {
		// Simple hello command: { "hello": 1 }
		bsonDoc = []byte{
			0x12, 0x00, 0x00, 0x00, // document length (18 bytes)
			0x10,                          // int32 type
			'h', 'e', 'l', 'l', 'o', 0x00, // field name "hello"
			0x01, 0x00, 0x00, 0x00, // value 1
			0x00, // document terminator
		}
	} else if command == "buildInfo" {
		// Simple buildInfo command: { "buildInfo": 1 }
		bsonDoc = []byte{
			0x16, 0x00, 0x00, 0x00, // document length (22 bytes)
			0x10,                                              // int32 type
			'b', 'u', 'i', 'l', 'd', 'I', 'n', 'f', 'o', 0x00, // field name "buildInfo"
			0x01, 0x00, 0x00, 0x00, // value 1
			0x00, // document terminator
		}
	} else {
		return nil
	}

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

// isValidMongoDBResponse validates MongoDB response
func isValidMongoDBResponse(response []byte) bool {
	if len(response) < 36 { // Minimum OP_REPLY size
		return false
	}

	// Parse header
	messageLength := binary.LittleEndian.Uint32(response[0:4])
	opCode := binary.LittleEndian.Uint32(response[12:16])

	// Validate message length
	if messageLength < 36 || messageLength > 48*1024*1024 {
		return false
	}

	// Check opcode (OP_REPLY = 1)
	if opCode != 1 {
		return false
	}

	// Parse OP_REPLY structure
	_ = binary.LittleEndian.Uint32(response[16:20]) // responseFlags - read but not used
	numberReturned := binary.LittleEndian.Uint32(response[32:36])

	// Should have at least one document
	if numberReturned == 0 {
		return false
	}

	return true
}

// extractPrintableStrings extracts all printable strings from binary data
func extractPrintableStrings(data []byte) []string {
	var strings []string
	var current []byte

	for i, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII
			current = append(current, b)
		} else {
			if len(current) > 2 {
				strings = append(strings, fmt.Sprintf("Offset %d: '%s'", i-len(current), string(current)))
			}
			current = nil
		}
	}

	if len(current) > 2 {
		strings = append(strings, fmt.Sprintf("Offset %d: '%s'", len(data)-len(current), string(current)))
	}

	return strings
}

// parseMongoDBResponse extracts information from MongoDB response with extensive debugging
func parseMongoDBResponse(response []byte, command string) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	log.Printf("MONGODB DEBUG: Parsing %s response (%d bytes)", command, len(response))

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		log.Printf("MONGODB DEBUG: Response too short (%d bytes)", len(response))
		result.Product = "mongodb"
		return result
	}

	bsonData := response[36:]
	log.Printf("MONGODB DEBUG: BSON data length: %d bytes", len(bsonData))

	// Show hex dump of first 200 bytes of BSON data
	dumpLen := len(bsonData)
	if dumpLen > 200 {
		dumpLen = 200
	}
	log.Printf("MONGODB DEBUG: BSON hex dump (first %d bytes): %s", dumpLen, hex.EncodeToString(bsonData[:dumpLen]))

	// Extract printable strings
	printableStrings := extractPrintableStrings(bsonData)
	log.Printf("MONGODB DEBUG: Found %d printable strings:", len(printableStrings))
	for i, str := range printableStrings {
		if i < 20 { // Limit output
			log.Printf("MONGODB DEBUG:   %s", str)
		}
	}

	// Look for specific MongoDB field names
	fieldNames := []string{"version", "gitVersion", "allocator", "javascriptEngine", "storageEngines", "buildEnvironment", "openssl", "bits", "maxBsonObjectSize"}
	log.Printf("MONGODB DEBUG: Searching for MongoDB fields:")
	for _, field := range fieldNames {
		if strings.Contains(string(bsonData), field) {
			log.Printf("MONGODB DEBUG:   Found field: %s", field)
		} else {
			log.Printf("MONGODB DEBUG:   Missing field: %s", field)
		}
	}

	// Basic detection - if we got a response, it's MongoDB
	result.ServerType = "mongod"
	result.Authentication = "disabled"
	result.Product = "mongodb (mongod)"

	log.Printf("MONGODB DEBUG: Final result: %+v", result)

	return result
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

	log.Printf("MONGODB DEBUG: Starting MongoDB detection")

	// Try different MongoDB commands
	commands := []string{"buildInfo", "isMaster", "hello"}

	for i, command := range commands {
		log.Printf("MONGODB DEBUG: Trying command: %s", command)
		requestID := int32(i + 1)
		message := createSimpleMongoDBQuery(command, requestID)
		if message == nil {
			log.Printf("MONGODB DEBUG: Failed to create %s query", command)
			continue
		}

		log.Printf("MONGODB DEBUG: Sending %s query (%d bytes)", command, len(message))
		response, err := utils.SendRecv(conn, message, timeout)
		if err != nil {
			log.Printf("MONGODB DEBUG: Error sending %s: %v", command, err)
			continue
		}

		log.Printf("MONGODB DEBUG: Received %s response (%d bytes)", command, len(response))

		if len(response) > 0 && isValidMongoDBResponse(response) {
			log.Printf("MONGODB DEBUG: Valid MongoDB response for command: %s", command)
			payload := parseMongoDBResponse(response, command)
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		} else {
			log.Printf("MONGODB DEBUG: Invalid MongoDB response for command: %s", command)
		}
	}

	log.Printf("MONGODB DEBUG: No valid MongoDB responses received")
	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
