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

// createSimpleMongoDBQuery creates a simple MongoDB OP_QUERY message without client metadata
func createSimpleMongoDBQuery(command string, requestID int32) []byte {
	// Create simple BSON document for the command
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
	responseFlags := binary.LittleEndian.Uint32(response[16:20])
	numberReturned := binary.LittleEndian.Uint32(response[32:36])

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

// dumpBSONResponse dumps the BSON response in a readable format
func dumpBSONResponse(data []byte) {
	log.Printf("MONGODB DEBUG: BSON Response dump (%d bytes):", len(data))
	log.Printf("MONGODB DEBUG: Hex dump: %s", hex.EncodeToString(data))

	// Try to find printable strings in the response
	log.Printf("MONGODB DEBUG: Printable strings found:")
	var currentString []byte
	for i, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII
			currentString = append(currentString, b)
		} else {
			if len(currentString) >= 3 { // Only show strings of 3+ chars
				log.Printf("MONGODB DEBUG:   Offset %d: '%s'", i-len(currentString), string(currentString))
			}
			currentString = nil
		}
	}
	if len(currentString) >= 3 {
		log.Printf("MONGODB DEBUG:   Offset %d: '%s'", len(data)-len(currentString), string(currentString))
	}

	// Look for common MongoDB field patterns
	log.Printf("MONGODB DEBUG: Looking for common MongoDB fields:")
	fields := []string{"version", "gitVersion", "allocator", "javascriptEngine", "storageEngines", "buildEnvironment", "openssl", "isMaster", "ismaster", "ok"}

	for _, field := range fields {
		fieldBytes := []byte(field)
		for i := 0; i <= len(data)-len(fieldBytes); i++ {
			match := true
			for j, b := range fieldBytes {
				if data[i+j] != b {
					match = false
					break
				}
			}
			if match {
				// Found field name, show context
				start := max(0, i-10)
				end := min(len(data), i+len(fieldBytes)+20)
				context := data[start:end]
				log.Printf("MONGODB DEBUG:   Found '%s' at offset %d, context: %s", field, i, hex.EncodeToString(context))
			}
		}
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseMongoDBResponse extracts information from MongoDB response
func parseMongoDBResponse(response []byte, command string) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		result.Product = "mongodb"
		return result
	}

	bsonData := response[36:]
	log.Printf("MONGODB DEBUG: Processing %s response (%d bytes BSON data)", command, len(bsonData))

	// Dump the BSON response for analysis
	dumpBSONResponse(bsonData)

	// Basic detection - just confirm it's MongoDB
	result.ServerType = "mongod"
	result.Authentication = "disabled"
	result.Product = "mongodb (mongod)"

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
	commands := []string{"isMaster", "hello", "buildInfo"}

	for i, command := range commands {
		log.Printf("MONGODB DEBUG: Trying command: %s", command)
		requestID := int32(i + 1)
		message := createSimpleMongoDBQuery(command, requestID)
		if message == nil {
			continue
		}

		response, err := utils.SendRecv(conn, message, timeout)
		if err != nil {
			log.Printf("MONGODB DEBUG: Command %s failed: %v", command, err)
			continue
		}

		log.Printf("MONGODB DEBUG: Received response for %s (%d bytes)", command, len(response))

		if len(response) > 0 && isValidMongoDBResponse(response) {
			log.Printf("MONGODB DEBUG: Valid MongoDB response for command: %s", command)
			payload := parseMongoDBResponse(response, command)
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		} else {
			log.Printf("MONGODB DEBUG: Invalid response for command: %s", command)
		}
	}

	log.Printf("MONGODB DEBUG: No valid MongoDB responses received")
	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
