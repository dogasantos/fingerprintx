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
	"fmt"
	"net"
	"regexp"
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

// createCorrectBSONQuery creates properly formatted BSON queries
func createCorrectBSONQuery(command string, requestID int32) []byte {
	var bsonDoc []byte

	if command == "isMaster" {
		// Correct BSON for { "isMaster": 1 }
		// Document structure: length(4) + elements + terminator(1)
		bsonDoc = []byte{
			0x16, 0x00, 0x00, 0x00, // document length: 22 bytes
			0x10,                                         // int32 type
			'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // field name + null terminator
			0x01, 0x00, 0x00, 0x00, // int32 value: 1
			0x00, // document terminator
		}
	} else if command == "hello" {
		// Correct BSON for { "hello": 1 }
		bsonDoc = []byte{
			0x12, 0x00, 0x00, 0x00, // document length: 18 bytes
			0x10,                          // int32 type
			'h', 'e', 'l', 'l', 'o', 0x00, // field name + null terminator
			0x01, 0x00, 0x00, 0x00, // int32 value: 1
			0x00, // document terminator
		}
	} else if command == "buildInfo" {
		// Correct BSON for { "buildInfo": 1 }
		bsonDoc = []byte{
			0x16, 0x00, 0x00, 0x00, // document length: 22 bytes
			0x10,                                              // int32 type
			'b', 'u', 'i', 'l', 'd', 'I', 'n', 'f', 'o', 0x00, // field name + null terminator
			0x01, 0x00, 0x00, 0x00, // int32 value: 1
			0x00, // document terminator
		}
	} else if command == "serverStatus" {
		// Correct BSON for { "serverStatus": 1 }
		bsonDoc = []byte{
			0x19, 0x00, 0x00, 0x00, // document length: 25 bytes
			0x10,                                                             // int32 type
			's', 'e', 'r', 'v', 'e', 'r', 'S', 't', 'a', 't', 'u', 's', 0x00, // field name + null terminator
			0x01, 0x00, 0x00, 0x00, // int32 value: 1
			0x00, // document terminator
		}
	} else {
		return nil
	}

	// Verify BSON document length matches actual length
	expectedLength := binary.LittleEndian.Uint32(bsonDoc[0:4])
	if int(expectedLength) != len(bsonDoc) {
		return nil // Length mismatch
	}

	// Create OP_QUERY message
	flags := make([]byte, 4)               // no flags
	collection := []byte("admin.$cmd\x00") // collection name with null terminator
	skip := make([]byte, 4)                // skip 0 documents
	limit := make([]byte, 4)               // return 1 document
	binary.LittleEndian.PutUint32(limit, 1)

	// Calculate total message length
	messageLength := 16 + 4 + len(collection) + 4 + 4 + len(bsonDoc)

	// Create MongoDB wire protocol header
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(messageLength)) // message length
	binary.LittleEndian.PutUint32(header[4:8], uint32(requestID))     // request ID
	binary.LittleEndian.PutUint32(header[8:12], 0)                    // response to (0 for request)
	binary.LittleEndian.PutUint32(header[12:16], 2004)                // opcode: OP_QUERY

	// Assemble complete message
	var message []byte
	message = append(message, header...)
	message = append(message, flags...)
	message = append(message, collection...)
	message = append(message, skip...)
	message = append(message, limit...)
	message = append(message, bsonDoc...)

	return message
}

// isValidMongoDBResponse validates MongoDB OP_REPLY response
func isValidMongoDBResponse(response []byte) bool {
	if len(response) < 36 {
		return false
	}

	messageLength := binary.LittleEndian.Uint32(response[0:4])
	opCode := binary.LittleEndian.Uint32(response[12:16])
	responseFlags := binary.LittleEndian.Uint32(response[16:20])
	numberReturned := binary.LittleEndian.Uint32(response[32:36])

	// Validate message structure
	if messageLength < 36 || messageLength > 48*1024*1024 {
		return false
	}

	// Must be OP_REPLY (opcode 1)
	if opCode != 1 {
		return false
	}

	// Check for query failure flag
	if responseFlags&0x02 != 0 {
		return false
	}

	// Must return at least one document
	if numberReturned == 0 {
		return false
	}

	return true
}

// extractStringValue extracts string values from BSON using safe pattern matching
func extractStringValue(data []byte, fieldName string) string {
	fieldBytes := []byte(fieldName + "\x00") // Include null terminator

	for i := 0; i < len(data)-len(fieldBytes)-8; i++ {
		// Look for string type (0x02) followed by field name
		if data[i] == 0x02 {
			if i+1+len(fieldBytes) < len(data) {
				// Check if field name matches
				match := true
				for j, b := range fieldBytes {
					if data[i+1+j] != b {
						match = false
						break
					}
				}

				if match {
					// Found field, extract string value
					strLenOffset := i + 1 + len(fieldBytes)
					if strLenOffset+4 < len(data) {
						strLen := binary.LittleEndian.Uint32(data[strLenOffset : strLenOffset+4])
						if strLen > 0 && strLen < 1024 && strLenOffset+4+int(strLen) <= len(data) {
							strValue := string(data[strLenOffset+4 : strLenOffset+4+int(strLen)-1])
							if isPrintableString(strValue) {
								return strValue
							}
						}
					}
				}
			}
		}
	}

	return ""
}

// extractInt32Value extracts int32 values from BSON
func extractInt32Value(data []byte, fieldName string) int32 {
	fieldBytes := []byte(fieldName + "\x00")

	for i := 0; i < len(data)-len(fieldBytes)-8; i++ {
		if data[i] == 0x10 { // int32 type
			if i+1+len(fieldBytes) < len(data) {
				match := true
				for j, b := range fieldBytes {
					if data[i+1+j] != b {
						match = false
						break
					}
				}

				if match {
					valueOffset := i + 1 + len(fieldBytes)
					if valueOffset+4 <= len(data) {
						return int32(binary.LittleEndian.Uint32(data[valueOffset : valueOffset+4]))
					}
				}
			}
		}
	}

	return 0
}

// extractArrayStrings extracts string arrays from BSON
func extractArrayStrings(data []byte, fieldName string) []string {
	var result []string
	fieldBytes := []byte(fieldName + "\x00")

	for i := 0; i < len(data)-len(fieldBytes)-8; i++ {
		if data[i] == 0x04 { // array type
			if i+1+len(fieldBytes) < len(data) {
				match := true
				for j, b := range fieldBytes {
					if data[i+1+j] != b {
						match = false
						break
					}
				}

				if match {
					arrayOffset := i + 1 + len(fieldBytes)
					if arrayOffset+4 < len(data) {
						arrayLen := binary.LittleEndian.Uint32(data[arrayOffset : arrayOffset+4])
						if arrayLen > 4 && arrayLen < 1024 && arrayOffset+int(arrayLen) <= len(data) {
							arrayData := data[arrayOffset+4 : arrayOffset+int(arrayLen)]

							// Scan array for string elements
							for j := 0; j < len(arrayData)-8; j++ {
								if arrayData[j] == 0x02 { // string type in array
									// Skip array index (like "0", "1", etc.)
									nameEnd := j + 1
									for nameEnd < len(arrayData) && arrayData[nameEnd] != 0x00 {
										nameEnd++
									}
									if nameEnd+5 < len(arrayData) {
										strLenOffset := nameEnd + 1
										strLen := binary.LittleEndian.Uint32(arrayData[strLenOffset : strLenOffset+4])
										if strLen > 0 && strLen < 256 && strLenOffset+4+int(strLen) <= len(arrayData) {
											strValue := string(arrayData[strLenOffset+4 : strLenOffset+4+int(strLen)-1])
											if isPrintableString(strValue) {
												result = append(result, strValue)
											}
										}
									}
								}
							}
						}
					}
					break
				}
			}
		}
	}

	return result
}

// isPrintableString validates that a string contains only printable characters
func isPrintableString(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// extractGCCVersion extracts GCC version from compiler string
func extractGCCVersion(compilerStr string) string {
	re := regexp.MustCompile(`gcc.*?([0-9]+\.[0-9]+\.[0-9]+)`)
	if matches := re.FindStringSubmatch(compilerStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// parseMongoDBResponse parses MongoDB response and extracts detailed information
func parseMongoDBResponse(response []byte, command string) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	if len(response) < 36 {
		result.Product = "mongodb"
		return result
	}

	// Extract BSON document from OP_REPLY
	bsonData := response[36:]

	// Extract core information
	result.Version = extractStringValue(bsonData, "version")
	result.GitVersion = extractStringValue(bsonData, "gitVersion")
	result.Allocator = extractStringValue(bsonData, "allocator")
	result.JavaScriptEngine = extractStringValue(bsonData, "javascriptEngine")

	// Extract numeric fields
	if maxBSON := extractInt32Value(bsonData, "maxBsonObjectSize"); maxBSON > 0 {
		result.MaxBSONSize = int(maxBSON)
	}
	if bits := extractInt32Value(bsonData, "bits"); bits > 0 {
		result.ArchitectureBits = int(bits)
	}

	// Extract arrays
	result.StorageEngines = extractArrayStrings(bsonData, "storageEngines")

	// Extract build environment
	result.BuildArch = extractStringValue(bsonData, "distarch")
	if result.BuildArch == "" {
		result.BuildArch = extractStringValue(bsonData, "target_arch")
	}
	result.BuildOS = extractStringValue(bsonData, "target_os")
	result.BuildDistmod = extractStringValue(bsonData, "distmod")

	// Extract compiler info
	if cc := extractStringValue(bsonData, "cc"); cc != "" {
		result.GCCVersion = extractGCCVersion(cc)
	}

	// Extract OpenSSL info
	result.OpenSSLRunning = extractStringValue(bsonData, "running")
	if result.OpenSSLRunning == "" {
		result.OpenSSLCompiled = extractStringValue(bsonData, "compiled")
	}

	// Determine server type
	result.ServerType = "mongod"
	if msg := extractStringValue(bsonData, "msg"); strings.Contains(msg, "mongos") {
		result.ServerType = "mongos"
	}

	// Check authentication
	result.Authentication = "disabled"
	if extractStringValue(bsonData, "authInfo") != "" {
		result.Authentication = "enabled"
	} else if extractStringValue(bsonData, "saslSupportedMechs") != "" {
		result.Authentication = "partially enabled"
	}

	// Build product banner
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
	if result.BuildArch != "" {
		result.Product += fmt.Sprintf(" (%s)", result.BuildArch)
	}
	if result.Authentication != "disabled" {
		result.Product += fmt.Sprintf(" [auth:%s]", result.Authentication)
	}

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

	// Try MongoDB commands in order of usefulness
	commands := []string{"buildInfo", "isMaster", "hello", "serverStatus"}

	for i, command := range commands {
		requestID := int32(i + 1)
		message := createCorrectBSONQuery(command, requestID)
		if message == nil {
			continue
		}

		response, err := utils.SendRecv(conn, message, timeout)
		if err == nil && len(response) > 0 && isValidMongoDBResponse(response) {
			payload := parseMongoDBResponse(response, command)
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		}
	}

	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
