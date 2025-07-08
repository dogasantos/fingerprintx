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

// extractStringFromBSON extracts string values using simple pattern matching
func extractStringFromBSON(data []byte, fieldName string) string {
	// Look for field name followed by string data
	fieldBytes := []byte(fieldName)

	for i := 0; i < len(data)-len(fieldBytes)-10; i++ {
		// Check if we found the field name
		if i > 0 && data[i-1] == 0x02 { // String type
			// Check if field name matches
			match := true
			for j, b := range fieldBytes {
				if i+j >= len(data) || data[i+j] != b {
					match = false
					break
				}
			}

			if match && i+len(fieldBytes) < len(data) && data[i+len(fieldBytes)] == 0x00 {
				// Found field name, now extract string value
				strLenOffset := i + len(fieldBytes) + 1
				if strLenOffset+4 < len(data) {
					strLen := binary.LittleEndian.Uint32(data[strLenOffset : strLenOffset+4])
					if strLen > 0 && strLen < 1024 && strLenOffset+4+int(strLen) <= len(data) {
						strValue := string(data[strLenOffset+4 : strLenOffset+4+int(strLen)-1]) // -1 for null terminator
						if isPrintableString(strValue) {
							return strValue
						}
					}
				}
			}
		}
	}

	return ""
}

// extractInt32FromBSON extracts int32 values using simple pattern matching
func extractInt32FromBSON(data []byte, fieldName string) int32 {
	fieldBytes := []byte(fieldName)

	for i := 0; i < len(data)-len(fieldBytes)-10; i++ {
		// Check if we found the field name
		if i > 0 && data[i-1] == 0x10 { // Int32 type
			// Check if field name matches
			match := true
			for j, b := range fieldBytes {
				if i+j >= len(data) || data[i+j] != b {
					match = false
					break
				}
			}

			if match && i+len(fieldBytes) < len(data) && data[i+len(fieldBytes)] == 0x00 {
				// Found field name, now extract int32 value
				valueOffset := i + len(fieldBytes) + 1
				if valueOffset+4 <= len(data) {
					return int32(binary.LittleEndian.Uint32(data[valueOffset : valueOffset+4]))
				}
			}
		}
	}

	return 0
}

// extractArrayFromBSON extracts string arrays using pattern matching
func extractArrayFromBSON(data []byte, fieldName string) []string {
	var result []string
	fieldBytes := []byte(fieldName)

	for i := 0; i < len(data)-len(fieldBytes)-10; i++ {
		// Check if we found the field name
		if i > 0 && data[i-1] == 0x04 { // Array type
			// Check if field name matches
			match := true
			for j, b := range fieldBytes {
				if i+j >= len(data) || data[i+j] != b {
					match = false
					break
				}
			}

			if match && i+len(fieldBytes) < len(data) && data[i+len(fieldBytes)] == 0x00 {
				// Found array field, extract string elements
				arrayOffset := i + len(fieldBytes) + 1
				if arrayOffset+4 < len(data) {
					arrayLen := binary.LittleEndian.Uint32(data[arrayOffset : arrayOffset+4])
					if arrayLen > 4 && arrayLen < 1024 && arrayOffset+int(arrayLen) <= len(data) {
						// Scan array for string elements
						arrayData := data[arrayOffset+4 : arrayOffset+int(arrayLen)]
						for j := 0; j < len(arrayData)-5; j++ {
							if arrayData[j] == 0x02 { // String type
								// Skip index name (like "0", "1", etc.)
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

	return result
}

// isPrintableString checks if a string contains only printable characters
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

// parseMongoDBResponse extracts information from MongoDB response using simple pattern matching
func parseMongoDBResponse(response []byte, command string) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		result.Product = "mongodb"
		return result
	}

	bsonData := response[36:]

	// Extract basic information using pattern matching
	result.Version = extractStringFromBSON(bsonData, "version")
	result.GitVersion = extractStringFromBSON(bsonData, "gitVersion")
	result.Allocator = extractStringFromBSON(bsonData, "allocator")
	result.JavaScriptEngine = extractStringFromBSON(bsonData, "javascriptEngine")

	// Extract numeric fields
	if maxBSON := extractInt32FromBSON(bsonData, "maxBsonObjectSize"); maxBSON > 0 {
		result.MaxBSONSize = int(maxBSON)
	}
	if bits := extractInt32FromBSON(bsonData, "bits"); bits > 0 {
		result.ArchitectureBits = int(bits)
	}

	// Extract storage engines
	result.StorageEngines = extractArrayFromBSON(bsonData, "storageEngines")

	// Extract build environment info
	result.BuildArch = extractStringFromBSON(bsonData, "distarch")
	if result.BuildArch == "" {
		result.BuildArch = extractStringFromBSON(bsonData, "target_arch")
	}
	result.BuildOS = extractStringFromBSON(bsonData, "target_os")
	result.BuildDistmod = extractStringFromBSON(bsonData, "distmod")

	// Extract GCC version from compiler info
	if cc := extractStringFromBSON(bsonData, "cc"); cc != "" {
		result.GCCVersion = extractGCCVersion(cc)
	}

	// Extract OpenSSL info
	result.OpenSSLRunning = extractStringFromBSON(bsonData, "running")
	if result.OpenSSLRunning == "" {
		result.OpenSSLCompiled = extractStringFromBSON(bsonData, "compiled")
	}

	// Determine server type
	result.ServerType = "mongod"
	if msg := extractStringFromBSON(bsonData, "msg"); strings.Contains(msg, "mongos") {
		result.ServerType = "mongos"
	}

	// Check authentication status
	result.Authentication = "disabled"
	if extractStringFromBSON(bsonData, "authInfo") != "" {
		result.Authentication = "enabled"
	} else if extractStringFromBSON(bsonData, "saslSupportedMechs") != "" {
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

	// Try different MongoDB commands
	commands := []string{"isMaster", "hello", "buildInfo"}

	for i, command := range commands {
		requestID := int32(i + 1)
		message := createSimpleMongoDBQuery(command, requestID)
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
