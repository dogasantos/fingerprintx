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
	} else if command == "listDatabases" {
		// Simple listDatabases command: { "listDatabases": 1 }
		bsonDoc = []byte{
			0x1a, 0x00, 0x00, 0x00, // document length (26 bytes)
			0x10,                                                                  // int32 type
			'l', 'i', 's', 't', 'D', 'a', 't', 'a', 'b', 'a', 's', 'e', 's', 0x00, // field name "listDatabases"
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

// extractStringFromBSON extracts string values using pattern matching
func extractStringFromBSON(data []byte, fieldName string) string {
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

// extractInt32FromBSON extracts int32 values using pattern matching
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

// extractBoolFromBSON extracts boolean values using pattern matching
func extractBoolFromBSON(data []byte, fieldName string) bool {
	fieldBytes := []byte(fieldName)

	for i := 0; i < len(data)-len(fieldBytes)-10; i++ {
		// Check if we found the field name
		if i > 0 && data[i-1] == 0x08 { // Boolean type
			// Check if field name matches
			match := true
			for j, b := range fieldBytes {
				if i+j >= len(data) || data[i+j] != b {
					match = false
					break
				}
			}

			if match && i+len(fieldBytes) < len(data) && data[i+len(fieldBytes)] == 0x00 {
				// Found field name, now extract boolean value
				valueOffset := i + len(fieldBytes) + 1
				if valueOffset < len(data) {
					return data[valueOffset] != 0x00
				}
			}
		}
	}

	return false
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

// extractIntArrayFromBSON extracts integer arrays using pattern matching
func extractIntArrayFromBSON(data []byte, fieldName string) []int {
	var result []int
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
				// Found array field, extract int elements
				arrayOffset := i + len(fieldBytes) + 1
				if arrayOffset+4 < len(data) {
					arrayLen := binary.LittleEndian.Uint32(data[arrayOffset : arrayOffset+4])
					if arrayLen > 4 && arrayLen < 1024 && arrayOffset+int(arrayLen) <= len(data) {
						// Scan array for int elements
						arrayData := data[arrayOffset+4 : arrayOffset+int(arrayLen)]
						for j := 0; j < len(arrayData)-8; j++ {
							if arrayData[j] == 0x10 { // Int32 type
								// Skip index name (like "0", "1", etc.)
								nameEnd := j + 1
								for nameEnd < len(arrayData) && arrayData[nameEnd] != 0x00 {
									nameEnd++
								}
								if nameEnd+5 <= len(arrayData) {
									valueOffset := nameEnd + 1
									value := int32(binary.LittleEndian.Uint32(arrayData[valueOffset : valueOffset+4]))
									result = append(result, int(value))
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

// extractNestedStringFromBSON extracts string from nested document
func extractNestedStringFromBSON(data []byte, parentField, childField string) string {
	parentBytes := []byte(parentField)

	for i := 0; i < len(data)-len(parentBytes)-20; i++ {
		// Check if we found the parent field
		if i > 0 && data[i-1] == 0x03 { // Document type
			// Check if parent field name matches
			match := true
			for j, b := range parentBytes {
				if i+j >= len(data) || data[i+j] != b {
					match = false
					break
				}
			}

			if match && i+len(parentBytes) < len(data) && data[i+len(parentBytes)] == 0x00 {
				// Found parent document, now look for child field
				docOffset := i + len(parentBytes) + 1
				if docOffset+4 < len(data) {
					docLen := binary.LittleEndian.Uint32(data[docOffset : docOffset+4])
					if docLen > 4 && docLen < 1024 && docOffset+int(docLen) <= len(data) {
						// Search within the nested document
						docData := data[docOffset+4 : docOffset+int(docLen)]
						return extractStringFromBSON(docData, childField)
					}
				}
			}
		}
	}

	return ""
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

// extractDatabaseNames extracts database names from listDatabases response
func extractDatabaseNames(data []byte) []string {
	var databases []string

	// Look for "databases" array in the response
	for i := 0; i < len(data)-20; i++ {
		if i > 0 && data[i-1] == 0x04 { // Array type
			// Check for "databases" field name
			if i+9 < len(data) && string(data[i:i+9]) == "databases" && data[i+9] == 0x00 {
				// Found databases array
				arrayOffset := i + 10
				if arrayOffset+4 < len(data) {
					arrayLen := binary.LittleEndian.Uint32(data[arrayOffset : arrayOffset+4])
					if arrayLen > 4 && arrayLen < 4096 && arrayOffset+int(arrayLen) <= len(data) {
						// Parse array elements (each is a document with "name" field)
						arrayData := data[arrayOffset+4 : arrayOffset+int(arrayLen)]
						for j := 0; j < len(arrayData)-10; j++ {
							if arrayData[j] == 0x03 { // Document type
								// Skip index and look for "name" field in document
								docOffset := j + 2 // Skip type and index
								for docOffset < len(arrayData) && arrayData[docOffset] != 0x00 {
									docOffset++
								}
								docOffset++ // Skip null terminator
								if docOffset+4 < len(arrayData) {
									docLen := binary.LittleEndian.Uint32(arrayData[docOffset : docOffset+4])
									if docLen > 4 && docLen < 256 && docOffset+int(docLen) <= len(arrayData) {
										docData := arrayData[docOffset+4 : docOffset+int(docLen)]
										if name := extractStringFromBSON(docData, "name"); name != "" {
											databases = append(databases, name)
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

	return databases
}

// parseMongoDBResponse extracts comprehensive information from MongoDB response
func parseMongoDBResponse(response []byte, command string) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		result.Product = "mongodb"
		return result
	}

	bsonData := response[36:]

	// Extract basic information
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

	// Extract boolean fields
	result.DebugBuild = extractBoolFromBSON(bsonData, "debug")

	// Extract arrays
	result.StorageEngines = extractArrayFromBSON(bsonData, "storageEngines")
	result.Modules = extractArrayFromBSON(bsonData, "modules")
	result.VersionArray = extractIntArrayFromBSON(bsonData, "versionArray")

	// Extract build environment info
	result.BuildArch = extractNestedStringFromBSON(bsonData, "buildEnvironment", "distarch")
	if result.BuildArch == "" {
		result.BuildArch = extractNestedStringFromBSON(bsonData, "buildEnvironment", "target_arch")
	}
	result.BuildOS = extractNestedStringFromBSON(bsonData, "buildEnvironment", "target_os")
	result.BuildDistmod = extractNestedStringFromBSON(bsonData, "buildEnvironment", "distmod")
	result.CXXFlags = extractNestedStringFromBSON(bsonData, "buildEnvironment", "cxxflags")
	result.LinkFlags = extractNestedStringFromBSON(bsonData, "buildEnvironment", "linkflags")
	result.CCFlags = extractNestedStringFromBSON(bsonData, "buildEnvironment", "ccflags")

	// Extract GCC version from compiler info
	if cc := extractNestedStringFromBSON(bsonData, "buildEnvironment", "cc"); cc != "" {
		result.GCCVersion = extractGCCVersion(cc)
	}
	if result.GCCVersion == "" {
		if cxx := extractNestedStringFromBSON(bsonData, "buildEnvironment", "cxx"); cxx != "" {
			result.GCCVersion = extractGCCVersion(cxx)
		}
	}

	// Extract OpenSSL info
	result.OpenSSLRunning = extractNestedStringFromBSON(bsonData, "openssl", "running")
	result.OpenSSLCompiled = extractNestedStringFromBSON(bsonData, "openssl", "compiled")

	// Extract cluster time information
	result.ClusterTime = extractStringFromBSON(bsonData, "clusterTime")
	result.OperationTime = extractStringFromBSON(bsonData, "operationTime")

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

	// For listDatabases command, extract database names
	if command == "listDatabases" {
		result.Databases = extractDatabaseNames(bsonData)
		if len(result.Databases) > 0 && result.Authentication == "disabled" {
			result.Vulnerable = true
		}
	}

	// Create comprehensive product banner
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
	if result.Vulnerable {
		result.Product += " [VULNERABLE]"
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

	// Try different MongoDB commands in order of information richness
	commands := []string{"buildInfo", "isMaster", "hello"}

	var bestResult *plugins.ServiceMongoDB

	for i, command := range commands {
		requestID := int32(i + 1)
		message := createSimpleMongoDBQuery(command, requestID)
		if message == nil {
			continue
		}

		response, err := utils.SendRecv(conn, message, timeout)
		if err == nil && len(response) > 0 && isValidMongoDBResponse(response) {
			payload := parseMongoDBResponse(response, command)

			// Keep the result with the most information
			if bestResult == nil || payload.Version != "" {
				bestResult = &payload
			}

			// If we got detailed info from buildInfo, we're done
			if command == "buildInfo" && payload.Version != "" {
				break
			}
		}
	}

	// If we have basic MongoDB detection, try to check for vulnerability
	if bestResult != nil && bestResult.Authentication == "disabled" {
		// Try listDatabases to check if we can access database list
		message := createSimpleMongoDBQuery("listDatabases", 999)
		if message != nil {
			response, err := utils.SendRecv(conn, message, timeout)
			if err == nil && len(response) > 0 && isValidMongoDBResponse(response) {
				dbResult := parseMongoDBResponse(response, "listDatabases")
				if len(dbResult.Databases) > 0 {
					bestResult.Databases = dbResult.Databases
					bestResult.Vulnerable = true
					// Update product banner to include vulnerability status
					if !strings.Contains(bestResult.Product, "[VULNERABLE]") {
						bestResult.Product += " [VULNERABLE]"
					}
				}
			}
		}
	}

	if bestResult != nil {
		return plugins.CreateServiceFrom(target, *bestResult, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
