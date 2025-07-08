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

// createBSONDocument creates a properly formatted BSON document
func createBSONDocument(fieldName string, value int32) []byte {
	// Calculate document length: 4 (length) + 1 (type) + len(fieldName) + 1 (null) + 4 (int32) + 1 (terminator)
	docLen := 4 + 1 + len(fieldName) + 1 + 4 + 1

	doc := make([]byte, 0, docLen)

	// Document length (little endian)
	doc = append(doc, byte(docLen), byte(docLen>>8), byte(docLen>>16), byte(docLen>>24))

	// Field type (0x10 = int32)
	doc = append(doc, 0x10)

	// Field name + null terminator
	doc = append(doc, []byte(fieldName)...)
	doc = append(doc, 0x00)

	// Int32 value (little endian)
	doc = append(doc, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))

	// Document terminator
	doc = append(doc, 0x00)

	return doc
}

// createMongoDBQuery creates a properly formatted MongoDB OP_QUERY message
func createMongoDBQuery(command string, requestID int32) []byte {
	// Create BSON document for the command
	bsonDoc := createBSONDocument(command, 1)

	// OP_QUERY structure:
	// header(16) + flags(4) + collection(variable) + skip(4) + limit(4) + query(variable)

	flags := []byte{0x00, 0x00, 0x00, 0x00} // no flags
	collection := []byte("admin.$cmd\x00")  // admin.$cmd collection
	skip := []byte{0x00, 0x00, 0x00, 0x00}  // skip 0
	limit := []byte{0x01, 0x00, 0x00, 0x00} // limit 1

	// Calculate total message length
	messageLength := 16 + len(flags) + len(collection) + len(skip) + len(limit) + len(bsonDoc)

	// Create header
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(messageLength)) // message length
	binary.LittleEndian.PutUint32(header[4:8], uint32(requestID))     // request ID
	binary.LittleEndian.PutUint32(header[8:12], 0)                    // response to
	binary.LittleEndian.PutUint32(header[12:16], 2004)                // OP_QUERY opcode

	// Combine all parts
	message := make([]byte, 0, messageLength)
	message = append(message, header...)
	message = append(message, flags...)
	message = append(message, collection...)
	message = append(message, skip...)
	message = append(message, limit...)
	message = append(message, bsonDoc...)

	return message
}

// createMongoDBOpMsg creates a MongoDB OP_MSG message (modern protocol)
func createMongoDBOpMsg(command string, requestID int32) []byte {
	// Create BSON document for the command
	bsonDoc := createBSONDocument(command, 1)

	// Add $db field to specify database
	dbField := []byte{
		0x02,                // string type
		'$', 'd', 'b', 0x00, // field name "$db"
		0x06, 0x00, 0x00, 0x00, // string length (5 + null)
		'a', 'd', 'm', 'i', 'n', 0x00, // "admin" + null terminator
	}

	// Modify BSON document to include $db field
	// Remove the terminator from original doc and add $db field
	modifiedDoc := bsonDoc[:len(bsonDoc)-1] // Remove terminator
	modifiedDoc = append(modifiedDoc, dbField...)
	modifiedDoc = append(modifiedDoc, 0x00) // Add terminator back

	// Update document length
	newLen := len(modifiedDoc)
	binary.LittleEndian.PutUint32(modifiedDoc[0:4], uint32(newLen))

	// OP_MSG structure:
	// header(16) + flags(4) + sections
	// Section 0: kind(1) + document

	flags := []byte{0x00, 0x00, 0x00, 0x00} // no flags
	sectionKind := []byte{0x00}             // kind 0 (body)

	// Calculate total message length
	messageLength := 16 + len(flags) + len(sectionKind) + len(modifiedDoc)

	// Create header
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(messageLength)) // message length
	binary.LittleEndian.PutUint32(header[4:8], uint32(requestID))     // request ID
	binary.LittleEndian.PutUint32(header[8:12], 0)                    // response to
	binary.LittleEndian.PutUint32(header[12:16], 2013)                // OP_MSG opcode

	// Combine all parts
	message := make([]byte, 0, messageLength)
	message = append(message, header...)
	message = append(message, flags...)
	message = append(message, sectionKind...)
	message = append(message, modifiedDoc...)

	return message
}

// isValidMongoDBResponse validates MongoDB response (handles both OP_REPLY and OP_MSG)
func isValidMongoDBResponse(response []byte) bool {
	if len(response) < 16 { // Minimum header size
		return false
	}

	// Parse header
	messageLength := binary.LittleEndian.Uint32(response[0:4])
	opCode := binary.LittleEndian.Uint32(response[12:16])

	// Validate message length
	if messageLength < 16 || messageLength > 48*1024*1024 {
		return false
	}

	// Check opcode (OP_REPLY = 1, OP_MSG = 2013)
	if opCode == 1 {
		// OP_REPLY validation
		if len(response) < 36 {
			return false
		}
		numberReturned := binary.LittleEndian.Uint32(response[32:36])
		return numberReturned > 0
	} else if opCode == 2013 {
		// OP_MSG validation
		return len(response) >= 21 // header(16) + flags(4) + kind(1)
	}

	return false
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

// getBSONDataFromResponse extracts BSON data from response (handles both OP_REPLY and OP_MSG)
func getBSONDataFromResponse(response []byte) []byte {
	if len(response) < 16 {
		return nil
	}

	opCode := binary.LittleEndian.Uint32(response[12:16])

	if opCode == 1 { // OP_REPLY
		if len(response) < 36 {
			return nil
		}
		return response[36:] // Skip OP_REPLY header
	} else if opCode == 2013 { // OP_MSG
		if len(response) < 21 {
			return nil
		}
		// Skip header(16) + flags(4) + kind(1)
		return response[21:]
	}

	return nil
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

// parseMongoDBResponse extracts comprehensive information from MongoDB response
func parseMongoDBResponse(response []byte, command string) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{
		Vulnerable: false, // Always initialize vulnerable field
	}

	bsonData := getBSONDataFromResponse(response)
	if bsonData == nil {
		result.Product = "mongodb"
		return result
	}

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

	// Extract storage engines
	result.StorageEngines = extractArrayFromBSON(bsonData, "storageEngines")

	// Extract build environment info
	result.BuildArch = extractNestedStringFromBSON(bsonData, "buildEnvironment", "distarch")
	if result.BuildArch == "" {
		result.BuildArch = extractNestedStringFromBSON(bsonData, "buildEnvironment", "target_arch")
	}
	result.BuildOS = extractNestedStringFromBSON(bsonData, "buildEnvironment", "target_os")
	result.BuildDistmod = extractNestedStringFromBSON(bsonData, "buildEnvironment", "distmod")

	// Extract GCC version from compiler info
	if cc := extractNestedStringFromBSON(bsonData, "buildEnvironment", "cc"); cc != "" {
		result.GCCVersion = extractGCCVersion(cc)
	}

	// Extract OpenSSL info
	result.OpenSSLRunning = extractNestedStringFromBSON(bsonData, "openssl", "running")
	result.OpenSSLCompiled = extractNestedStringFromBSON(bsonData, "openssl", "compiled")

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

	// For listDatabases command, extract database names and set vulnerability
	if command == "listDatabases" {
		result.Databases = extractDatabaseNames(bsonData)
		if len(result.Databases) > 0 {
			result.Vulnerable = true
		}
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
	if result.Vulnerable {
		result.Product += " [VULNERABLE]"
	}

	return result
}

// tryListDatabases attempts to list databases using both OP_QUERY and OP_MSG protocols
func tryListDatabases(conn net.Conn, timeout time.Duration) ([]string, bool) {
	// First try OP_QUERY (legacy protocol)
	requestID := int32(999)
	message := createMongoDBQuery("listDatabases", requestID)
	if message != nil {
		response, err := utils.SendRecv(conn, message, timeout)
		if err == nil && len(response) > 0 && isValidMongoDBResponse(response) {
			bsonData := getBSONDataFromResponse(response)
			if bsonData != nil {
				errorMsg := extractStringFromBSON(bsonData, "errmsg")

				// If no error, extract databases
				if errorMsg == "" {
					databases := extractDatabaseNames(bsonData)
					return databases, len(databases) > 0
				}

				// If error is about legacy opcode removal, try OP_MSG
				if strings.Contains(errorMsg, "legacy-opcode-removal") ||
					strings.Contains(errorMsg, "Unsupported OP_QUERY") {
					// Try OP_MSG protocol
					requestID = int32(1000)
					msgMessage := createMongoDBOpMsg("listDatabases", requestID)
					if msgMessage != nil {
						msgResponse, msgErr := utils.SendRecv(conn, msgMessage, timeout)
						if msgErr == nil && len(msgResponse) > 0 && isValidMongoDBResponse(msgResponse) {
							msgBsonData := getBSONDataFromResponse(msgResponse)
							if msgBsonData != nil {
								msgErrorMsg := extractStringFromBSON(msgBsonData, "errmsg")
								if msgErrorMsg == "" {
									databases := extractDatabaseNames(msgBsonData)
									return databases, len(databases) > 0
								}
							}
						}
					}
				}
			}
		}
	}

	return nil, false
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
		message := createMongoDBQuery(command, requestID)
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

			// If we got detailed info from buildInfo, we're done with basic detection
			if command == "buildInfo" && payload.Version != "" {
				break
			}
		}
	}

	// If we have basic MongoDB detection and authentication is disabled, test for vulnerability
	if bestResult != nil && bestResult.Authentication == "disabled" {
		databases, vulnerable := tryListDatabases(conn, timeout)
		if vulnerable {
			bestResult.Databases = databases
			bestResult.Vulnerable = true
			// Update product banner to include vulnerability status
			if !strings.Contains(bestResult.Product, "[VULNERABLE]") {
				bestResult.Product += " [VULNERABLE]"
			}
		}
	}

	// Ensure vulnerable field is always set
	if bestResult != nil {
		// vulnerable field is already initialized to false in parseMongoDBResponse
		return plugins.CreateServiceFrom(target, *bestResult, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
