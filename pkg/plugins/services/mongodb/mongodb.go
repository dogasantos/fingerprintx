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

// parseBSONInt64 parses a BSON int64 from data at offset
func parseBSONInt64(data []byte, offset int) (int64, int, error) {
	if offset+8 > len(data) {
		return 0, 0, fmt.Errorf("insufficient data for int64")
	}

	value := int64(binary.LittleEndian.Uint64(data[offset : offset+8]))
	return value, offset + 8, nil
}

// parseBSONBoolean parses a BSON boolean from data at offset
func parseBSONBoolean(data []byte, offset int) (bool, int, error) {
	if offset+1 > len(data) {
		return false, 0, fmt.Errorf("insufficient data for boolean")
	}

	value := data[offset] != 0
	return value, offset + 1, nil
}

// parseBSONArray parses a BSON array from data at offset
func parseBSONArray(data []byte, offset int) ([]interface{}, int, error) {
	if offset+4 >= len(data) {
		return nil, 0, fmt.Errorf("insufficient data for array length")
	}

	// Read array length
	arrayLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	if arrayLen < 5 || arrayLen > 1024*1024 { // Sanity check
		return nil, 0, fmt.Errorf("invalid array length: %d", arrayLen)
	}

	arrayEnd := offset + int(arrayLen)
	if arrayEnd > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for array content")
	}

	var values []interface{}
	currentOffset := offset + 4

	// Parse array elements
	for currentOffset < arrayEnd-1 { // -1 for terminator
		elementType := data[currentOffset]
		currentOffset++

		// Read element name (array indices like "0", "1", etc.)
		nameEnd := currentOffset
		for nameEnd < arrayEnd && data[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= arrayEnd {
			break
		}
		currentOffset = nameEnd + 1 // Skip null terminator

		// Parse element value based on type
		var value interface{}
		var err error

		switch elementType {
		case BSONTypeString:
			value, currentOffset, err = parseBSONString(data, currentOffset)
		case BSONTypeInt32:
			value, currentOffset, err = parseBSONInt32(data, currentOffset)
		case BSONTypeInt64:
			value, currentOffset, err = parseBSONInt64(data, currentOffset)
		case BSONTypeBoolean:
			value, currentOffset, err = parseBSONBoolean(data, currentOffset)
		default:
			// Skip unknown types
			break
		}

		if err != nil {
			break
		}

		if value != nil {
			values = append(values, value)
		}
	}

	return values, arrayEnd, nil
}

// parseBSONDocument parses a BSON document and returns key-value pairs
func parseBSONDocument(data []byte, offset int) (map[string]interface{}, int, error) {
	if offset+4 >= len(data) {
		return nil, 0, fmt.Errorf("insufficient data for document length")
	}

	// Read document length
	docLen := binary.LittleEndian.Uint32(data[offset : offset+4])
	if docLen < 5 || docLen > 16*1024*1024 { // Sanity check
		return nil, 0, fmt.Errorf("invalid document length: %d", docLen)
	}

	docEnd := offset + int(docLen)
	if docEnd > len(data) {
		return nil, 0, fmt.Errorf("insufficient data for document content")
	}

	result := make(map[string]interface{})
	currentOffset := offset + 4

	// Parse document elements
	for currentOffset < docEnd-1 { // -1 for terminator
		if currentOffset >= len(data) {
			break
		}

		elementType := data[currentOffset]
		if elementType == 0 { // Document terminator
			break
		}
		currentOffset++

		// Read element name
		nameStart := currentOffset
		nameEnd := currentOffset
		for nameEnd < docEnd && data[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= docEnd {
			break
		}

		elementName := string(data[nameStart:nameEnd])
		currentOffset = nameEnd + 1 // Skip null terminator

		// Parse element value based on type
		var value interface{}
		var err error

		switch elementType {
		case BSONTypeString:
			value, currentOffset, err = parseBSONString(data, currentOffset)
		case BSONTypeInt32:
			value, currentOffset, err = parseBSONInt32(data, currentOffset)
		case BSONTypeInt64:
			value, currentOffset, err = parseBSONInt64(data, currentOffset)
		case BSONTypeBoolean:
			value, currentOffset, err = parseBSONBoolean(data, currentOffset)
		case BSONTypeArray:
			value, currentOffset, err = parseBSONArray(data, currentOffset)
		case BSONTypeDocument:
			value, currentOffset, err = parseBSONDocument(data, currentOffset)
		default:
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
			// Skip this element and try to continue
			continue
		}

		result[elementName] = value
	}

	return result, docEnd, nil
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

// extractGCCVersion extracts GCC version from compiler string
func extractGCCVersion(compilerStr string) string {
	re := regexp.MustCompile(`gcc.*?([0-9]+\.[0-9]+\.[0-9]+)`)
	if matches := re.FindStringSubmatch(compilerStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractDatabaseNames extracts database names from listDatabases response
func extractDatabaseNames(bsonDoc map[string]interface{}) []string {
	var databases []string

	if v, ok := bsonDoc["databases"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if doc, ok := item.(map[string]interface{}); ok {
					if name, ok := doc["name"]; ok {
						if str, ok := name.(string); ok {
							databases = append(databases, str)
						}
					}
				}
			}
		}
	}

	return databases
}

// checkVulnerability checks if MongoDB is vulnerable (auth disabled + can list databases)
func checkVulnerability(conn net.Conn, timeout time.Duration, authDisabled bool) (bool, []string) {
	if !authDisabled {
		return false, nil
	}

	// Try to list databases
	requestID := int32(100)
	message := createMongoDBQuery("listDatabases", requestID)
	if message == nil {
		return false, nil
	}

	response, err := utils.SendRecv(conn, message, timeout)
	if err != nil || len(response) == 0 || !isValidMongoDBResponse(response) {
		return false, nil
	}

	// Parse response
	bsonDoc, _, err := parseBSONDocument(response, 36)
	if err != nil {
		return false, nil
	}

	// Extract database names
	databases := extractDatabaseNames(bsonDoc)
	if len(databases) > 0 {
		return true, databases // Vulnerable: can list databases without auth
	}

	return false, nil
}

// parseMongoDBResponse extracts information from MongoDB response and populates structured fields
func parseMongoDBResponse(response []byte, command string, conn net.Conn, timeout time.Duration) plugins.ServiceMongoDB {
	result := plugins.ServiceMongoDB{}

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		result.Product = "mongodb"
		return result
	}

	// Parse BSON document
	bsonDoc, _, err := parseBSONDocument(response, 36)
	if err != nil {
		result.Product = "mongodb"
		return result
	}

	// Extract basic information
	if v, ok := bsonDoc["version"]; ok {
		if str, ok := v.(string); ok {
			result.Version = str
		}
	}

	if v, ok := bsonDoc["gitVersion"]; ok {
		if str, ok := v.(string); ok {
			result.GitVersion = str
		}
	}

	if v, ok := bsonDoc["allocator"]; ok {
		if str, ok := v.(string); ok {
			result.Allocator = str
		}
	}

	if v, ok := bsonDoc["javascriptEngine"]; ok {
		if str, ok := v.(string); ok {
			result.JavaScriptEngine = str
		}
	}

	// Extract numeric fields
	if v, ok := bsonDoc["maxBsonObjectSize"]; ok {
		if num, ok := v.(int32); ok {
			result.MaxBSONSize = int(num)
		}
	}

	if v, ok := bsonDoc["bits"]; ok {
		if num, ok := v.(int32); ok {
			result.ArchitectureBits = int(num)
		}
	}

	if v, ok := bsonDoc["debug"]; ok {
		if b, ok := v.(bool); ok {
			result.DebugBuild = b
		}
	}

	// Extract storage engines
	if v, ok := bsonDoc["storageEngines"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if str, ok := item.(string); ok {
					result.StorageEngines = append(result.StorageEngines, str)
				}
			}
		}
	}

	// Extract modules
	if v, ok := bsonDoc["modules"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if str, ok := item.(string); ok {
					result.Modules = append(result.Modules, str)
				}
			}
		}
	}

	// Extract version array
	if v, ok := bsonDoc["versionArray"]; ok {
		if arr, ok := v.([]interface{}); ok {
			for _, item := range arr {
				if num, ok := item.(int32); ok {
					result.VersionArray = append(result.VersionArray, int(num))
				}
			}
		}
	}

	// Extract build environment
	if v, ok := bsonDoc["buildEnvironment"]; ok {
		if doc, ok := v.(map[string]interface{}); ok {
			if arch, ok := doc["distarch"]; ok {
				if str, ok := arch.(string); ok {
					result.BuildArch = str
				}
			}
			if arch, ok := doc["target_arch"]; ok && result.BuildArch == "" {
				if str, ok := arch.(string); ok {
					result.BuildArch = str
				}
			}
			if os, ok := doc["target_os"]; ok {
				if str, ok := os.(string); ok {
					result.BuildOS = str
				}
			}
			if distmod, ok := doc["distmod"]; ok {
				if str, ok := distmod.(string); ok {
					result.BuildDistmod = str
				}
			}
			if cc, ok := doc["cc"]; ok {
				if str, ok := cc.(string); ok {
					result.GCCVersion = extractGCCVersion(str)
				}
			}
			if cxxflags, ok := doc["cxxflags"]; ok {
				if str, ok := cxxflags.(string); ok {
					result.CXXFlags = str
				}
			}
			if linkflags, ok := doc["linkflags"]; ok {
				if str, ok := linkflags.(string); ok {
					result.LinkFlags = str
				}
			}
			if ccflags, ok := doc["ccflags"]; ok {
				if str, ok := ccflags.(string); ok {
					result.CCFlags = str
				}
			}
		}
	}

	// Extract OpenSSL information
	if v, ok := bsonDoc["openssl"]; ok {
		if doc, ok := v.(map[string]interface{}); ok {
			if compiled, ok := doc["compiled"]; ok {
				if str, ok := compiled.(string); ok {
					result.OpenSSLCompiled = str
				}
			}
			if running, ok := doc["running"]; ok {
				if str, ok := running.(string); ok {
					result.OpenSSLRunning = str
				}
			}
		}
	}

	// Extract cluster time
	if v, ok := bsonDoc["$clusterTime"]; ok {
		if doc, ok := v.(map[string]interface{}); ok {
			if clusterTime, ok := doc["clusterTime"]; ok {
				if str, ok := clusterTime.(string); ok {
					result.ClusterTime = str
				}
			}
		}
	}

	if v, ok := bsonDoc["operationTime"]; ok {
		if str, ok := v.(string); ok {
			result.OperationTime = str
		}
	}

	// Determine server type
	result.ServerType = "mongod"
	if v, ok := bsonDoc["msg"]; ok {
		if str, ok := v.(string); ok && strings.Contains(str, "mongos") {
			result.ServerType = "mongos"
		}
	}

	// Determine server role
	if v, ok := bsonDoc["ismaster"]; ok {
		if b, ok := v.(bool); ok && b {
			result.ServerRole = "primary"
		}
	}
	if v, ok := bsonDoc["isWritablePrimary"]; ok {
		if b, ok := v.(bool); ok && b {
			result.ServerRole = "primary"
		}
	}
	if v, ok := bsonDoc["secondary"]; ok {
		if b, ok := v.(bool); ok && b {
			result.ServerRole = "secondary"
		}
	}

	// Check authentication status
	result.Authentication = "disabled"
	if _, ok := bsonDoc["authInfo"]; ok {
		result.Authentication = "enabled"
	} else if _, ok := bsonDoc["saslSupportedMechs"]; ok {
		result.Authentication = "partially enabled"
	} else if _, ok := bsonDoc["authenticatedUsers"]; ok {
		result.Authentication = "enabled"
	}

	// Check vulnerability (if auth is disabled, try to list databases)
	authDisabled := result.Authentication == "disabled"
	vulnerable, databases := checkVulnerability(conn, timeout, authDisabled)
	result.Vulnerable = vulnerable
	result.Databases = databases

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
	commands := []string{"hello", "isMaster", "buildInfo"}

	for i, command := range commands {
		requestID := int32(i + 1)
		message := createMongoDBQuery(command, requestID)
		if message == nil {
			continue
		}

		response, err := utils.SendRecv(conn, message, timeout)
		if err == nil && len(response) > 0 && isValidMongoDBResponse(response) {
			payload := parseMongoDBResponse(response, command, conn, timeout)
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		}
	}

	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
