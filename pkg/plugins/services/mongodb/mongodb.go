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

	// Look for MongoDB-specific content
	responseStr := strings.ToLower(string(response))
	mongoIndicators := []string{
		"ismaster", "hello", "version", "mongodb", "buildinfo",
		"maxbsonobjectsize", "gitversion", "allocator", "javascriptengine",
	}

	for _, indicator := range mongoIndicators {
		if strings.Contains(responseStr, indicator) {
			return true
		}
	}

	return false
}

// extractStringValue extracts string value using multiple patterns
func extractStringValue(data string, key string) string {
	patterns := []string{
		fmt.Sprintf(`"%s"\s*:\s*"([^"]+)"`, regexp.QuoteMeta(key)),
		fmt.Sprintf(`%s["\x00\s]*[:\x00]\s*["\x00]*([^"\x00\s,}]+)`, regexp.QuoteMeta(key)),
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(data); len(matches) > 1 {
			return strings.Trim(matches[1], `"`)
		}
	}
	return ""
}

// extractArrayValues extracts array values
func extractArrayValues(data string, key string) []string {
	var values []string

	// Pattern for JSON array
	pattern := fmt.Sprintf(`"%s"\s*:\s*\[\s*([^\]]+)\s*\]`, regexp.QuoteMeta(key))
	re := regexp.MustCompile(pattern)
	if matches := re.FindStringSubmatch(data); len(matches) > 1 {
		// Extract quoted strings from array content
		arrayContent := matches[1]
		stringRe := regexp.MustCompile(`"([^"]+)"`)
		stringMatches := stringRe.FindAllStringSubmatch(arrayContent, -1)
		for _, match := range stringMatches {
			if len(match) > 1 {
				values = append(values, match[1])
			}
		}
	}

	return values
}

// extractBuildEnvironment extracts detailed build environment information
func extractBuildEnvironment(data string) map[string]string {
	buildEnv := make(map[string]string)

	// Look for buildEnvironment object
	buildEnvPattern := `"buildEnvironment"\s*:\s*\{([^}]+)\}`
	re := regexp.MustCompile(buildEnvPattern)
	if matches := re.FindStringSubmatch(data); len(matches) > 1 {
		buildContent := matches[1]

		// Extract individual build environment fields
		fields := []string{
			"distarch", "cc", "cxx", "cxxflags", "linkflags", "ccflags",
			"target_arch", "target_os", "distmod",
		}

		for _, field := range fields {
			value := extractStringValue(buildContent, field)
			if value != "" {
				buildEnv[field] = value
			}
		}
	}

	return buildEnv
}

// extractOpenSSLInfo extracts OpenSSL information
func extractOpenSSLInfo(data string) map[string]string {
	openssl := make(map[string]string)

	// Look for openssl object
	opensslPattern := `"openssl"\s*:\s*\{([^}]+)\}`
	re := regexp.MustCompile(opensslPattern)
	if matches := re.FindStringSubmatch(data); len(matches) > 1 {
		opensslContent := matches[1]

		compiled := extractStringValue(opensslContent, "compiled")
		running := extractStringValue(opensslContent, "running")

		if compiled != "" {
			openssl["compiled"] = compiled
		}
		if running != "" {
			openssl["running"] = running
		}
	}

	return openssl
}

// checkAuthenticationStatus checks if authentication is enabled
func checkAuthenticationStatus(data string) string {
	// Look for authentication-related indicators
	if strings.Contains(data, `"authInfo"`) {
		return "enabled"
	}
	if strings.Contains(data, `"authenticatedUsers"`) {
		return "enabled"
	}
	if strings.Contains(data, `"authenticationMechanisms"`) {
		return "partially enabled"
	}
	if strings.Contains(data, `"saslSupportedMechs"`) {
		return "partially enabled"
	}

	// Check for specific auth-related fields
	authPatterns := []string{
		`"authenticationDatabase"`,
		`"authSource"`,
		`"authMechanism"`,
	}

	for _, pattern := range authPatterns {
		if strings.Contains(data, pattern) {
			return "partially enabled"
		}
	}

	return "disabled"
}

// parseMongoDBResponse extracts comprehensive information from MongoDB response
func parseMongoDBResponse(response []byte, command string) (map[string]any, string) {
	info := make(map[string]any)

	info["Response_Length"] = len(response)
	info["Command_Used"] = command

	// Skip OP_REPLY header (36 bytes) to get to BSON document
	if len(response) < 36 {
		return info, "mongodb"
	}

	responseStr := string(response)

	// Extract basic version information
	version := extractStringValue(responseStr, "version")
	gitVersion := extractStringValue(responseStr, "gitVersion")

	// Extract version array
	versionArrayPattern := `"versionArray"\s*:\s*\[\s*([^\]]+)\s*\]`
	re := regexp.MustCompile(versionArrayPattern)
	if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
		info["Version_Array"] = matches[1]
	}

	// Extract runtime information
	allocator := extractStringValue(responseStr, "allocator")
	jsEngine := extractStringValue(responseStr, "javascriptEngine")

	// Extract system information
	bits := extractStringValue(responseStr, "bits")
	debug := extractStringValue(responseStr, "debug")
	maxBSONSize := extractStringValue(responseStr, "maxBsonObjectSize")

	// Extract storage engines
	storageEngines := extractArrayValues(responseStr, "storageEngines")

	// Extract modules
	modules := extractArrayValues(responseStr, "modules")

	// Extract build environment
	buildEnv := extractBuildEnvironment(responseStr)

	// Extract OpenSSL information
	opensslInfo := extractOpenSSLInfo(responseStr)

	// Extract cluster and operation time
	clusterTime := extractStringValue(responseStr, "clusterTime")
	operationTime := extractStringValue(responseStr, "operationTime")

	// Check authentication status
	authStatus := checkAuthenticationStatus(responseStr)

	// Extract server type and role
	var serverType, serverRole string
	if strings.Contains(responseStr, "mongos") {
		serverType = "mongos"
	} else {
		serverType = "mongod"
	}

	if strings.Contains(responseStr, `"ismaster":true`) || strings.Contains(responseStr, `"isWritablePrimary":true`) {
		serverRole = "primary"
	} else if strings.Contains(responseStr, `"secondary":true`) {
		serverRole = "secondary"
	}

	// Store all extracted information
	if version != "" {
		info["MongoDB_Version"] = version
	}
	if gitVersion != "" {
		info["Git_Version"] = gitVersion
	}
	if allocator != "" {
		info["Allocator"] = allocator
	}
	if jsEngine != "" {
		info["JavaScript_Engine"] = jsEngine
	}
	if bits != "" {
		info["Architecture_Bits"] = bits
	}
	if debug != "" {
		info["Debug_Build"] = debug
	}
	if maxBSONSize != "" {
		info["Max_BSON_Size"] = maxBSONSize
	}
	if len(storageEngines) > 0 {
		info["Storage_Engines"] = strings.Join(storageEngines, ", ")
	}
	if len(modules) > 0 {
		info["Modules"] = strings.Join(modules, ", ")
	} else {
		info["Modules"] = "none"
	}
	if authStatus != "" {
		info["Authentication"] = authStatus
	}
	if serverType != "" {
		info["Server_Type"] = serverType
	}
	if serverRole != "" {
		info["Server_Role"] = serverRole
	}
	if clusterTime != "" {
		info["Cluster_Time"] = clusterTime
	}
	if operationTime != "" {
		info["Operation_Time"] = operationTime
	}

	// Store build environment details
	if len(buildEnv) > 0 {
		var buildDetails []string
		if arch, ok := buildEnv["distarch"]; ok {
			buildDetails = append(buildDetails, "arch:"+arch)
		} else if arch, ok := buildEnv["target_arch"]; ok {
			buildDetails = append(buildDetails, "arch:"+arch)
		}
		if os, ok := buildEnv["target_os"]; ok {
			buildDetails = append(buildDetails, "os:"+os)
		}
		if distmod, ok := buildEnv["distmod"]; ok {
			buildDetails = append(buildDetails, "distmod:"+distmod)
		}
		if cc, ok := buildEnv["cc"]; ok {
			// Extract just the compiler version
			ccRe := regexp.MustCompile(`gcc.*?([0-9]+\.[0-9]+\.[0-9]+)`)
			if matches := ccRe.FindStringSubmatch(cc); len(matches) > 1 {
				buildDetails = append(buildDetails, "gcc:"+matches[1])
			}
		}

		if len(buildDetails) > 0 {
			info["Build_Environment"] = strings.Join(buildDetails, "; ")
		}
	}

	// Store OpenSSL information
	if len(opensslInfo) > 0 {
		if running, ok := opensslInfo["running"]; ok {
			info["OpenSSL"] = running
		} else if compiled, ok := opensslInfo["compiled"]; ok {
			info["OpenSSL"] = compiled
		}
	}

	// Create comprehensive product banner
	productBanner := "mongodb"
	if version != "" {
		productBanner = fmt.Sprintf("mongodb %s", version)
	}
	if serverType != "" {
		productBanner += fmt.Sprintf(" (%s)", serverType)
	}
	if allocator != "" {
		productBanner += fmt.Sprintf(" [%s]", allocator)
	}
	if len(buildEnv) > 0 {
		if arch, ok := buildEnv["distarch"]; ok {
			productBanner += fmt.Sprintf(" (%s)", arch)
		} else if arch, ok := buildEnv["target_arch"]; ok {
			productBanner += fmt.Sprintf(" (%s)", arch)
		}
	}
	if authStatus != "disabled" {
		productBanner += fmt.Sprintf(" [auth:%s]", authStatus)
	}

	return info, productBanner
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
			infoMap, productBanner := parseMongoDBResponse(response, command)
			mongoInfo := fmt.Sprintf("%s", infoMap)
			payload := plugins.ServiceMongoDB{
				Info:    mongoInfo,
				Product: productBanner,
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		}
	}

	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
