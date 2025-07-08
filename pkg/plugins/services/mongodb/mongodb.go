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

// createMongoDBHeader creates a MongoDB wire protocol header
func createMongoDBHeader(messageLength, requestID, responseTo, opCode int32) []byte {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(messageLength))
	binary.LittleEndian.PutUint32(header[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(header[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(header[12:16], uint32(opCode))
	return header
}

// createBSONDocument creates a simple BSON document for MongoDB commands
func createBSONDocument(command string, value interface{}) []byte {
	// Simple BSON document creation for basic commands
	// This is a minimal implementation for detection purposes

	var doc []byte

	if command == "hello" || command == "isMaster" {
		// Create BSON document: {hello: 1} or {isMaster: 1}
		doc = []byte{
			0x16, 0x00, 0x00, 0x00, // document length (22 bytes)
			0x10, // int32 type
		}
		doc = append(doc, []byte(command)...)
		doc = append(doc, 0x00)                              // null terminator
		doc = append(doc, []byte{0x01, 0x00, 0x00, 0x00}...) // value: 1
		doc = append(doc, 0x00)                              // document terminator
	} else if command == "buildInfo" {
		// Create BSON document: {buildInfo: 1}
		doc = []byte{
			0x15, 0x00, 0x00, 0x00, // document length (21 bytes)
			0x10, // int32 type
		}
		doc = append(doc, []byte(command)...)
		doc = append(doc, 0x00)                              // null terminator
		doc = append(doc, []byte{0x01, 0x00, 0x00, 0x00}...) // value: 1
		doc = append(doc, 0x00)                              // document terminator
	}

	return doc
}

// createMongoDBCommand creates a complete MongoDB command message
func createMongoDBCommand(command string, requestID int32) []byte {
	// Create BSON document
	bsonDoc := createBSONDocument(command, 1)
	if len(bsonDoc) == 0 {
		return nil
	}

	// OP_MSG format (opcode 2013)
	// Header + flagBits + sections
	flagBits := make([]byte, 4) // no flags set

	// Section 0 (body section)
	sectionKind := []byte{0x00} // kind 0 = body
	section := append(sectionKind, bsonDoc...)

	// Calculate total message length
	messageLength := 16 + 4 + len(section) // header + flagBits + section

	// Create header
	header := createMongoDBHeader(int32(messageLength), requestID, 0, 2013) // OP_MSG

	// Combine all parts
	message := append(header, flagBits...)
	message = append(message, section...)

	return message
}

// createLegacyQuery creates a legacy OP_QUERY message for hello/isMaster
func createLegacyQuery(command string, requestID int32) []byte {
	// OP_QUERY format (opcode 2004) - still supported for hello/isMaster
	bsonDoc := createBSONDocument(command, 1)
	if len(bsonDoc) == 0 {
		return nil
	}

	// OP_QUERY structure:
	// header + flags + fullCollectionName + numberToSkip + numberToReturn + query
	flags := make([]byte, 4)                       // no flags
	fullCollectionName := []byte("admin.$cmd\x00") // admin database, $cmd collection
	numberToSkip := make([]byte, 4)                // 0
	numberToReturn := make([]byte, 4)              // -1 (all)
	binary.LittleEndian.PutUint32(numberToReturn, 0xFFFFFFFF)

	// Calculate message length
	messageLength := 16 + 4 + len(fullCollectionName) + 4 + 4 + len(bsonDoc)

	// Create header
	header := createMongoDBHeader(int32(messageLength), requestID, 0, 2004) // OP_QUERY

	// Combine all parts
	message := append(header, flags...)
	message = append(message, fullCollectionName...)
	message = append(message, numberToSkip...)
	message = append(message, numberToReturn...)
	message = append(message, bsonDoc...)

	return message
}

// isValidMongoDBResponse checks if response is a valid MongoDB response
func isValidMongoDBResponse(response []byte) bool {
	if len(response) < 16 {
		return false
	}

	// Check message header
	messageLength := binary.LittleEndian.Uint32(response[0:4])
	if messageLength < 16 || messageLength > 48*1024*1024 { // MongoDB max message size
		return false
	}

	if int(messageLength) != len(response) {
		return false
	}

	// Check opcode (should be OP_REPLY=1 or OP_MSG=2013)
	opCode := binary.LittleEndian.Uint32(response[12:16])
	if opCode != 1 && opCode != 2013 {
		return false
	}

	// Look for MongoDB-specific indicators in the response
	responseStr := strings.ToLower(string(response))
	mongoIndicators := []string{
		"mongodb", "mongo", "ismaster", "hello", "version",
		"buildinfo", "gitversion", "maxbsonobjectsize",
	}

	for _, indicator := range mongoIndicators {
		if strings.Contains(responseStr, indicator) {
			return true
		}
	}

	return false
}

// parseMongoDBResponse extracts information from MongoDB response
func parseMongoDBResponse(response []byte, command string) (map[string]any, string) {
	info := make(map[string]any)
	responseStr := string(response)

	info["Response_Length"] = fmt.Sprintf("%d", len(response))
	info["Command_Used"] = command

	// Extract version information
	versionPatterns := []string{
		`"version"\s*:\s*"([^"]+)"`,
		`version["\s]*[:=]\s*["\s]*([0-9]+\.[0-9]+\.[0-9]+[^"\s]*)`,
		`gitVersion["\s]*[:=]\s*["\s]*([^"\s,}]+)`,
	}

	var version string
	for _, pattern := range versionPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			version = strings.Trim(matches[1], `"`)
			break
		}
	}

	// Extract server type (mongod/mongos)
	serverTypePatterns := []string{
		`"msg"\s*:\s*"([^"]*mongod[^"]*)"`,
		`"msg"\s*:\s*"([^"]*mongos[^"]*)"`,
		`"process"\s*:\s*"([^"]+)"`,
	}

	var serverType string
	for _, pattern := range serverTypePatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			serverType = matches[1]
			break
		}
	}

	// Extract build information
	buildPatterns := []string{
		`"buildEnvironment"\s*:\s*{[^}]*"target_arch"\s*:\s*"([^"]+)"`,
		`"buildEnvironment"\s*:\s*{[^}]*"target_os"\s*:\s*"([^"]+)"`,
		`"allocator"\s*:\s*"([^"]+)"`,
	}

	var buildInfo []string
	for _, pattern := range buildPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			buildInfo = append(buildInfo, matches[1])
		}
	}

	// Extract replica set information
	replicaSetPatterns := []string{
		`"setName"\s*:\s*"([^"]+)"`,
		`"ismaster"\s*:\s*(true|false)`,
		`"secondary"\s*:\s*(true|false)`,
	}

	var replicaInfo []string
	for _, pattern := range replicaSetPatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
			replicaInfo = append(replicaInfo, matches[1])
		}
	}

	// Extract max BSON object size
	maxBSONPattern := `"maxBsonObjectSize"\s*:\s*([0-9]+)`
	re := regexp.MustCompile(`(?i)` + maxBSONPattern)
	if matches := re.FindStringSubmatch(responseStr); len(matches) > 1 {
		info["Max_BSON_Size"] = matches[1]
	}

	// Store extracted information
	if version != "" {
		info["MongoDB_Version"] = version
	}
	if serverType != "" {
		info["Server_Type"] = serverType
	}
	if len(buildInfo) > 0 {
		info["Build_Info"] = strings.Join(buildInfo, "; ")
	}
	if len(replicaInfo) > 0 {
		info["Replica_Set"] = strings.Join(replicaInfo, "; ")
	}

	// Check for specific MongoDB features
	if strings.Contains(responseStr, "ismaster") {
		info["Feature"] = "Master/Slave Replication"
	}
	if strings.Contains(responseStr, "setName") {
		info["Feature"] = "Replica Set"
	}
	if strings.Contains(responseStr, "mongos") {
		info["Feature"] = "Sharded Cluster"
	}

	// Create product banner
	productBanner := "mongodb"
	if version != "" {
		productBanner = fmt.Sprintf("mongodb %s", version)
	}
	if serverType != "" {
		if strings.Contains(strings.ToLower(serverType), "mongod") {
			productBanner += " (mongod)"
		} else if strings.Contains(strings.ToLower(serverType), "mongos") {
			productBanner += " (mongos)"
		}
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

	for _, command := range commands {
		// Try modern OP_MSG format first
		requestID := int32(1)
		message := createMongoDBCommand(command, requestID)
		if message != nil {
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

		// Try legacy OP_QUERY format for hello/isMaster
		if command == "hello" || command == "isMaster" {
			legacyMessage := createLegacyQuery(command, requestID)
			if legacyMessage != nil {
				response, err := utils.SendRecv(conn, legacyMessage, timeout)
				if err == nil && len(response) > 0 && isValidMongoDBResponse(response) {
					infoMap, productBanner := parseMongoDBResponse(response, command+"_legacy")
					mongoInfo := fmt.Sprintf("%s", infoMap)
					payload := plugins.ServiceMongoDB{
						Info:    mongoInfo,
						Product: productBanner,
					}
					return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
				}
			}
		}
	}

	return nil, nil
}

func (p *MongoDBPlugin) Priority() int {
	return 800
}
