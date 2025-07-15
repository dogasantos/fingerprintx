package amqp

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/vcore8/fingerprintx/pkg/plugins"
	utils "github.com/vcore8/fingerprintx/pkg/plugins/pluginutils"
)

const AMQP = "amqp"

// Ports for known AMQP protocols (including RabbitMQ)
var commonAMQPorts = map[int]struct{}{
	5672: {}, // RabbitMQ AMQP
}

// init function to register the plugin
func init() {
	plugins.RegisterPlugin(&AMQPPlugin{})
}

// AMQPPlugin struct for the plugin
type AMQPPlugin struct{}

func DetectAMQP(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.ServiceAMQP, error) {
	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Send a request and get the response (AMQP handshake)
	request := []byte("AMQP\x00\x00\x09\x01") // AMQP handshake

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, fmt.Errorf("error during AMQP response: %w", err)
	}

	// Check for an empty response
	if len(response) == 0 {
		return nil, fmt.Errorf("empty response received")
	}

	// First Matching Condition: Check if the response contains "rabbit@" or "RabbitMQ"
	if bytes.Contains(response, []byte("rabbit@")) || bytes.Contains(response, []byte("RabbitMQ")) {
		// Extract the version from the response
		version := extractVersion(response)

		// Extract the text fields from the response
		textFields := extractText(response)

		// Return the service metadata
		service := &plugins.ServiceAMQP{
			Provider: "RabbitMQ", // Set as RabbitMQ since we detected AMQP
			Version:  version,    // Extracted version
			Metadata: textFields, // Include the extracted text fields
		}

		return service, nil
	}

	// Second Matching Condition: Ensure the first 4 bytes are "AMQP"
	if len(response) >= 4 && bytes.Equal(response[:4], []byte("AMQP")) {
		// Extract the version from the response
		version := extractVersion(response)

		// Extract the text fields from the response
		textFields := extractText(response)

		// Return the service metadata
		service := &plugins.ServiceAMQP{
			Provider: "RabbitMQ", // Set as RabbitMQ since we detected AMQP
			Version:  version,    // Extracted version
			Metadata: textFields, // Include the extracted text fields
		}

		return service, nil
	}

	// If neither match is found, return nil
	return nil, nil
}

// extractVersion extracts the version from the response
func extractVersion(response []byte) string {
	// Look for the "versionS" field in the response
	startIndex := bytes.Index(response, []byte("versionS"))
	if startIndex == -1 {
		return "Unknown"
	}

	// Skip "versionS" and the next 3 null bytes (\x00\x00\x00)
	startIndex += len("versionS") + 3

	// Ensure there is at least one byte for the length byte
	if startIndex >= len(response) {
		return "Unknown"
	}

	// Read the length byte (\x05 or \x06)
	lengthByte := response[startIndex]
	startIndex++ // Move past the length byte

	// Check that there are enough bytes for the version string
	if startIndex+int(lengthByte) > len(response) {
		return "Unknown"
	}

	// Extract the version string based on the length byte
	versionBytes := response[startIndex : startIndex+int(lengthByte)]

	// Return the version string
	return string(versionBytes)
}

func cleanText(input string) string {
	// Replace null bytes (0x00 or '\u0000') with spaces
	input = strings.ReplaceAll(input, "\u0000", " ")

	// Optionally remove other non-printable characters (like control characters) except for spaces
	reControl := regexp.MustCompile(`[^\x20-\x7E]+`)
	input = reControl.ReplaceAllString(input, " ")

	// Replace multiple spaces with a single space
	reMultipleSpaces := regexp.MustCompile(`\s+`)
	input = reMultipleSpaces.ReplaceAllString(input, " ")

	// Manually clean known problematic text prefixes
	input = strings.Replace(input, "7Copyright", "Copyright", -1)
	input = strings.Replace(input, "9Licensed", "Licensed", -1)
	input = strings.Replace(input, "productS", "Product", -1)
	input = strings.Replace(input, "platformS", "Platform", -1)
	input = strings.Replace(input, "versionS", "Version", -1)

	// Deduplicate substrings within the details
	parts := strings.Fields(input) // Split by spaces into parts
	seen := make(map[string]struct{})
	var deduplicated []string
	for _, part := range parts {
		if _, exists := seen[part]; !exists {
			seen[part] = struct{}{}
			deduplicated = append(deduplicated, part)
		}
	}

	// Join back into a single string
	return strings.Join(deduplicated, " ")
}

func extractText(response []byte) map[string]string {
	// Map to store the extracted fields
	extractedFields := make(map[string]string)

	// Define known tags to search for in the response
	tags := []string{
		"provider",
		"versionS",
		"platformS",
		"productS",
		"copyrightS",
		"platformS",
		"informationS",
	}

	// Iterate through each tag and extract the associated text
	for _, tag := range tags {
		// Find the tag in the response
		startIndex := bytes.Index(response, []byte(tag))
		if startIndex != -1 {
			// Skip the tag and the next 3 null bytes
			startIndex += len(tag) + 3
			// Extract the text after the tag (null-terminated string)
			textEnd := bytes.IndexByte(response[startIndex:], 0) // Find the next null byte
			if textEnd == -1 {
				textEnd = len(response) // If no null byte is found, take till the end of the response
			}
			// Extract the text and clean it
			extractedText := string(response[startIndex : startIndex+textEnd])
			cleanedText := cleanText(extractedText)
			// Store the cleaned text
			extractedFields[tag] = cleanedText
		}
	}
	return extractedFields
}

// Run is the main execution function of the plugin
func (p *AMQPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Ensure serviceMetadata is checked for nil
	serviceMetadata, err := DetectAMQP(conn, timeout, target)
	if err != nil {
		return nil, fmt.Errorf("error during AMQP detection: %w", err)
	}

	// If no service detected, return a default service
	if serviceMetadata == nil {
		return nil, nil
	}

	// Return the service details if a match is found
	return plugins.CreateServiceFrom(target, serviceMetadata, false, serviceMetadata.Version, plugins.TCP), nil
}

// PortPriority prioritizes known AMQP ports
func (p *AMQPPlugin) PortPriority(port uint16) bool {
	_, ok := commonAMQPorts[int(port)]
	return ok
}

// Name returns the name of the plugin
func (p *AMQPPlugin) Name() string {
	return AMQP
}

// Type specifies the protocol type handled by this plugin
func (p *AMQPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *AMQPPlugin) Priority() int {
	return 500
}
