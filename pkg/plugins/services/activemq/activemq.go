package activemq

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

type MQPlugin struct{}

const MQ = "activemq"

// Ports for known MQ protocols
var commonMQPorts = map[int]struct{}{
	61616: {}, // ActiveMQ OpenWire
	1414:  {}, // IBM MQ
}

// MQServiceMetadata represents the parsed metadata of the MQ service
type MQServiceMetadata struct {
	ProviderName    string
	Version         string
	PlatformDetails string
	Capabilities    string
	JVMVersion      string
}

// init function to register the plugin
func init() {
	plugins.RegisterPlugin(&MQPlugin{})
}

// Function to clean and deduplicate the string
func cleanString(input string) string {
	// Replace null bytes (0x00 or '\u0000') with spaces
	input = strings.ReplaceAll(input, "\u0000", " ")

	// Optionally remove other non-printable characters (like control characters) except for spaces
	reControl := regexp.MustCompile(`[^\x20-\x7E]+`)
	input = reControl.ReplaceAllString(input, " ")

	// Replace multiple spaces with a single space
	reMultipleSpaces := regexp.MustCompile(`\s+`)
	input = reMultipleSpaces.ReplaceAllString(input, " ")

	// Add a colon after "ProviderVersion"
	input = strings.ReplaceAll(input, "ProviderVersion", "ProviderVersion:")

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

// DetectMQ attempts to identify the MQ protocol based on the response
func DetectMQ(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.ServiceMQ, error) {
	// Set connection deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	// Send a request and get the response
	request := []byte{0x00, 0x01, 0x80} // Example request for MQ protocols

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, fmt.Errorf("error during MQ response: %w", err)
	}

	if len(response) == 0 {
		return nil, fmt.Errorf("empty response received")
	}

	// Check if bytes 6 to 12 correspond to "ActiveMQ" (0x4163746976654d51)
	if len(response) > 12 {
		protocolCheck := response[5:13]

		// Check if the protocolCheck matches "ActiveMQ"
		if bytes.Equal(protocolCheck, []byte("ActiveMQ")) {
			providerName := "ActiveMQ"
			providerVersion := cleanString(extractProviderVersion(response))
			platformDetails := cleanString(extractPlatformDetails(response))
			capabilities := cleanString(extractCapabilities(response))

			var os, jvm string
			// Extract OS using the provided regex
			reOS := regexp.MustCompile(`OS:\s(Windows\sServer\s\d+,\s\d+\.\d+,\s(amd64|x86_64|x86)|Windows\s\d+,\s\d+\.\d+|Linux)`)
			osMatches := reOS.FindStringSubmatch(platformDetails)
			if len(osMatches) > 1 {
				os = osMatches[1]
			} else {
				os = ""
			}

			// Extract JVM version using the provided regex
			reJVM := regexp.MustCompile(`JVM:\s((\d[^,]*),\s[^,]*,)\s`)
			jvmMatches := reJVM.FindStringSubmatch(platformDetails)
			if len(jvmMatches) > 1 {
				jvm = jvmMatches[1]
			} else {
				jvm = ""
			}

			// Return the service metadata with Version included
			service := &plugins.ServiceMQ{
				Provider: providerName,
				Version:  providerVersion, // Assign the version here
				Details:  fmt.Sprintf("Capabilities: %s", capabilities),
				Os:       os,
				Jvm:      jvm,
			}

			return service, nil
		}

		// RabbitMQ check here
		// Check for RabbitMQ protocol by checking for "AMQP" in bytes 6 to 12
		protocolCheckRabbitMQ := response[5:9] // AMQP starts with "AMQP" (0x414d5150)

		if bytes.Equal(protocolCheckRabbitMQ, []byte("AMQP")) {
			providerName := "RabbitMQ"
			providerVersion := cleanString(extractProviderVersion(response))
			platformDetails := cleanString(extractPlatformDetails(response))
			capabilities := cleanString(extractCapabilities(response))

			var os, jvm string
			// Extract OS using the provided regex
			reOS := regexp.MustCompile(`OS:\s(Windows\sServer\s\d+,\s\d+\.\d+,\s(amd64|x86_64|x86)|Windows\s\d+,\s\d+\.\d+|Linux)`)
			osMatches := reOS.FindStringSubmatch(platformDetails)
			if len(osMatches) > 1 {
				os = osMatches[1]
			} else {
				os = ""
			}

			// Extract JVM version using the provided regex
			reJVM := regexp.MustCompile(`JVM:\s((\d[^,]*),\s[^,]*,)\s`)
			jvmMatches := reJVM.FindStringSubmatch(platformDetails)
			if len(jvmMatches) > 1 {
				jvm = jvmMatches[1]
			} else {
				jvm = ""
			}

			// Return the service metadata for RabbitMQ
			service := &plugins.ServiceMQ{
				Provider: providerName,
				Version:  providerVersion, // Assign the version here
				Details:  fmt.Sprintf("Capabilities: %s", capabilities),
				Os:       os,
				Jvm:      jvm,
			}

			return service, nil
		}

	}

	return nil, fmt.Errorf("Invalid MQ Protocol, ActiveMQ not detected")
}

// extractProviderVersion extracts the provider version from the response
func extractProviderVersion(response []byte) string {
	// ProviderVersion is located after the "ProviderVersion" keyword
	if idx := bytes.Index(response, []byte("ProviderVersion")); idx != -1 {
		version := string(response[idx+len("ProviderVersion"):])
		return strings.TrimSpace(version)
	}
	return "Unknown"
}

// extractPlatformDetails extracts platform details from the response
func extractPlatformDetails(response []byte) string {
	if idx := bytes.Index(response, []byte("PlatformDetails")); idx != -1 {
		platform := string(response[idx+len("PlatformDetails"):])
		return strings.TrimSpace(platform)
	}
	return "Unknown"
}

// extractJVMVersion extracts the JVM version from the response
func extractJVMVersion(response []byte) string {
	// Similar to ProviderVersion, JVMVersion is found after the "JVM" keyword
	if idx := bytes.Index(response, []byte("JVM")); idx != -1 {
		jvm := string(response[idx+len("JVM"):])
		return strings.TrimSpace(jvm)
	}
	return "Unknown"
}

// extractCapabilities extracts the capabilities starting from byte 28 to the end of the response
func extractCapabilities(response []byte) string {
	if len(response) > 28 {
		return string(response[28:])
	}
	return "Unknown"
}

// Run is the main execution function of the plugin
func (p *MQPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Ensure serviceMetadata is checked for nil
	serviceMetadata, err := DetectMQ(conn, timeout, target)
	if err != nil {
		return nil, fmt.Errorf("error during MQ detection: %w", err)
	}

	// If no service detected, return a default service
	if serviceMetadata == nil {
		return nil, nil
	}

	// Return the service details if a match is found
	return plugins.CreateServiceFrom(target, serviceMetadata, false, serviceMetadata.Version, plugins.TCP), nil
}

// PortPriority prioritizes known MQ ports
func (p *MQPlugin) PortPriority(port uint16) bool {
	_, ok := commonMQPorts[int(port)]
	return ok
}

// Name returns the name of the plugin
func (p *MQPlugin) Name() string {
	return MQ
}

// Type specifies the protocol type handled by this plugin
func (p *MQPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority sets the plugin priority
func (p *MQPlugin) Priority() int {
	return 500
}
