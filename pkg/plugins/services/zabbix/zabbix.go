package zabbixagent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type ZabbixAgentPlugin struct{}

const ZABBIX_AGENT = "zabbix-agent"

// ZabbixHeader represents the Zabbix protocol header
type ZabbixHeader struct {
	Protocol [4]byte // "ZBXD"
	Version  uint8   // Protocol version (1)
	DataLen  uint32  // Data length (little endian)
	Reserved uint32  // Reserved (0)
}

// PassiveCheckRequest represents a Zabbix passive check request
type PassiveCheckRequest struct {
	Request string `json:"request"`
	Data    []struct {
		Key     string `json:"key"`
		Timeout int    `json:"timeout"`
	} `json:"data"`
}

// PassiveCheckResponse represents a Zabbix passive check response
type PassiveCheckResponse struct {
	Version string `json:"version"`
	Variant int    `json:"variant"`
	Data    []struct {
		Value string `json:"value,omitempty"`
		Error string `json:"error,omitempty"`
	} `json:"data"`
}

// ActiveCheckRequest represents a Zabbix active check request
type ActiveCheckRequest struct {
	Request        string `json:"request"`
	Host           string `json:"host"`
	HostMetadata   string `json:"host_metadata,omitempty"`
	Interface      string `json:"interface,omitempty"`
	IP             string `json:"ip,omitempty"`
	Port           int    `json:"port,omitempty"`
	Version        string `json:"version"`
	Variant        int    `json:"variant"`
	ConfigRevision int    `json:"config_revision,omitempty"`
	Session        string `json:"session,omitempty"`
}

// ActiveCheckResponse represents a Zabbix active check response
type ActiveCheckResponse struct {
	Response       string `json:"response"`
	ConfigRevision int    `json:"config_revision,omitempty"`
	Data           []struct {
		Key         string `json:"key"`
		ItemID      int    `json:"itemid"`
		Delay       string `json:"delay"`
		LastLogSize int    `json:"lastlogsize"`
		MTime       int    `json:"mtime"`
		Timeout     string `json:"timeout,omitempty"`
	} `json:"data,omitempty"`
	Commands []struct {
		Command string `json:"command"`
		ID      int    `json:"id"`
		Wait    int    `json:"wait"`
	} `json:"commands,omitempty"`
}

// VendorInfo represents detected Zabbix vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// ZabbixFingerprint represents collected Zabbix fingerprinting data
type ZabbixFingerprint struct {
	AgentVersion      string
	AgentVariant      int
	Hostname          string
	ResponseTime      time.Duration
	ProtocolVersion   string
	SupportedChecks   []string
	ActiveChecks      bool
	PassiveChecks     bool
	ConfigRevision    int
	SessionID         string
	HostMetadata      string
	HostInterface     string
	ListenIP          string
	ListenPort        int
	SupportedItems    []string
	RemoteCommands    bool
	TLSSupport        bool
	TLSVersion        string
	EncryptionEnabled bool
	PSKSupport        bool
	CertificateAuth   bool
	OperatingSystem   string
	Architecture      string
	KernelVersion     string
	DetectionLevel    string
}

var (
	commonZabbixPorts = map[int]struct{}{
		10050: {}, // Zabbix Agent (passive)
		10051: {}, // Zabbix Server/Proxy (active)
	}

	// Common Zabbix agent items for testing
	testItems = []string{
		"agent.ping",
		"agent.version",
		"system.uptime",
		"system.hostname",
		"system.uname",
		"vfs.fs.size[/,total]",
		"vm.memory.size[total]",
		"system.cpu.load[all,avg1]",
		"net.if.discovery",
		"system.sw.packages",
	}
)

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

// Run performs Zabbix Agent detection
func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startTime := time.Now()

	// Perform Zabbix Agent detection
	fingerprint, err := p.performZabbixDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	// If detection failed, this is not Zabbix Agent
	if fingerprint == nil {
		return nil, nil
	}

	fingerprint.ResponseTime = time.Since(startTime)

	// Create vendor information
	vendor := p.createVendorInfo(fingerprint)

	// Create service result using ServiceZabbixAgent struct
	serviceZabbixAgent := plugins.ServiceZabbixAgent{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// Agent information
		AgentVersion: fingerprint.AgentVersion,
		AgentVariant: fingerprint.AgentVariant,
		Hostname:     fingerprint.Hostname,
		ResponseTime: fingerprint.ResponseTime.Milliseconds(),

		// Protocol information
		ProtocolVersion: fingerprint.ProtocolVersion,
		SupportedChecks: fingerprint.SupportedChecks,
		ActiveChecks:    fingerprint.ActiveChecks,
		PassiveChecks:   fingerprint.PassiveChecks,
		ConfigRevision:  fingerprint.ConfigRevision,
		SessionID:       fingerprint.SessionID,

		// Capabilities
		HostMetadata:   fingerprint.HostMetadata,
		HostInterface:  fingerprint.HostInterface,
		ListenIP:       fingerprint.ListenIP,
		ListenPort:     fingerprint.ListenPort,
		SupportedItems: fingerprint.SupportedItems,
		RemoteCommands: fingerprint.RemoteCommands,

		// Security features
		TLSSupport:        fingerprint.TLSSupport,
		TLSVersion:        fingerprint.TLSVersion,
		EncryptionEnabled: fingerprint.EncryptionEnabled,
		PSKSupport:        fingerprint.PSKSupport,
		CertificateAuth:   fingerprint.CertificateAuth,

		// System information
		OperatingSystem: fingerprint.OperatingSystem,
		Architecture:    fingerprint.Architecture,
		KernelVersion:   fingerprint.KernelVersion,

		// Detection metadata
		DetectionLevel: fingerprint.DetectionLevel,
	}

	service := plugins.CreateServiceFrom(target, serviceZabbixAgent, false, "", plugins.TCP)
	return service, nil
}

// performZabbixDetection performs Zabbix Agent protocol detection
func (p *ZabbixAgentPlugin) performZabbixDetection(conn net.Conn, timeout time.Duration) (*ZabbixFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	fingerprint := &ZabbixFingerprint{
		SupportedChecks: []string{},
		SupportedItems:  []string{},
		DetectionLevel:  "basic",
	}

	// Try passive check first (most common)
	success, err := p.tryPassiveCheck(conn, fingerprint)
	if err != nil {
		return nil, err
	}

	if success {
		fingerprint.PassiveChecks = true
		fingerprint.DetectionLevel = "enhanced"

		// Try to get more information with additional checks
		p.performEnhancedDetection(conn, fingerprint)
	} else {
		// Try active check request
		success, err = p.tryActiveCheck(conn, fingerprint)
		if err != nil {
			return nil, err
		}

		if success {
			fingerprint.ActiveChecks = true
			fingerprint.DetectionLevel = "enhanced"
		} else {
			// Not a Zabbix Agent
			return nil, nil
		}
	}

	return fingerprint, nil
}

// tryPassiveCheck attempts a Zabbix passive check
func (p *ZabbixAgentPlugin) tryPassiveCheck(conn net.Conn, fingerprint *ZabbixFingerprint) (bool, error) {
	// Create passive check request for agent.version
	request := PassiveCheckRequest{
		Request: "passive checks",
		Data: []struct {
			Key     string `json:"key"`
			Timeout int    `json:"timeout"`
		}{
			{Key: "agent.version", Timeout: 3},
		},
	}

	// Send request
	err := p.sendZabbixRequest(conn, request)
	if err != nil {
		return false, err
	}

	// Read response
	response, err := p.readZabbixResponse(conn)
	if err != nil {
		return false, err
	}

	// Parse passive check response
	var passiveResp PassiveCheckResponse
	err = json.Unmarshal(response, &passiveResp)
	if err != nil {
		return false, nil // Not valid JSON, not Zabbix
	}

	// Check if this is a valid Zabbix response
	if passiveResp.Version == "" || passiveResp.Variant == 0 {
		return false, nil
	}

	// Extract information
	fingerprint.AgentVersion = passiveResp.Version
	fingerprint.AgentVariant = passiveResp.Variant
	fingerprint.ProtocolVersion = "7.0+"

	if len(passiveResp.Data) > 0 && passiveResp.Data[0].Value != "" {
		fingerprint.SupportedItems = append(fingerprint.SupportedItems, "agent.version")
	}

	return true, nil
}

// tryActiveCheck attempts a Zabbix active check request
func (p *ZabbixAgentPlugin) tryActiveCheck(conn net.Conn, fingerprint *ZabbixFingerprint) (bool, error) {
	// Create active check request
	request := ActiveCheckRequest{
		Request: "active checks",
		Host:    "test-host",
		Version: "7.4.0",
		Variant: 2,
	}

	// Send request
	err := p.sendZabbixRequest(conn, request)
	if err != nil {
		return false, err
	}

	// Read response
	response, err := p.readZabbixResponse(conn)
	if err != nil {
		return false, err
	}

	// Parse active check response
	var activeResp ActiveCheckResponse
	err = json.Unmarshal(response, &activeResp)
	if err != nil {
		return false, nil // Not valid JSON, not Zabbix
	}

	// Check if this is a valid Zabbix response
	if activeResp.Response == "" {
		return false, nil
	}

	// Extract information
	fingerprint.ConfigRevision = activeResp.ConfigRevision
	fingerprint.RemoteCommands = len(activeResp.Commands) > 0

	// Extract supported items from response
	for _, item := range activeResp.Data {
		fingerprint.SupportedItems = append(fingerprint.SupportedItems, item.Key)
	}

	return true, nil
}

// performEnhancedDetection performs additional checks to gather more information
func (p *ZabbixAgentPlugin) performEnhancedDetection(conn net.Conn, fingerprint *ZabbixFingerprint) {
	// Try additional items to gather system information
	systemItems := []string{
		"system.hostname",
		"system.uname",
		"agent.ping",
	}

	for _, item := range systemItems {
		value, err := p.checkSingleItem(conn, item)
		if err != nil {
			continue
		}

		fingerprint.SupportedItems = append(fingerprint.SupportedItems, item)

		// Extract system information
		switch item {
		case "system.hostname":
			fingerprint.Hostname = value
		case "system.uname":
			fingerprint.OperatingSystem = value
			// Parse uname output for more details
			parts := strings.Fields(value)
			if len(parts) >= 3 {
				fingerprint.KernelVersion = parts[2]
			}
			if len(parts) >= 5 {
				fingerprint.Architecture = parts[4]
			}
		}
	}
}

// checkSingleItem performs a single item check
func (p *ZabbixAgentPlugin) checkSingleItem(conn net.Conn, key string) (string, error) {
	request := PassiveCheckRequest{
		Request: "passive checks",
		Data: []struct {
			Key     string `json:"key"`
			Timeout int    `json:"timeout"`
		}{
			{Key: key, Timeout: 3},
		},
	}

	err := p.sendZabbixRequest(conn, request)
	if err != nil {
		return "", err
	}

	response, err := p.readZabbixResponse(conn)
	if err != nil {
		return "", err
	}

	var passiveResp PassiveCheckResponse
	err = json.Unmarshal(response, &passiveResp)
	if err != nil {
		return "", err
	}

	if len(passiveResp.Data) > 0 && passiveResp.Data[0].Value != "" {
		return passiveResp.Data[0].Value, nil
	}

	return "", fmt.Errorf("no value returned")
}

// sendZabbixRequest sends a Zabbix protocol request
func (p *ZabbixAgentPlugin) sendZabbixRequest(conn net.Conn, request interface{}) error {
	// Marshal request to JSON
	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// Create Zabbix header
	header := ZabbixHeader{
		Protocol: [4]byte{'Z', 'B', 'X', 'D'},
		Version:  1,
		DataLen:  uint32(len(jsonData)),
		Reserved: 0,
	}

	// Write header
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, header)

	// Write data
	buf.Write(jsonData)

	// Send to connection
	_, err = conn.Write(buf.Bytes())
	return err
}

// readZabbixResponse reads a Zabbix protocol response
func (p *ZabbixAgentPlugin) readZabbixResponse(conn net.Conn) ([]byte, error) {
	// Read header (13 bytes)
	headerBuf := make([]byte, 13)
	_, err := conn.Read(headerBuf)
	if err != nil {
		return nil, err
	}

	// Parse header
	if string(headerBuf[0:4]) != "ZBXD" {
		return nil, fmt.Errorf("invalid Zabbix protocol header")
	}

	dataLen := binary.LittleEndian.Uint32(headerBuf[5:9])
	if dataLen > 1024*1024 { // 1MB limit
		return nil, fmt.Errorf("response too large")
	}

	// Read data
	dataBuf := make([]byte, dataLen)
	_, err = conn.Read(dataBuf)
	if err != nil {
		return nil, err
	}

	return dataBuf, nil
}

// createVendorInfo creates vendor information based on detection results
func (p *ZabbixAgentPlugin) createVendorInfo(fingerprint *ZabbixFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:        "Zabbix",
		Product:     "Zabbix Agent",
		Version:     fingerprint.AgentVersion,
		Method:      "Zabbix Protocol Analysis",
		Description: "Zabbix monitoring agent detected via protocol communication",
		Confidence:  85,
	}

	// Determine agent variant
	switch fingerprint.AgentVariant {
	case 1:
		vendor.Product = "Zabbix Agent"
		vendor.Description = "Zabbix Agent (classic) detected"
	case 2:
		vendor.Product = "Zabbix Agent 2"
		vendor.Description = "Zabbix Agent 2 (Go-based) detected"
	}

	// Adjust confidence based on detection level
	if fingerprint.DetectionLevel == "enhanced" {
		vendor.Confidence = 95
	}

	// Adjust confidence based on supported features
	if len(fingerprint.SupportedItems) > 3 {
		vendor.Confidence = 98
	}

	if fingerprint.PassiveChecks && fingerprint.ActiveChecks {
		vendor.Confidence = 99
	}

	return vendor
}

// PortPriority returns true if the port is a common Zabbix port
func (p *ZabbixAgentPlugin) PortPriority(port uint16) bool {
	_, exists := commonZabbixPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *ZabbixAgentPlugin) Name() string {
	return ZABBIX_AGENT
}

// Type returns the protocol type
func (p *ZabbixAgentPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority
func (p *ZabbixAgentPlugin) Priority() int {
	return 700
}
