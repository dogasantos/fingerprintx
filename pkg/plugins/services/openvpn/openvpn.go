package openvpn

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

const OPENVPN = "openvpn"

type Plugin struct{}

// VendorInfo represents detected vendor information
type VendorInfo struct {
	Name        string
	Product     string
	Version     string
	Confidence  int    // 1-100, higher is more confident
	Method      string // How it was detected
	Description string
}

// OpenVPNFingerprint represents collected OpenVPN fingerprinting data
type OpenVPNFingerprint struct {
	ResponseSize     int
	HandshakePattern string
	PacketStructure  string
	SupportsAuth     bool
	OpcodeSequence   []uint8
	StandardPort     int
	Transport        string
	Encryption       string
	Authentication   []string
	Compression      []string
	SessionID        string
	DetectionMethod  string
}

var (
	// Only ports 1194 and 1723 for OpenVPN
	commonOpenVPNPorts = map[int]struct{}{
		1194: {}, // Standard OpenVPN UDP port
		1723: {}, // Alternative OpenVPN port
	}

	// User-provided certificate and key
	openVPNClientCert = `-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIUPLZBCLor7PLzHgxxyz7VT/r3IIowDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yNTA3MDcwMzA4MjBaGA8yMjk3
MDcyNjAzMDgyMFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANQGLuDbiGWEf+eEQZGH0SPogLgz8CXDj8OX4IZb
ewLfvRgu1YX4mb44mUcoq1LWtTq+ODkclO17fTe8mlX3sgYxHBhLFUD27ow/Ya/7
1+mpEJ9iGyMtgK8OG4RU1Xk8Cu5qcSglJay3Ib6qTAh2DWbyZb17xNMMYy2GZA61
FGkBCQHVtn5ywCx+nWgWjaJ1M9j9FrJGI+kmGUmGmsci+KxUsumMbL2mOt8AXM8u
xUXmhx4BDcSdsHjAwuHVxodTHeRsTfCuXHNOv/OkBDBWkyse0dq/o4qVzTyCkB27
3GmrHDak1wpl/0sZN3I0NmBnQoz1ltCDRIYiZHgv22JNf8cCAwEAAaNTMFEwHQYD
VR0OBBYEFAWFBwjPhoDptozHo3s98xYmtG2MMB8GA1UdIwQYMBaAFAWFBwjPhoDp
tozHo3s98xYmtG2MMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AHwBoQy8Rn0g+dvV641l0RnJ6RmQ9pSRs+kKS0ZgNRlmP1Zf9i2lm0cFsmPs6g8P
68cVsXzqZjMEowzLmP27DQYXK/CS58175REs01NWRzhJVnZhRmeqxN++/5mG6lPo
3oeiAK3J8YVAwab+s1S5ItW+Kcf2kv39p6g1A4lJc8bbGFHiQEYm/Ew0YRCWiwph
6HxpKTQAX6tdUTre7gi7jzyMPfOKhQrU/ZtYYeL374N/qeIV+PQKaFstfiT3go8R
tXjhM9ubY2aB22VHLIFnC2H/B4KecYfzZppHb4/Sxeh2eKtNhpcp2QrkcRq3h00m
y584RyCsohppvhUqlYcLA0Y=
-----END CERTIFICATE-----`

	openVPNClientKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUBi7g24hlhH/n
hEGRh9Ej6IC4M/Alw4/Dl+CGW3sC370YLtWF+Jm+OJlHKKtS1rU6vjg5HJTte303
vJpV97IGMRwYSxVA9u6MP2Gv+9fpqRCfYhsjLYCvDhuEVNV5PAruanEoJSWstyG+
qkwIdg1m8mW9e8TTDGMthmQOtRRpAQkB1bZ+csAsfp1oFo2idTPY/RayRiPpJhlJ
hprHIvisVLLpjGy9pjrfAFzPLsVF5oceAQ3EnbB4wMLh1caHUx3kbE3wrlxzTr/z
pAQwVpMrHtHav6OKlc08gpAdu9xpqxw2pNcKZf9LGTdyNDZgZ0KM9ZbQg0SGImR4
L9tiTX/HAgMBAAECggEABQ+6ucJz4JyHoyK8n/lCjF1mCT+wKW6gNXagNQTlDF4D
+RpRHZggL3LRcenuIRWgEO1ukSp2Aa9Tf2ugsZGurcgpWAke0kSy0CVJMzbLYjgX
ff6NEEtrSYKINKID0JeW2TcwSVmNqzBZ/V+6Xe9XhZAezqWwPquKiJEvPUykVpdV
Gj5an7jQUG9+LGwUNOwpIqiMfWJoJ/iGk4XpBiYity4XVMEa7SWxe6fbO+NZotFD
KW9W7RUCtwL/UcVj7jINIH4PLOGyTe9E8HjcPwS8A5Bi2WYL4gQ+FGLJw73OPnk9
LCnyEKlBX6k3ICDKWgHsw/G7LgogIs4mIBm243pq3QKBgQDyr/yXDWVDyA+8ZPYo
ksMcOac0+kx8IOaCGFffTPSkFWfZl4d5CVFiVOZ5FgLxahvKAfv6Ks7l6CIun46G
2zKPV3oHWhDo7TOk8IEE+u+mBlRKgdxz6p3IbBEAJyup4RgW6n0iumU8D8Mby1qo
3Os/96jy5V2EtNLQ1mntrui/MwKBgQDfp5kAVuHKZz8Uu74IHnGxtc32WNdJTjtp
ClKPSY58TNUJ8abAxiXH37TIry0NBSATT3s9lbo1AMDjKq5igvoh+XwbZkh/HsLY
8qSOfKqVD8fswGad+767fJrFyvG5PNDuUsNHkAMMOYWYhwmU6PjQx3PkLlmCd60v
SRySm9zNHQKBgGHCwt2WZ9SGItChWwe9FxunndOZgHYAStrdM4igV2xBszPT9p6r
Qj16Nd1RIJ5fQBJ/+iEsXWv/tsVRQPjSE+vqMR4FCgrKgqNOvqpi62bV5d6dsVCA
kk7KOY72OICWTD3u97mlnGI1d0MbB8o+NAXwnf46pxFuRf4aYVF9xARBAoGAQU3u
nuq/gxoikStAkZ5SFFHBkeze78ioEEOzV6Nit2i3y++DgUZaQcJQR0jfHq4gb4MF
uTW+6TsPF0WfJaSY5NK0KkvzXyrcOfyfj/tW06+H8Nk9HWQkjRoVFyvq6OuZFf2U
h5DFUwx4tdC4O4LLJCsY68ec2zuWlfgDH8vi7QECgYEAvAS6Ptf/JiREBoZfNFZy
/AP7/1Awm48lUYGVkyFx2PYnbbBqL3+KQ6Dq42lZbhV4Qn1Mz4IiF/f9VSugBsTq
JUZpMq4NAl+cyrsNPakbxh8Ln/7JP1DiA8PGpwI4NmowAZ4H3lJdhlpzB0rwKk91
kpxw33Zc5RKj80lJQRIejpE=
-----END PRIVATE KEY-----`
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run performs fast OpenVPN detection with quick fallback
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Only scan ports 1194 and 1723
	port := int(target.Address.Port())
	if _, exists := commonOpenVPNPorts[port]; !exists {
		return nil, nil
	}

	// Perform fast OpenVPN detection
	fingerprint, err := p.performFastDetection(conn, timeout)
	if err != nil {
		return nil, err
	}

	if fingerprint == nil {
		return nil, nil // Not OpenVPN
	}

	// Set additional fingerprint data
	fingerprint.StandardPort = port
	fingerprint.Transport = "UDP"

	// Create vendor information
	vendor := p.createVendorInfo(fingerprint)

	// Create service result
	serviceOpenVPN := plugins.ServiceOpenVPN{
		// Vendor information
		VendorName:        vendor.Name,
		VendorProduct:     vendor.Product,
		VendorVersion:     vendor.Version,
		VendorConfidence:  vendor.Confidence,
		VendorMethod:      vendor.Method,
		VendorDescription: vendor.Description,

		// OpenVPN fingerprint data
		ResponseSize:     fingerprint.ResponseSize,
		HandshakePattern: fingerprint.HandshakePattern,
		PacketStructure:  fingerprint.PacketStructure,
		SupportsAuth:     fingerprint.SupportsAuth,
		OpcodeSequence:   fingerprint.OpcodeSequence,

		// Protocol information
		StandardPort:   fingerprint.StandardPort,
		Transport:      fingerprint.Transport,
		Encryption:     fingerprint.Encryption,
		Authentication: fingerprint.Authentication,
		Compression:    fingerprint.Compression,
		SessionID:      fingerprint.SessionID,
	}

	service := plugins.CreateServiceFrom(target, serviceOpenVPN, false, "", plugins.UDP)
	return service, nil
}

// performFastDetection performs fast OpenVPN detection with quick fallback
func (p *Plugin) performFastDetection(conn net.Conn, timeout time.Duration) (*OpenVPNFingerprint, error) {
	// Set overall timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	fingerprint := &OpenVPNFingerprint{
		OpcodeSequence: []uint8{},
		Authentication: []string{},
		Compression:    []string{},
	}

	// Method 1: Quick TLS attempt (2 seconds max)
	confidence := p.tryQuickTLS(conn, fingerprint)
	if confidence >= 25 {
		fingerprint.DetectionMethod = "Quick_TLS"
		return fingerprint, nil
	}

	// Method 2: Simple OpenVPN packets (3 seconds max)
	confidence = p.trySimpleOpenVPN(conn, fingerprint)
	if confidence >= 20 {
		fingerprint.DetectionMethod = "Simple_OpenVPN"
		return fingerprint, nil
	}

	// Method 3: Basic UDP probe (2 seconds max)
	confidence = p.tryBasicUDPProbe(conn, fingerprint)
	if confidence >= 15 {
		fingerprint.DetectionMethod = "Basic_UDP_Probe"
		return fingerprint, nil
	}

	return nil, nil // Not confident enough
}

// tryQuickTLS attempts quick TLS handshake (2 seconds max)
func (p *Plugin) tryQuickTLS(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Load client certificate
	clientCert, err := p.loadClientCertificate()
	if err != nil {
		return confidence
	}

	// Create TLS config with short timeout
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		ServerName:         "",
	}

	// Set short deadline for TLS attempt
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Attempt TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		// Analyze TLS error for OpenVPN patterns
		errorStr := strings.ToLower(err.Error())
		if strings.Contains(errorStr, "certificate") || strings.Contains(errorStr, "handshake") {
			confidence += 20
			fingerprint.PacketStructure = "TLS_Error_Pattern"
			fingerprint.SupportsAuth = true
		}
		return confidence
	}

	// TLS handshake succeeded
	confidence += 40
	fingerprint.PacketStructure = "TLS_Handshake_Success"
	fingerprint.Encryption = "TLS"
	fingerprint.Authentication = append(fingerprint.Authentication, "Client_Certificate")

	return confidence
}

// trySimpleOpenVPN attempts simple OpenVPN packet exchange (3 seconds max)
func (p *Plugin) trySimpleOpenVPN(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Set deadline for OpenVPN attempt
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Try basic OpenVPN packets
	packets := [][]byte{
		p.createSimpleClientHello(),
		p.createSimpleResetPacket(),
	}

	for _, packet := range packets {
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, err := conn.Write(packet)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		response := make([]byte, 1500)
		n, err := conn.Read(response)
		if err != nil {
			continue
		}

		// Analyze response for OpenVPN patterns
		packetConfidence := p.analyzeSimpleResponse(response[:n], fingerprint)
		if packetConfidence > confidence {
			confidence = packetConfidence
			fingerprint.ResponseSize = n
		}
	}

	if confidence > 0 {
		fingerprint.PacketStructure = "OpenVPN_Packet_Response"
	}

	return confidence
}

// tryBasicUDPProbe attempts basic UDP probe (2 seconds max)
func (p *Plugin) tryBasicUDPProbe(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Set deadline for UDP probe
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send simple probe
	probe := []byte("OpenVPN")
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err := conn.Write(probe)
	if err != nil {
		return confidence
	}

	// Read any response
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		return confidence
	}

	fingerprint.ResponseSize = n

	// Any response on OpenVPN ports gets some confidence
	confidence += 15
	fingerprint.PacketStructure = "UDP_Response_OpenVPN_Port"

	// Check for any patterns
	responseStr := strings.ToLower(string(response))
	if strings.Contains(responseStr, "openvpn") || strings.Contains(responseStr, "tls") {
		confidence += 10
	}

	return confidence
}

// analyzeSimpleResponse analyzes response for basic OpenVPN patterns
func (p *Plugin) analyzeSimpleResponse(response []byte, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	if len(response) < 1 {
		return confidence
	}

	// Check for OpenVPN packet structure
	if len(response) >= 1 {
		opcode := response[0] >> 3
		fingerprint.OpcodeSequence = append(fingerprint.OpcodeSequence, opcode)

		// OpenVPN opcodes (1-10)
		if opcode >= 1 && opcode <= 10 {
			confidence += 30
			fingerprint.HandshakePattern = fmt.Sprintf("OpenVPN_Opcode_%d", opcode)

			// Check for session ID
			if len(response) >= 9 {
				sessionID := response[1:9]
				fingerprint.SessionID = fmt.Sprintf("%x", sessionID)
				confidence += 15
			}
		}
	}

	// Check response content
	responseStr := strings.ToLower(string(response))
	if strings.Contains(responseStr, "openvpn") {
		confidence += 20
	}
	if strings.Contains(responseStr, "auth") {
		confidence += 15
		fingerprint.SupportsAuth = true
	}

	return confidence
}

// createSimpleClientHello creates a simple OpenVPN client hello
func (p *Plugin) createSimpleClientHello() []byte {
	packet := make([]byte, 14)

	// Opcode (P_CONTROL_HARD_RESET_CLIENT_V1) and key ID
	packet[0] = (2 << 3) | 0 // Opcode 2, Key ID 0

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 1

	// Net time
	packet[13] = 0

	return packet
}

// createSimpleResetPacket creates a simple OpenVPN reset packet
func (p *Plugin) createSimpleResetPacket() []byte {
	packet := make([]byte, 14)

	// Opcode (P_CONTROL_HARD_RESET_CLIENT_V2) and key ID
	packet[0] = (3 << 3) | 0 // Opcode 3, Key ID 0

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 2

	// Net time
	packet[13] = 0

	return packet
}

// loadClientCertificate loads the user-provided client certificate
func (p *Plugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(openVPNClientCert), []byte(openVPNClientKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createVendorInfo creates vendor information based on fingerprinting results
func (p *Plugin) createVendorInfo(fingerprint *OpenVPNFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "OpenVPN",
		Product:    "OpenVPN Server",
		Confidence: 60,
		Method:     "Fast UDP Detection",
	}

	// Enhance confidence based on detection method
	switch fingerprint.DetectionMethod {
	case "Quick_TLS":
		vendor.Confidence += 20
		vendor.Product = "OpenVPN Server (TLS)"
	case "Simple_OpenVPN":
		vendor.Confidence += 15
		vendor.Product = "OpenVPN Server (Protocol)"
	case "Basic_UDP_Probe":
		vendor.Confidence += 10
		vendor.Product = "OpenVPN Server (Basic)"
	}

	// Enhance confidence based on features
	if fingerprint.SupportsAuth {
		vendor.Confidence += 5
	}
	if len(fingerprint.OpcodeSequence) > 0 {
		vendor.Confidence += 5
	}

	// Set version based on features
	if fingerprint.SupportsAuth {
		vendor.Version = "OpenVPN 2.4+"
	} else {
		vendor.Version = "OpenVPN 2.0+"
	}

	// Update method
	vendor.Method = fmt.Sprintf("Fast UDP Detection (%s)", fingerprint.DetectionMethod)

	return vendor
}

// PortPriority returns true if the port is a common OpenVPN port
func (p *Plugin) PortPriority(port uint16) bool {
	_, exists := commonOpenVPNPorts[int(port)]
	return exists
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return OPENVPN
}

// Type returns the protocol type
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the plugin priority
func (p *Plugin) Priority() int {
	return 580
}
