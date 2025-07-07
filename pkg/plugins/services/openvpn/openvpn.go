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

// OpenVPNFingerprint represents collected OpenVPN fingerprinting data (NO TIMING)
type OpenVPNFingerprint struct {
	ResponseSize     int
	HandshakePattern string
	TLSHandshake     bool
	PacketStructure  string
	SupportsAuth     bool    // Whether tls-auth/tls-crypt is detected
	OpcodeSequence   []uint8 // Sequence of opcodes observed
	StandardPort     int
	Transport        string
	Encryption       string
	Authentication   []string
	Compression      []string
	SessionID        string
	DetectionMethod  string
	TLSVersion       string
	CipherSuite      string
	CertificateInfo  map[string]interface{}
}

var (
	// Only ports 1194 and 1723 for OpenVPN
	commonOpenVPNPorts = map[int]struct{}{
		1194: {}, // Standard OpenVPN UDP port
		1723: {}, // Alternative OpenVPN port (also used by PPTP but we'll detect the difference)
	}

	// Embedded self-signed certificate for OpenVPN authentication
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

	// Known OpenVPN vendor patterns
	vendorPatterns = map[string]VendorInfo{
		"openvpn_community": {
			Name:        "OpenVPN",
			Product:     "OpenVPN Community Edition",
			Confidence:  85,
			Method:      "TLS Handshake Analysis",
			Description: "Open source OpenVPN server",
		},
		"openvpn_access_server": {
			Name:        "OpenVPN",
			Product:     "OpenVPN Access Server",
			Confidence:  90,
			Method:      "TLS Handshake Analysis",
			Description: "Commercial OpenVPN Access Server",
		},
		"pfsense_openvpn": {
			Name:        "pfSense",
			Product:     "pfSense OpenVPN",
			Confidence:  80,
			Method:      "TLS Handshake Analysis",
			Description: "pfSense integrated OpenVPN server",
		},
		"mikrotik_openvpn": {
			Name:        "MikroTik",
			Product:     "RouterOS OpenVPN",
			Confidence:  75,
			Method:      "TLS Handshake Analysis",
			Description: "MikroTik RouterOS OpenVPN implementation",
		},
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run performs OpenVPN detection using TLS handshake with embedded certificate
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Only scan ports 1194 and 1723
	port := int(target.Address.Port())
	if _, exists := commonOpenVPNPorts[port]; !exists {
		return nil, nil
	}

	// Perform OpenVPN TLS handshake detection
	fingerprint, err := p.performTLSHandshakeDetection(conn, timeout)
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

	// Create service result using ServiceOpenVPN struct
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

	service := plugins.CreateServiceFrom(target, serviceOpenVPN, fingerprint.TLSHandshake, "", plugins.UDP)
	return service, nil
}

// performTLSHandshakeDetection performs OpenVPN detection using TLS handshake
func (p *Plugin) performTLSHandshakeDetection(conn net.Conn, timeout time.Duration) (*OpenVPNFingerprint, error) {
	// Set connection timeout
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	fingerprint := &OpenVPNFingerprint{
		OpcodeSequence:  []uint8{},
		Authentication:  []string{},
		Compression:     []string{},
		CertificateInfo: make(map[string]interface{}),
	}

	// Method 1: TLS handshake with client certificate (most reliable)
	confidence := p.tryTLSHandshakeWithCert(conn, fingerprint)
	if confidence >= 30 {
		fingerprint.DetectionMethod = "TLS_Handshake_With_Certificate"
		return fingerprint, nil
	}

	// Method 2: Basic TLS handshake (fallback)
	confidence = p.tryBasicTLSHandshake(conn, fingerprint)
	if confidence >= 25 {
		fingerprint.DetectionMethod = "Basic_TLS_Handshake"
		return fingerprint, nil
	}

	// Method 3: OpenVPN control packets (fallback)
	confidence = p.tryOpenVPNControlPackets(conn, fingerprint)
	if confidence >= 20 {
		fingerprint.DetectionMethod = "OpenVPN_Control_Packets"
		return fingerprint, nil
	}

	return nil, nil // Not confident enough
}

// tryTLSHandshakeWithCert attempts TLS handshake with embedded client certificate
func (p *Plugin) tryTLSHandshakeWithCert(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Load client certificate
	clientCert, err := p.loadClientCertificate()
	if err != nil {
		return confidence
	}

	// Create TLS config with client certificate
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		ServerName:         "",
	}

	// Attempt TLS handshake over UDP (OpenVPN style)
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		// TLS handshake failed, but analyze the error for OpenVPN patterns
		confidence += p.analyzeTLSError(err, fingerprint)
		return confidence
	}

	// TLS handshake succeeded
	fingerprint.TLSHandshake = true
	confidence += 50

	// Analyze TLS connection
	state := tlsConn.ConnectionState()
	fingerprint.TLSVersion = p.getTLSVersionString(state.Version)
	fingerprint.CipherSuite = p.getCipherSuiteString(state.CipherSuite)

	// Extract certificate information
	if len(state.PeerCertificates) > 0 {
		serverCert := state.PeerCertificates[0]
		fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
		fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()
		confidence += 20
	}

	// Try OpenVPN protocol communication over TLS
	confidence += p.tryOpenVPNProtocolOverTLS(tlsConn, fingerprint)

	fingerprint.PacketStructure = "OpenVPN_TLS_Handshake"
	fingerprint.Encryption = "TLS"
	fingerprint.Authentication = append(fingerprint.Authentication, "Client_Certificate")

	return confidence
}

// tryBasicTLSHandshake attempts basic TLS handshake without client certificate
func (p *Plugin) tryBasicTLSHandshake(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Create basic TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
	}

	// Attempt TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		// Analyze TLS error for OpenVPN patterns
		confidence += p.analyzeTLSError(err, fingerprint)
		return confidence
	}

	// TLS handshake succeeded
	fingerprint.TLSHandshake = true
	confidence += 40

	// Analyze TLS connection
	state := tlsConn.ConnectionState()
	fingerprint.TLSVersion = p.getTLSVersionString(state.Version)
	fingerprint.CipherSuite = p.getCipherSuiteString(state.CipherSuite)

	// Extract certificate information
	if len(state.PeerCertificates) > 0 {
		serverCert := state.PeerCertificates[0]
		fingerprint.CertificateInfo["subject"] = serverCert.Subject.String()
		fingerprint.CertificateInfo["issuer"] = serverCert.Issuer.String()

		// Check for OpenVPN patterns in certificate
		confidence += p.analyzeOpenVPNCertificate(serverCert, fingerprint)
	}

	fingerprint.PacketStructure = "Basic_TLS_Handshake"
	fingerprint.Encryption = "TLS"

	return confidence
}

// tryOpenVPNControlPackets attempts OpenVPN control packet communication
func (p *Plugin) tryOpenVPNControlPackets(conn net.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Try different OpenVPN control packets
	packets := [][]byte{
		p.createOpenVPNClientHello(),
		p.createOpenVPNResetPacket(),
		p.createOpenVPNAuthPacket(),
	}

	for _, packet := range packets {
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, err := conn.Write(packet)
		if err != nil {
			continue
		}

		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		response := make([]byte, 1500)
		n, err := conn.Read(response)
		if err != nil {
			continue
		}

		// Analyze OpenVPN response
		packetConfidence := p.analyzeOpenVPNResponse(response[:n], fingerprint)
		if packetConfidence > confidence {
			confidence = packetConfidence
			fingerprint.ResponseSize = n
		}
	}

	if confidence > 0 {
		fingerprint.PacketStructure = "OpenVPN_Control_Packets"
	}

	return confidence
}

// analyzeTLSError analyzes TLS errors for OpenVPN patterns
func (p *Plugin) analyzeTLSError(err error, fingerprint *OpenVPNFingerprint) int {
	confidence := 0
	errorStr := strings.ToLower(err.Error())

	// OpenVPN-specific TLS error patterns
	if strings.Contains(errorStr, "certificate") {
		confidence += 15
		fingerprint.Authentication = append(fingerprint.Authentication, "Certificate_Required")
	}

	if strings.Contains(errorStr, "handshake") {
		confidence += 10
		fingerprint.PacketStructure = "TLS_Handshake_Error"
	}

	if strings.Contains(errorStr, "tls") {
		confidence += 10
		fingerprint.Encryption = "TLS"
	}

	// OpenVPN often requires specific TLS configurations
	if strings.Contains(errorStr, "protocol") || strings.Contains(errorStr, "version") {
		confidence += 15
	}

	return confidence
}

// tryOpenVPNProtocolOverTLS attempts OpenVPN protocol communication over TLS
func (p *Plugin) tryOpenVPNProtocolOverTLS(tlsConn *tls.Conn, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Send OpenVPN control message over TLS
	controlMsg := p.createOpenVPNControlMessage()
	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := tlsConn.Write(controlMsg)
	if err != nil {
		return confidence
	}

	// Read response
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1500)
	n, err := tlsConn.Read(response)
	if err != nil {
		return confidence
	}

	// Analyze OpenVPN protocol response
	confidence += p.analyzeOpenVPNProtocolResponse(response[:n], fingerprint)
	fingerprint.ResponseSize = n

	return confidence
}

// analyzeOpenVPNCertificate analyzes certificate for OpenVPN patterns
func (p *Plugin) analyzeOpenVPNCertificate(cert interface{}, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// This would analyze the certificate for OpenVPN-specific patterns
	// For now, just add basic confidence for having a certificate
	confidence += 15
	fingerprint.SupportsAuth = true

	return confidence
}

// analyzeOpenVPNResponse analyzes response for OpenVPN patterns
func (p *Plugin) analyzeOpenVPNResponse(response []byte, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	if len(response) < 1 {
		return confidence
	}

	// Check for OpenVPN packet structure
	if len(response) >= 1 {
		opcode := response[0] >> 3
		fingerprint.OpcodeSequence = append(fingerprint.OpcodeSequence, opcode)

		// OpenVPN opcodes
		if opcode >= 1 && opcode <= 10 {
			confidence += 40
			fingerprint.HandshakePattern = fmt.Sprintf("OpenVPN_Opcode_%d", opcode)

			// Check for session ID
			if len(response) >= 9 {
				sessionID := response[1:9]
				fingerprint.SessionID = fmt.Sprintf("%x", sessionID)
				confidence += 20
			}

			// Check for packet ID
			if len(response) >= 13 {
				confidence += 15
			}
		}
	}

	return confidence
}

// analyzeOpenVPNProtocolResponse analyzes OpenVPN protocol response
func (p *Plugin) analyzeOpenVPNProtocolResponse(response []byte, fingerprint *OpenVPNFingerprint) int {
	confidence := 0

	// Analyze response for OpenVPN protocol patterns
	responseStr := strings.ToLower(string(response))

	if strings.Contains(responseStr, "openvpn") {
		confidence += 30
	}

	if strings.Contains(responseStr, "auth") {
		confidence += 20
		fingerprint.SupportsAuth = true
	}

	if strings.Contains(responseStr, "tls") {
		confidence += 15
		fingerprint.Encryption = "TLS"
	}

	return confidence
}

// loadClientCertificate loads the embedded client certificate
func (p *Plugin) loadClientCertificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(openVPNClientCert), []byte(openVPNClientKey))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}

// createOpenVPNClientHello creates an OpenVPN client hello packet
func (p *Plugin) createOpenVPNClientHello() []byte {
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

// createOpenVPNResetPacket creates an OpenVPN reset packet
func (p *Plugin) createOpenVPNResetPacket() []byte {
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

// createOpenVPNAuthPacket creates an OpenVPN auth packet
func (p *Plugin) createOpenVPNAuthPacket() []byte {
	packet := make([]byte, 20)

	// Opcode with auth flag
	packet[0] = (2 << 3) | 1 // Opcode 2, Key ID 1 (indicates auth)

	// Session ID (8 bytes)
	rand.Read(packet[1:9])

	// Packet ID (4 bytes)
	packet[9] = 0
	packet[10] = 0
	packet[11] = 0
	packet[12] = 1

	// Auth data
	rand.Read(packet[13:20])

	return packet
}

// createOpenVPNControlMessage creates an OpenVPN control message
func (p *Plugin) createOpenVPNControlMessage() []byte {
	// Simple OpenVPN control message
	return []byte("OpenVPN Control Message")
}

// createVendorInfo creates vendor information based on fingerprinting results
func (p *Plugin) createVendorInfo(fingerprint *OpenVPNFingerprint) VendorInfo {
	vendor := VendorInfo{
		Name:       "OpenVPN",
		Product:    "OpenVPN Server",
		Confidence: 60,
		Method:     "TLS Handshake Analysis",
	}

	// Analyze patterns for vendor detection
	if fingerprint.TLSHandshake {
		vendor.Confidence += 20
	}

	if fingerprint.SupportsAuth {
		vendor = vendorPatterns["openvpn_community"]
	}

	// Enhance confidence based on fingerprint quality
	if len(fingerprint.OpcodeSequence) > 0 {
		vendor.Confidence += 10
	}

	if fingerprint.TLSHandshake {
		vendor.Confidence += 15
	}

	// Set version based on TLS version
	if fingerprint.TLSVersion != "" {
		if strings.Contains(fingerprint.TLSVersion, "1.3") {
			vendor.Version = "OpenVPN 2.5+"
		} else if strings.Contains(fingerprint.TLSVersion, "1.2") {
			vendor.Version = "OpenVPN 2.4+"
		} else {
			vendor.Version = "OpenVPN 2.0-2.3"
		}
	}

	// Update method based on detection method
	vendor.Method = fmt.Sprintf("TLS Handshake Analysis (%s)", fingerprint.DetectionMethod)

	return vendor
}

// getTLSVersionString converts TLS version to string
func (p *Plugin) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// getCipherSuiteString converts cipher suite to string
func (p *Plugin) getCipherSuiteString(cipherSuite uint16) string {
	switch cipherSuite {
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	default:
		return fmt.Sprintf("0x%04x", cipherSuite)
	}
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
