package mysql

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

type MYSQLPlugin struct{}

const (
	MYSQL = "MySQL"
)

func init() {
	plugins.RegisterPlugin(&MYSQLPlugin{})
}

func (p *MYSQLPlugin) Name() string {
	return MYSQL
}

func (p *MYSQLPlugin) PortPriority(port uint16) bool {
	return port == 3306
}

func (p *MYSQLPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MYSQLPlugin) Priority() int {
	return 133
}

func (p *MYSQLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	version, err := p.detectVersion(conn, timeout)
	if err != nil {
		version = "unknown"
	}

	mysqlVersionStr, err := checkInitialHandshakePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "handshake",
			ErrorMessage: "",
			ErrorCode:    0,
			Version:      version,
		}
		return plugins.CreateServiceFrom(target, payload, false, mysqlVersionStr, plugins.TCP), nil
	}

	errorStr, errorCode, err := checkErrorMessagePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "error",
			ErrorMessage: errorStr,
			ErrorCode:    errorCode,
			Version:      version,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func (p *MYSQLPlugin) detectVersion(conn net.Conn, timeout time.Duration) (string, error) {
	// Try SSL/TLS connection and analyze response
	err := attemptSSLConnection(conn, timeout)
	if err != nil {
		version := analyzeSSLError(err.Error())
		if version != "" {
			return version, nil
		}
	}

	// Try different authentication methods and analyze responses
	authMethods := []string{"mysql_native_password", "caching_sha2_password"}
	for _, authMethod := range authMethods {
		err := attemptAuthMethod(conn, timeout, authMethod)
		if err != nil {
			version := analyzeAuthMethodError(err.Error())
			if version != "" {
				return version, nil
			}
		}
	}

	// If no version detected from specific checks, return generic version
	return "unknown", fmt.Errorf("unable to detect MySQL version")
}

func checkErrorMessagePacket(response []byte) (string, int, error) {
	if len(response) < 8 {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet is too small for an error message packet",
		}
	}

	packetLength := int(binary.LittleEndian.Uint32(response[:4]))
	actualResponseLength := len(response) - 4

	if packetLength != actualResponseLength {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length does not match length of the response from the server",
		}
	}

	header := int(response[4])
	if header != 0xff {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid header for an error message packet",
		}
	}

	errorCode := int(binary.LittleEndian.Uint16(response[5:7]))
	if errorCode < 1000 || errorCode > 2000 {
		return "", errorCode, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid error code",
		}
	}

	errorStr, err := readEOFTerminatedASCIIString(response, 7)
	if err != nil {
		return "", errorCode, &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: err.Error()}
	}

	return errorStr, errorCode, nil
}

func checkInitialHandshakePacket(response []byte) (string, error) {
	if len(response) < 35 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length is too small for an initial handshake packet",
		}
	}

	packetLength := int(binary.LittleEndian.Uint32(response[:4]))
	version := int(response[4])

	if packetLength < 25 || packetLength > 4096 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length doesn't make sense for the MySQL handshake packet",
		}
	}

	if version != 10 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid version",
		}
	}

	mysqlVersionStr, position, err := readNullTerminatedASCIIString(response, 5)
	if err != nil {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "unable to read null-terminated ASCII version string, err: " + err.Error(),
		}
	}

	fillerPos := position + 13
	if fillerPos >= len(response) {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to be a valid initial handshake packet",
		}
	}

	if response[fillerPos] != 0x00 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info: fmt.Sprintf(
				"expected filler byte at this position to be zero got: %d",
				response[fillerPos],
			),
		}
	}

	return mysqlVersionStr, nil
}

func readNullTerminatedASCIIString(buffer []byte, startPosition int) (string, int, error) {
	characters := []byte{}
	success := false
	endPosition := 0

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else if buffer[position] == 0x00 {
			success = true
			endPosition = position
			break
		} else {
			return "", 0, &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	if !success {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "hit the end of the buffer without encountering a null terminator",
		}
	}

	return string(characters), endPosition, nil
}

func readEOFTerminatedASCIIString(buffer []byte, startPosition int) (string, error) {
	characters := []byte{}

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else {
			return "", &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	return string(characters), nil
}

// analyzeErrorMessage infers version based on error message
func analyzeErrorMessage(errorStr string, errorCode int) string {
	if errorCode == 1130 && matchHostNotAllowedError(errorStr) {
		return "MySQL 5.7 or later"
	}
	// Add more error message analysis here
	return ""
}

// matchHostNotAllowedError matches the "Host 'x.x.x.x' is not allowed" error without hardcoded IP
func matchHostNotAllowedError(errorStr string) bool {
	matched, _ := regexp.MatchString(`Host '.*' is not allowed to connect to this MySQL server`, errorStr)
	return matched
}

// attemptAuthMethod tries to authenticate using a specific method
func attemptAuthMethod(conn net.Conn, timeout time.Duration, authMethod string) error {
	authPacket := buildAuthPacket(authMethod)
	_, err := conn.Write(authPacket)
	if err != nil {
		return err
	}

	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return err
	}

	return parseAuthResponse(response)
}

// buildAuthPacket builds an authentication packet for a specific method
func buildAuthPacket(authMethod string) []byte {
	// Example: Build a packet based on the auth method
	packet := []byte{0x01, 0x00, 0x00, 0x00, 0x01}
	packet = append(packet, []byte(authMethod)...)
	return packet
}

// parseAuthResponse parses the response from an authentication attempt
func parseAuthResponse(response []byte) error {
	if len(response) == 0 {
		return fmt.Errorf("empty response")
	}

	if response[0] == 0x00 {
		return nil
	} else if response[0] == 0xff {
		return fmt.Errorf("authentication failed: %s", string(response[1:]))
	}

	return fmt.Errorf("unexpected response: %v", response)
}

// analyzeAuthMethodError infers version based on authentication error
func analyzeAuthMethodError(errorStr string) string {
	if matchAuthPluginError(errorStr, "caching_sha2_password") {
		return "MySQL 8.0 or later"
	}
	// Add more detailed checks for 8.0.x versions here
	if matchAuthPluginError(errorStr, "mysql_native_password") {
		// Example detailed check for MySQL 5.7.x versions
		if strings.Contains(errorStr, "specific 5.7.x error message") {
			return "MySQL 5.7.x"
		}
	}
	return ""
}

// matchAuthPluginError matches specific auth plugin errors
func matchAuthPluginError(errorStr, plugin string) bool {
	matched, _ := regexp.MatchString(fmt.Sprintf(`Authentication plugin '%s' cannot be loaded`, plugin), errorStr)
	return matched
}

// attemptSSLConnection tries to establish an SSL connection
func attemptSSLConnection(conn net.Conn, timeout time.Duration) error {
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // MySQL 5.7 and 8.0
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,    // MySQL 5.6
			tls.TLS_AES_256_GCM_SHA384,                // MySQL 8.0.16+
		},
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, config)

	// Perform handshake to trigger sending ClientHello
	err := tlsConn.Handshake()
	if err != nil {
		return err
	}

	return nil
}

// parseSSLResponse parses the response from an SSL handshake attempt
func parseSSLResponse(response []byte) error {
	if len(response) == 0 {
		return fmt.Errorf("empty response")
	}

	if response[0] == 0x15 { // SSL Alert
		return fmt.Errorf("SSL handshake failed: %s", string(response[1:]))
	} else if response[0] == 0x16 { // SSL Handshake
		return nil
	}

	return fmt.Errorf("unexpected SSL response: %v", response)
}

// analyzeSSLError infers version based on SSL error
func analyzeSSLError(errorStr string) string {
	if matchSSLAlertError(errorStr, "handshake failure") {
		return "MySQL 5.7 or later"
	}
	// Add more detailed checks for SSL errors here
	return ""
}

// matchSSLAlertError matches specific SSL alert errors
func matchSSLAlertError(errorStr, alert string) bool {
	matched, _ := regexp.MatchString(fmt.Sprintf(`SSL handshake failed: %s`, alert), errorStr)
	return matched
}

func (p *MYSQLPlugin) detectDetailedVersion(conn net.Conn, baseVersion string) string {
	switch baseVersion {
	case "MySQL 5.7":
		version := p.checkTLSVersion(conn, tls.VersionTLS12)
		if version == "TLS 1.2" {
			if p.checkCipherSuite(conn, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) {
				return "MySQL 5.7.x"
			}
		}
	case "MySQL 8.0":
		version := p.checkTLSVersion(conn, tls.VersionTLS13)
		if version == "TLS 1.3" {
			if p.checkCipherSuite(conn, tls.TLS_AES_256_GCM_SHA384) {
				return "MySQL 8.0.16+"
			}
		}
	}
	return baseVersion
}

func (p *MYSQLPlugin) checkTLSVersion(conn net.Conn, version uint16) string {
	config := &tls.Config{
		MaxVersion:         version,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, config)

	err := tlsConn.Handshake()
	if err == nil {
		return fmt.Sprintf("TLS %d.%d", version>>8, version&0xff)
	}
	return ""
}

func (p *MYSQLPlugin) checkCipherSuite(conn net.Conn, cipherSuite uint16) bool {
	config := &tls.Config{
		CipherSuites:       []uint16{cipherSuite},
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(conn, config)

	err := tlsConn.Handshake()
	return err == nil
}
