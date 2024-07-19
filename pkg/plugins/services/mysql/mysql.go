package mysql

import (
	"fmt"
	"net"
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

func (p *MYSQLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	mysqlVersionStr, err := CheckInitialHandshakePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "handshake",
			ErrorMessage: "",
			ErrorCode:    0,
		}
		return plugins.CreateServiceFrom(target, payload, false, mysqlVersionStr, plugins.TCP), nil
	}

	errorStr, errorCode, err := CheckErrorMessagePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "error",
			ErrorMessage: errorStr,
			ErrorCode:    errorCode,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}
	return nil, nil
}

func (p *MYSQLPlugin) PortPriority(port uint16) bool {
	return port == 3306
}

func (p *MYSQLPlugin) Name() string {
	return MYSQL
}

func (p *MYSQLPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MYSQLPlugin) Priority() int {
	return 133
}

func CheckErrorMessagePacket(response []byte) (string, int, error) {
	if len(response) < 8 {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet is too small for an error message packet",
		}
	}

	packetLength := int(uint32(response[0]) | uint32(response[1])<<8 | uint32(response[2])<<16 | uint32(response[3])<<24)
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

	errorCode := int(uint32(response[5]) | uint32(response[6])<<8)
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

func CheckInitialHandshakePacket(response []byte) (string, error) {
	if len(response) < 35 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length is too small for an initial handshake packet",
		}
	}

	packetLength := int(uint32(response[0]) | uint32(response[1])<<8 | uint32(response[2])<<16 | uint32(response[3])<<24)
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
