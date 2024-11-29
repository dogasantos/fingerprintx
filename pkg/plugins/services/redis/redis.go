package redis

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
)

type REDISPlugin struct{}
type REDISTLSPlugin struct{}

type Info struct {
	AuthRequired  bool
	ProtectedMode bool
}

const REDIS = "redis"
const REDISTLS = "redis"

// Check if the response is from a Redis server
func checkRedis(data []byte) (Info, error) {
	pong := []byte("+PONG\r\n")                                           // +PONG response
	noauth := []byte("-NOAUTH Authentication required")                   // -NOAUTH response
	protectedMode := []byte("-DENIED Redis is running in protected mode") // Protected mode response

	if bytes.HasPrefix(data, pong) {
		return Info{AuthRequired: false, ProtectedMode: false}, nil
	}
	if bytes.HasPrefix(data, noauth) {
		return Info{AuthRequired: true, ProtectedMode: false}, nil
	}
	if bytes.HasPrefix(data, protectedMode) {
		return Info{AuthRequired: false, ProtectedMode: true}, nil
	}

	return Info{}, &utils.InvalidResponseErrorInfo{
		Service: REDIS,
		Info:    "invalid response",
	}
}

// Extract version and OS information from the INFO response
func extractRedisInfo(infoResponse []byte) (string, string) {
	lines := strings.Split(string(infoResponse), "\n")
	var redisVersion, osVersion string

	for _, line := range lines {
		if strings.HasPrefix(line, "redis_version:") {
			redisVersion = strings.TrimSpace(strings.Split(line, ":")[1])
		}
		if strings.HasPrefix(line, "os:") {
			osVersion = strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}

	return redisVersion, osVersion
}

// Query Redis INFO command
func getRedisInfo(conn net.Conn, timeout time.Duration) (string, string, error) {
	infoCmd := []byte{
		0x2a, 0x31, 0x0d, 0x0a, // *1\r\n
		0x24, 0x34, 0x0d, 0x0a, // $4\r\n
		0x49, 0x4e, 0x46, 0x4f, // INFO
		0x0d, 0x0a, // \r\n
	}

	response, err := utils.SendRecv(conn, infoCmd, timeout)
	if err != nil {
		return "", "", fmt.Errorf("failed to send INFO command: %w", err)
	}

	if len(response) == 0 {
		return "", "", fmt.Errorf("empty response to INFO command")
	}

	redisVersion, osVersion := extractRedisInfo(response)
	return redisVersion, osVersion, nil
}

func init() {
	plugins.RegisterPlugin(&REDISPlugin{})
	plugins.RegisterPlugin(&REDISTLSPlugin{})
}

func DetectRedis(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// PING command
	ping := []byte{
		0x2a, 0x31, 0x0d, 0x0a, // *1\r\n
		0x24, 0x34, 0x0d, 0x0a, // $4\r\n
		0x50, 0x49, 0x4e, 0x47, // PING
		0x0d, 0x0a, // \r\n
	}

	response, err := utils.SendRecv(conn, ping, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Check for Redis response and handle protected mode
	result, err := checkRedis(response)
	if err != nil {
		return nil, nil
	}

	payload := plugins.ServiceRedis{
		AuthRequired:  result.AuthRequired,
		ProtectedMode: result.ProtectedMode,
	}

	// If no auth required and not in protected mode, retrieve Redis and OS versions
	if !result.AuthRequired && !result.ProtectedMode {
		redisVersion, osVersion, err := getRedisInfo(conn, timeout)
		if err == nil {
			payload.Version = redisVersion
			payload.OperatingSystem = osVersion
		}
	}

	// Return the service object
	if tls {
		return plugins.CreateServiceFrom(target, payload, true, payload.Version, plugins.TCPTLS), nil
	}
	return plugins.CreateServiceFrom(target, payload, false, payload.Version, plugins.TCP), nil
}

func (p *REDISPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectRedis(conn, target, timeout, false)
}

func (p *REDISTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectRedis(conn, target, timeout, true)
}

func (p *REDISPlugin) PortPriority(port uint16) bool {
	return port == 6379
}

func (p *REDISTLSPlugin) PortPriority(port uint16) bool {
	return port == 6380
}

func (p *REDISPlugin) Name() string {
	return REDIS
}

func (p *REDISTLSPlugin) Name() string {
	return REDISTLS
}

func (p *REDISPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *REDISTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *REDISPlugin) Priority() int {
	return 413
}

func (p *REDISTLSPlugin) Priority() int {
	return 414
}
