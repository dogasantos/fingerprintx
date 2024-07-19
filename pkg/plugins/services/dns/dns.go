package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	utils "github.com/praetorian-inc/fingerprintx/pkg/plugins/pluginutils"
)

const DNS = "dns"

type UDPPlugin struct{}
type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
}

func CheckDNS(conn net.Conn, timeout time.Duration) (bool, string, error) {
	for attempts := 0; attempts < 3; attempts++ {
		transactionID := make([]byte, 2)
		_, err := rand.Read(transactionID)
		if err != nil {
			return false, "", &utils.RandomizeError{Message: "Transaction ID"}
		}

		InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
			// Transaction ID
			0x01, 0x00, // Flags: 0x0100 Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // Name: version.bind
			0x00, 0x10, // Type: TXT (Text strings) (16)
			0x00, 0x03, // Class: CH (0x0003)
		}...)

		if conn.RemoteAddr().Network() == "tcp" {
			InitialConnectionPackage = append([]byte{0x00, 0x1e}, InitialConnectionPackage...)
		}

		response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
		if err != nil {
			log.Printf("Error sending/receiving DNS query: %v", err)
			continue
		}

		if len(response) == 0 {
			log.Printf("Received empty response")
			continue
		}

		if conn.RemoteAddr().Network() == "udp" {
			if !bytes.Equal(transactionID, response[:2]) {
				log.Printf("Transaction ID mismatch for UDP response")
				continue
			}
		}

		if conn.RemoteAddr().Network() == "tcp" {
			if !bytes.Equal(transactionID, response[2:4]) {
				log.Printf("Transaction ID mismatch for TCP response")
				continue
			}
		}

		// Parse the response manually
		banner, err := parseDNSResponse(response)
		if err != nil {
			log.Printf("Error parsing DNS response: %v", err)
			continue
		}

		if banner != "" {
			return true, banner, nil
		}
	}

	return false, "", fmt.Errorf("failed to get valid DNS response after 3 attempts")
}

func parseDNSResponse(response []byte) (string, error) {
	log.Printf("Raw DNS response: %x", response)
	reader := bytes.NewReader(response)

	// Skip the header (12 bytes)
	header := make([]byte, 12)
	if _, err := reader.Read(header); err != nil {
		return "", fmt.Errorf("error reading DNS header: %w", err)
	}
	log.Printf("DNS header: %x", header)

	// Read the question section (variable length)
	for {
		var length byte
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return "", fmt.Errorf("error reading question section length: %w", err)
		}

		if length == 0 {
			break
		}

		if _, err := reader.Seek(int64(length), 1); err != nil {
			return "", fmt.Errorf("error skipping question section: %w", err)
		}
	}

	// Skip the question type and class (4 bytes)
	qTypeClass := make([]byte, 4)
	if _, err := reader.Read(qTypeClass); err != nil {
		return "", fmt.Errorf("error reading question type/class: %w", err)
	}
	log.Printf("DNS question type/class: %x", qTypeClass)

	// Read the answer name (handle compression)
	_, err := readName(reader)
	if err != nil {
		return "", fmt.Errorf("error reading answer name: %w", err)
	}

	var answerType uint16
	if err := binary.Read(reader, binary.BigEndian, &answerType); err != nil {
		return "", fmt.Errorf("error reading answer type: %w", err)
	}
	log.Printf("DNS answer type: %x", answerType)

	if answerType != 0x0010 { // Check if the answer type is TXT (0x0010)
		return "", fmt.Errorf("unexpected answer type: %x", answerType)
	}

	// Read the answer class (2 bytes), TTL (4 bytes), and RDLength (2 bytes)
	answerMeta := make([]byte, 8)
	if _, err := reader.Read(answerMeta); err != nil {
		return "", fmt.Errorf("error reading answer metadata: %w", err)
	}
	log.Printf("DNS answer metadata: %x", answerMeta)

	var rdLength uint16
	if err := binary.Read(reader, binary.BigEndian, &rdLength); err != nil {
		return "", fmt.Errorf("error reading RDLength: %w", err)
	}
	log.Printf("DNS RDLength: %x", rdLength)

	// Read the TXT data
	txtData := make([]byte, rdLength)
	if _, err := reader.Read(txtData); err != nil {
		return "", fmt.Errorf("error reading TXT data: %w", err)
	}
	log.Printf("TXT Data: %x", txtData)

	if len(txtData) > 0 {
		return string(txtData[1:]), nil
	}

	return "", fmt.Errorf("no TXT data found")
}

func readName(reader *bytes.Reader) ([]byte, error) {
	var name []byte

	for {
		var length byte
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("error reading name length: %w", err)
		}

		// Check for name compression
		if length&0xc0 == 0xc0 {
			var offset byte
			if err := binary.Read(reader, binary.BigEndian, &offset); err != nil {
				return nil, fmt.Errorf("error reading name offset: %w", err)
			}
			// Use the offset to read the name (not implemented here for simplicity)
			name = append(name, length, offset)
			break
		}

		if length == 0 {
			break
		}

		part := make([]byte, length)
		if _, err := reader.Read(part); err != nil {
			return nil, fmt.Errorf("error reading name part: %w", err)
		}
		name = append(name, part...)
		name = append(name, '.')
	}

	return name, nil
}

func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, banner, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		return plugins.CreateServiceFrom(target, payload, false, banner, plugins.UDP), nil
	}

	return nil, nil
}

func (p *UDPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p UDPPlugin) Name() string {
	return DNS
}

func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, banner, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		return plugins.CreateServiceFrom(target, payload, false, banner, plugins.TCP), nil
	}

	return nil, nil
}

func (p TCPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p TCPPlugin) Name() string {
	return DNS
}

func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}
