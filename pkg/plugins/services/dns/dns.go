package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
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
		response, err := sendDNSQuery(conn, timeout)
		if err != nil {
			log.Printf("Error sending DNS query: %v", err)
			continue
		}

		// Parse the response
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

func sendDNSQuery(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(timeout))

	message := createDNSQueryMessage()

	if conn.RemoteAddr().Network() == "tcp" {
		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(message)))
		message = append(length, message...)
	}

	if _, err := conn.Write(message); err != nil {
		return nil, err
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

func createDNSQueryMessage() []byte {
	var buffer bytes.Buffer

	// Transaction ID
	transactionID := make([]byte, 2)
	binary.Write(&buffer, binary.BigEndian, transactionID)

	// Flags (Standard query)
	binary.Write(&buffer, binary.BigEndian, uint16(0x0100))

	// Questions
	binary.Write(&buffer, binary.BigEndian, uint16(1))

	// Answer RRs, Authority RRs, Additional RRs
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))
	binary.Write(&buffer, binary.BigEndian, uint16(0))

	// Query: version.bind, TXT, CHAOS class
	query := []byte{
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n', // "version"
		0x04, 'b', 'i', 'n', 'd', // "bind"
		0x00,       // null terminator
		0x00, 0x10, // QTYPE: TXT
		0x00, 0x03, // QCLASS: CHAOS
	}
	buffer.Write(query)

	return buffer.Bytes()
}

func parseDNSResponse(response []byte) (string, error) {
	log.Printf("Raw DNS response: %x", response)

	if len(response) < 12 {
		return "", fmt.Errorf("invalid DNS response")
	}

	header := response[:12]
	qdCount := binary.BigEndian.Uint16(header[4:6])
	anCount := binary.BigEndian.Uint16(header[6:8])

	log.Printf("DNS header: %x", header)
	log.Printf("Questions: %d, Answers: %d", qdCount, anCount)

	offset := 12
	for i := 0; i < int(qdCount); i++ {
		offset += int(response[offset]) + 5
	}

	for i := 0; i < int(anCount); i++ {
		offset += int(response[offset]) + 1
		if offset+10 > len(response) {
			return "", fmt.Errorf("invalid DNS answer offset")
		}

		answerType := binary.BigEndian.Uint16(response[offset+2 : offset+4])
		if answerType != 0x0010 { // Check if the answer type is TXT (0x0010)
			offset += 10
			continue
		}

		rdataLen := binary.BigEndian.Uint16(response[offset+8 : offset+10])
		if offset+10+int(rdataLen) > len(response) {
			return "", fmt.Errorf("invalid RDATA length")
		}

		txtData := response[offset+10 : offset+10+int(rdataLen)]
		if len(txtData) > 1 {
			return string(txtData[1:]), nil // skip the first byte which represents the length of the TXT record
		}

		offset += 10 + int(rdataLen)
	}

	return "", fmt.Errorf("version.bind TXT record not found")
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
