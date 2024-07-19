package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
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
	var header dns.MsgHdr
	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		return "", fmt.Errorf("error reading DNS header: %w", err)
	}
	log.Printf("DNS header: %+v", header)

	questionCount := header.Qdcount
	for i := uint16(0); i < questionCount; i++ {
		_, err := dns.NewName(reader)
		if err != nil {
			return "", fmt.Errorf("error reading DNS question name: %w", err)
		}
		var questionType uint16
		var questionClass uint16
		if err := binary.Read(reader, binary.BigEndian, &questionType); err != nil {
			return "", fmt.Errorf("error reading DNS question type: %w", err)
		}
		if err := binary.Read(reader, binary.BigEndian, &questionClass); err != nil {
			return "", fmt.Errorf("error reading DNS question class: %w", err)
		}
		log.Printf("DNS question type: %d, class: %d", questionType, questionClass)
	}

	answerCount := header.Ancount
	for i := uint16(0); i < answerCount; i++ {
		name, err := dns.NewName(reader)
		if err != nil {
			return "", fmt.Errorf("error reading DNS answer name: %w", err)
		}
		log.Printf("DNS answer name: %s", name)

		var answerType uint16
		var answerClass uint16
		var ttl uint32
		var rdlength uint16
		if err := binary.Read(reader, binary.BigEndian, &answerType); err != nil {
			return "", fmt.Errorf("error reading DNS answer type: %w", err)
		}
		if err := binary.Read(reader, binary.BigEndian, &answerClass); err != nil {
			return "", fmt.Errorf("error reading DNS answer class: %w", err)
		}
		if err := binary.Read(reader, binary.BigEndian, &ttl); err != nil {
			return "", fmt.Errorf("error reading DNS answer TTL: %w", err)
		}
		if err := binary.Read(reader, binary.BigEndian, &rdlength); err != nil {
			return "", fmt.Errorf("error reading DNS answer RDLength: %w", err)
		}
		log.Printf("DNS answer type: %d, class: %d, ttl: %d, rdlength: %d", answerType, answerClass, ttl, rdlength)

		rdata := make([]byte, rdlength)
		if _, err := reader.Read(rdata); err != nil {
			return "", fmt.Errorf("error reading DNS answer RData: %w", err)
		}

		if answerType == dns.TypeTXT {
			txt := dns.TXT{
				Hdr: dns.RR_Header{
					Name:     name,
					Rrtype:   answerType,
					Class:    answerClass,
					Ttl:      ttl,
					Rdlength: rdlength,
				},
				Txt: []string{string(rdata)},
			}
			log.Printf("TXT Record: %s", txt.Txt)
			return "version.bind: " + txt.Txt[0], nil
		}
	}

	return "", fmt.Errorf("no TXT records found")
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
