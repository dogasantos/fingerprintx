package dns

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/paulstuart/dnsquery"
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
	resolver := dnsquery.NewResolver(conn.RemoteAddr().String())
	resolver.RetryTimes = 3
	resolver.QueryTimeout = timeout

	query := dnsquery.Query{
		Name:  "version.bind",
		Type:  dnsquery.TypeTXT,
		Class: dnsquery.ClassCHAOS,
	}

	response, err := resolver.Lookup(query)
	if err != nil {
		return nil, err
	}

	return response.Raw, nil
}

func parseDNSResponse(response []byte) (string, error) {
	log.Printf("Raw DNS response: %x", response)

	if len(response) < 12 {
		return "", fmt.Errorf("invalid DNS response")
	}

	parsed, err := dnsquery.Parse(response)
	if err != nil {
		return "", fmt.Errorf("error parsing DNS response: %v", err)
	}

	for _, answer := range parsed.Answers {
		if answer.Type == dnsquery.TypeTXT && answer.Name == "version.bind." {
			if len(answer.Data) > 0 {
				return answer.Data, nil
			}
		}
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
