package dns

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
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
		client := &dns.Client{
			Net:     conn.RemoteAddr().Network(),
			Timeout: timeout,
		}

		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn("version.bind."), dns.TypeTXT)
		message.Question[0].Qclass = dns.ClassCHAOS
		message.RecursionDesired = false
		message.Id = dns.Id()

		addr := conn.RemoteAddr().String()
		in, _, err := client.Exchange(message, addr)
		if err != nil {
			//log.Printf("Error exchanging DNS query: %v", err)
			continue
		}

		//log.Printf("DNS query RTT: %v", rtt)

		// Parse the response
		banner, err := parseDNSResponse(in)
		if err != nil {
			//log.Printf("Error parsing DNS response: %v", err)
			continue
		}

		if banner != "" {
			return true, banner, nil
		}
	}

	return false, "", fmt.Errorf("failed to get valid DNS response after 3 attempts")
}

func parseDNSResponse(msg *dns.Msg) (string, error) {
	//log.Printf("Parsing DNS response: %v", msg)
	for _, answer := range msg.Answer {
		//log.Printf("Answer: %v", answer)
		if txt, ok := answer.(*dns.TXT); ok && txt.Hdr.Name == "version.bind." && txt.Hdr.Class == dns.ClassCHAOS {
			if len(txt.Txt) > 0 {
				return txt.Txt[0], nil
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
		payload := plugins.ServiceDNS{
			Banner: banner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
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
		payload := plugins.ServiceDNS{
			Banner: banner,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
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
