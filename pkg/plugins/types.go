// types.go

package plugins

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// type SupportedIPVersion uint64
type Protocol uint64

const (
	IP Protocol = iota + 1
	UDP
	TCP
	TCPTLS
)

const TypeService string = "service"

const (
	ProtoRMI        = "rmi"
	ProtoDNS        = "dns"
	ProtoDHCP       = "dhcp"
	ProtoEcho       = "echo"
	ProtoEPMD       = "epmd"
	ProtoFGFMSD     = "fgfmsd"
	ProtoDameware   = "damewaremr"
	ProtoFTP        = "ftp"
	ProtoHTTP       = "http"
	ProtoHTTPS      = "https"
	ProtoHTTP2      = "http2"
	ProtoIMAP       = "imap"
	ProtoIMAPS      = "imaps"
	ProtoIPMI       = "ipmi"
	ProtoIPSEC      = "ipsec"
	ProtoJDWP       = "jdwp"
	ProtoKafka      = "kafka"
	ProtoLDAP       = "ldap"
	ProtoLDAPS      = "ldaps"
	ProtoModbus     = "modbus"
	ProtoMQ         = "activemq" // Generic MQ protocol for ActiveMQ, RabbitMQ, etc.
	ProtoAMQP       = "amqp"
	ProtoMQTT       = "mqtt"
	ProtoMSSQL      = "mssql"
	ProtoMSRPC      = "msrpc"
	ProtoMySQL      = "mysql"
	ProtoNetbios    = "netbios"
	ProtoNTP        = "ntp"
	ProtoOracle     = "oracle"
	ProtoOpenVPN    = "openvpn"
	ProtoPOP3       = "pop3"
	ProtoPOP3S      = "pop3s"
	ProtoPostgreSQL = "postgresql"
	ProtoRDP        = "rdp"
	ProtoRPC        = "rpc"
	ProtoRedis      = "redis"
	ProtoRedisTLS   = "redis"
	ProtoRsync      = "rsync"
	ProtoRtsp       = "rtsp"
	ProtoSMB        = "smb"
	ProtoSMTP       = "smtp"
	ProtoSMTPS      = "smtps"
	ProtoSNMP       = "snmp"
	ProtoSSH        = "ssh"
	ProtoStun       = "stun"
	ProtoTelnet     = "telnet"
	ProtoVNC        = "vnc"
	ProtoNFS        = "nfs"
	ProtoUnknown    = "unknown"
)

// Used as a key for maps to plugins.
// i.e.: map[Service] Plugin
type PluginID struct {
	name     string
	protocol Protocol
}

type Metadata interface {
	Type() string
}

func (e Service) Type() string { return TypeService }

func (e Service) Metadata() Metadata {
	switch e.Protocol {
	case ProtoFGFMSD:
		var p ServiceFGFMSD
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDameware:
		var p ServiceDameware
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoEPMD:
		var p ServiceEPMD
		_ = json.Unmarshal(e.Raw, &p)
		return p

	case ProtoFTP:
		var p ServiceFTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPostgreSQL:
		var p ServicePostgreSQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoVNC:
		var p ServiceVNC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoTelnet:
		var p ServiceTelnet
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRedis:
		var p ServiceRedis
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTP:
		var p ServiceHTTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTPS:
		var p ServiceHTTPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTP2:
		var p ServiceHTTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMB:
		var p ServiceSMB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRDP:
		var p ServiceRDP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRPC:
		var p ServiceRPC
		_ = json.Unmarshal(e.Raw, &p)
		return p

	case ProtoMSSQL:
		var p ServiceMSSQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNetbios:
		var p ServiceNetbios
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKafka:
		var p ServiceKafka
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoOracle:
		var p ServiceOracle
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMySQL:
		var p ServiceMySQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMTP:
		var p ServiceSMTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMTPS:
		var p ServiceSMTPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLDAP:
		var p ServiceLDAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoModbus:
		var p ServiceModbus
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLDAPS:
		var p ServiceLDAPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSSH:
		var p ServiceSSH
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIMAP:
		var p ServiceIMAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRsync:
		var p ServiceRsync
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRtsp:
		var p ServiceRtsp
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIMAPS:
		var p ServiceIMAPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMQTT:
		var p ServiceMQTT
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMQ:
		var p ServiceMQ
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoAMQP:
		var p ServiceAMQP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRMI:
		var p ServiceRMI
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPOP3:
		var p ServicePOP3
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPOP3S:
		var p ServicePOP3S
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNFS:
		var p ServiceNFS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	default:
		var p ServiceUnknown
		_ = json.Unmarshal(e.Raw, &p)
		return p
	}
}

type ServiceUnknown map[string]any

func (e ServiceUnknown) Type() string { return ProtoUnknown }

func (e ServiceUnknown) Map() map[string]any { return e }

func CreateServiceFrom(target Target, m Metadata, tls bool, version string, transport Protocol) *Service {
	service := Service{}
	b, _ := json.Marshal(m)

	service.Host = target.Host
	service.IP = target.Address.Addr().String()
	service.Port = int(target.Address.Port())
	service.Protocol = m.Type()
	service.Transport = strings.ToLower(transport.String())
	service.Raw = json.RawMessage(b)
	if version != "" {
		service.Version = version
	}
	service.TLS = tls

	return &service
}

type Target struct {
	Address netip.AddrPort
	Host    string
}

type Plugin interface {
	Run(net.Conn, time.Duration, Target) (*Service, error)
	PortPriority(uint16) bool
	Name() string
	Type() Protocol
	Priority() int
}

type Service struct {
	Host      string          `json:"host,omitempty"`
	IP        string          `json:"ip"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol"`
	TLS       bool            `json:"tls"`
	Transport string          `json:"transport"`
	Version   string          `json:"version,omitempty"`
	Raw       json.RawMessage `json:"metadata"`
}

type ServiceNFS struct {
	VersionDetails string   `json:"versionDetails"`
	SharedContent  []string `json:"sharedContent"`
}

func (e ServiceNFS) Type() string { return ProtoNFS }

type ServiceHTTP struct {
	Status          string      `json:"status"`     // e.g. "200 OK"
	StatusCode      int         `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
}

func (e ServiceHTTP) Type() string { return ProtoHTTP }

type ServiceHTTPS struct {
	Status          string      `json:"status"`     // e.g. "200 OK"
	StatusCode      int         `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header `json:"responseHeaders"`
	Technologies    []string    `json:"technologies,omitempty"`
}

func (e ServiceHTTPS) Type() string { return ProtoHTTPS }

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"` // e.g. Windows Server 2016 or 2019
	OSVersion           string `json:"osVersion,omitempty"`
	TargetName          string `json:"targetName,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceRDP) Type() string { return ProtoRDP }

type ServiceRPC struct {
	Entries []RPCB `json:"entries"`
}

type RPCB struct {
	Program  int    `json:"program"`
	Version  int    `json:"version"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Owner    string `json:"owner"`
}

func (e ServiceRPC) Type() string { return ProtoRPC }

type ServiceSMB struct {
	SigningEnabled      bool   `json:"signingEnabled"`  // e.g. Is SMB Signing Enabled?
	SigningRequired     bool   `json:"signingRequired"` // e.g. Is SMB Signing Required?
	OSVersion           string `json:"osVersion"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceSMB) Type() string { return ProtoSMB }

type ServiceMySQL struct {
	PacketType   string `json:"packetType"` // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string `json:"errorMsg"`   // error message if the server returns an error packet
	ErrorCode    int    `json:"errorCode"`  // error code returned if the server returns an error packet
	Version      string `json:"version"`    // version based on some differential analysis (aproximated)
}

func (e ServiceMySQL) Type() string { return ProtoMySQL }

func (e ServicePostgreSQL) Type() string { return ProtoPostgreSQL }

type ServicePostgreSQL struct {
	AuthRequired bool `json:"authRequired"`
}

type ServicePOP3 struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3) Type() string { return ProtoPOP3 }

type ServicePOP3S struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3S) Type() string { return ProtoPOP3S }

type ServiceSNMP struct{}

func (e ServiceSNMP) Type() string { return ProtoSNMP }

type ServiceNTP struct{}

func (e ServiceNTP) Type() string { return ProtoNTP }

type ServiceNetbios struct {
	NetBIOSName string `json:"netBIOSName"`
}

func (e ServiceNetbios) Type() string { return ProtoNetbios }

type ServiceIMAP struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAP) Type() string { return ProtoIMAP }

type ServiceIMAPS struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAPS) Type() string { return ProtoIMAPS }

type ServiceIPSEC struct {
	ResponderISP string `json:"responderISP"`
	MessageID    string `json:"messageID"`
}

func (e ServiceIPSEC) Type() string { return ProtoIPSEC }

type ServiceMQ struct {
	Provider string `json:"provider,omitempty"` // Detected MQ provider, e.g., "ActiveMQ", "RabbitMQ", "IBM MQ"
	Version  string `json:"version,omitempty"`  // Detected protocol or service version
	Details  string `json:"details,omitempty"`  // Additional human-readable details (e.g., OS, architecture, platform info)
	Os       string `json:"os,omitempty"`       // Additional human-readable details (e.g., OS, architecture, platform info)
	Jvm      string `json:"jvm,omitempty"`      // Additional human-readable details (e.g., OS, architecture, platform info)
}

func (e ServiceMQ) Type() string { return ProtoMQ }

type ServiceAMQP struct {
	Provider string            `json:"provider,omitempty"` // Detected MQ provider, e.g., "ActiveMQ", "RabbitMQ", "IBM MQ"
	Version  string            `json:"version,omitempty"`  // Detected protocol or service version
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (e ServiceAMQP) Type() string { return ProtoAMQP }

type ServiceEPMD struct {
	Provider string `json:"provider,omitempty"`
}

func (e ServiceEPMD) Type() string { return ProtoEPMD }

type ServiceRMI struct {
	Provider string `json:"provider"`
}

func (e ServiceRMI) Type() string { return ProtoRMI }

type ServiceMSSQL struct{}

func (e ServiceMSSQL) Type() string { return ProtoMSSQL }

type ServiceVNC struct{}

func (e ServiceVNC) Type() string { return ProtoVNC }

type ServiceTelnet struct {
	ServerData string `json:"serverData"`
}

func (e ServiceTelnet) Type() string { return ProtoTelnet }

type ServiceRedis struct {
	ProtectedMode   bool   `json:"protectedMode"`
	AuthRequired    bool   `json:"authRequired"`
	Version         string `json:"version"`
	OperatingSystem string `json:"OperatingSystem"`
}

func (e ServiceRedis) Type() string { return ProtoRedis }

type ServiceFTP struct {
	Banner string `json:"banner"`
}

func (e ServiceFTP) Type() string { return ProtoFTP }

type ServiceFGFMSD struct {
	String string `json:"String"`
}

func (e ServiceFGFMSD) Type() string { return ProtoFGFMSD }

type ServiceDameware struct {
	Banner string `json:"banner"`
}

func (e ServiceDameware) Type() string { return ProtoDameware }

type ServiceSMTP struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTP) Type() string { return ProtoSMTP }

type ServiceSMTPS struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTPS) Type() string { return ProtoSMTPS }

type ServiceStun struct {
	Info string `json:"info"`
}

func (e ServiceStun) Type() string { return ProtoStun }

type ServiceSSH struct {
	Banner              string `json:"banner"`
	PasswordAuthEnabled bool   `json:"passwordAuthEnabled"`
	Algo                string `json:"algo"`
	HostKey             string `json:"hostKey,omitempty"`
	HostKeyType         string `json:"hostKeyType,omitempty"`
	HostKeyFingerprint  string `json:"hostKeyFingerprint,omitempty"`
}

func (e ServiceSSH) Type() string { return ProtoSSH }

type ServiceLDAP struct{}

func (e ServiceLDAP) Type() string { return ProtoLDAP }

type ServiceLDAPS struct{}

func (e ServiceLDAPS) Type() string { return ProtoLDAPS }

type ServiceKafka struct{}

func (e ServiceKafka) Type() string { return ProtoKafka }

type ServiceOracle struct {
	Info string `json:"info"`
}

func (e ServiceOracle) Type() string { return ProtoOracle }

type ServiceOpenVPN struct{}

func (e ServiceOpenVPN) Type() string { return ProtoOpenVPN }

type ServiceMQTT struct{}

func (e ServiceMQTT) Type() string { return ProtoMQTT }

type ServiceModbus struct{}

func (e ServiceModbus) Type() string { return ProtoModbus }

type ServiceRtsp struct {
	ServerInfo string `json:"serverInfo"`
}

func (e ServiceRtsp) Type() string { return ProtoRtsp }

type ServiceDNS struct {
	Banner string `json:"banner,omitempty"`
}

func (e ServiceDNS) Type() string { return ProtoDNS }

type ServiceDHCP struct {
	Option string `json:"option"`
}

func (e ServiceDHCP) Type() string { return ProtoDHCP }

type ServiceEcho struct{}

func (e ServiceEcho) Type() string { return ProtoEcho }

type ServiceIPMI struct{}

func (e ServiceIPMI) Type() string { return ProtoIPMI }

type ServiceRsync struct{}

func (e ServiceRsync) Type() string { return ProtoRsync }

type ServiceJDWP struct {
	Description string `json:"description"`
	JdwpMajor   int32  `json:"jdwpMajor"`
	JdwpMinor   int32  `json:"jdwpMinor"`
	VMVersion   string `json:"VMVersion"`
	VMName      string `json:"VMName"`
}

func (e ServiceJDWP) Type() string { return ProtoJDWP }
