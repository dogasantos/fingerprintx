package fgfmsd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
)

type FGFMSDPlugin struct{}

const FGFMSD = "fgfmsd"

// Base64 Encoded Certificate and Private Key
const (
	clientCertBase64 = "-----BEGIN CERTIFICATE-----
MIIDzDCCArSgAwIBAgIDBjE+MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREwDwYD
VQQKEwhGb3J0aW5ldDEeMBwGA1UECxMVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRAw
DgYDVQQDEwdzdXBwb3J0MSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGZvcnRpbmV0
LmNvbTAeFw0xNzExMTAyMTE0MjZaFw0zODAxMTkwMzE0MDdaMIGgMQswCQYDVQQG
EwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU3Vubnl2YWxlMREw
DwYDVQQKEwhGb3J0aW5ldDEVMBMGA1UECxMMRm9ydGlNYW5hZ2VyMRkwFwYDVQQD
ExBGTUctVk0wMDAwMDAwMDAwMSMwIQYJKoZIhvcNAQkBFhRzdXBwb3J0QGZvcnRp
bmV0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMcgGzRlTTeV
jIcE8D7z7Vnp6LKDcGE57VL4qs1fOxvTrK2j7vWbVMHSsOpf8taAAm55qmqeS//w
oCJQq3t5mmq1M6MHm2nom6Q+dObcsfhieLrIFwp9X1Xt9YHKQd5qOR5PysrMhFKd
pwMJfmlzuWWcIUeilgecP6eq9GS50gu4m+0NK0d3LTsmWz1jLNC3k74fYwYDsaPn
hl/tsxcqZWrYHUHJhH5ep8YAxE6Eo2JG67BXOI/JbxrWPEh+zRLqA7ZrWeBPl0AE
IXTK+SIBJTW0dpnxEcG6wBQQxCp8jZ+RlaFpKjBdYucDVTDtkLabvetOrAn+mjcR
utg6NHlptSECAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEA
l265IvoXNxpTJEWdYwYvjAFdaueBk349ApvriQmsPdAJmhFgF4U8l6PI/kBPVYCg
zP0EA1zImHwLFkzlCVtMtzhuUY3h2ZIUEhYwX0xEf5Kay2XHicWAwugQ0k/QDmiv
w7/w7UTiwPaMLroEcjRbH8T4TLCXBdKsgXYW+t72CSA8MJDSug8o2yABom6XKlXl
35mD93BrFkbxhhAiCrrC63byX7XTuXTyrP1dO9Qi9aSPWrIbi2SV+SjTLhP0n1bd
ikVOHNNreyhQRlRjguPrW0P2Xqjbecgp98tdRyoOSr9sF5Qo5TKdvIwUFClFgsy+
7pactwTnQmwhvlLQ7Z/dOg==
-----END CERTIFICATE-----"
	clientKeyBase64  = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHIBs0ZU03lYyH
BPA+8+1Z6eiyg3BhOe1S+KrNXzsb06yto+71m1TB0rDqX/LWgAJueapqnkv/8KAi
UKt7eZpqtTOjB5tp6JukPnTm3LH4Yni6yBcKfV9V7fWBykHeajkeT8rKzIRSnacD
CX5pc7llnCFHopYHnD+nqvRkudILuJvtDStHdy07Jls9YyzQt5O+H2MGA7Gj54Zf
7bMXKmVq2B1ByYR+XqfGAMROhKNiRuuwVziPyW8a1jxIfs0S6gO2a1ngT5dABCF0
yvkiASU1tHaZ8RHBusAUEMQqfI2fkZWhaSowXWLnA1Uw7ZC2m73rTqwJ/po3EbrY
OjR5abUhAgMBAAECggEAcIXaGa+tBN4DfUDzKf/ZflfJ4SaZWLfNPne6vTc1RbJG
ABGFNVFDggu3YZo6ta+8sAUcogc11zl4pCuF286Jzgb7WQMxdZW2bgfFM7g+8adj
pdjv/EOAniRL+b37nt3TzSc154fOtojUGclBoAF/IMYroDlmIoLPDcZzOIAxC+GU
BCkCh/a3AFnhkkym0IGx4i89ji+nxcY5vEqD4n4Q49gkebxjmTVBq7YEU2YwOsbT
0BO9jmYKE0wumetNpYJsR2qVI7dUmJMNdcEah/A9ODqMM2BJUxovW8XgR9wOIXN2
3aWwmPeAtTnVhvBaHJL/ItGOGjmdcM1pwChowCWj4QKBgQD5EMo2A9+qeziSt3Ve
nmD1o7zDyGAe0bGLN4rIou6I/Zz8p7ckRYIAw2HhmsE2C2ZF8OS9GWmsu23tnTBl
DQTj1fSquw1cjLxUgwTkLUF7FTUBrxLstYSz1EJSzd8+V8mLI3bXriq8yFVK7z8y
jFBB3BqkqUcBjIWFAMDvWoyJtQKBgQDMq15o9bhWuR7rGTvzhDiZvDNemTHHdRWz
6cxb4d4TWsRsK73Bv1VFRg/SpDTg88kV2X8wqt7yfR2qhcyiAAFJq9pflG/rUSp6
KvNbcXW7ys+x33x+MkZtbSh8TJ3SP9IoppawB/SP/p2YxkdgjPF/sllPEAkgHznW
Gwk5jxRxPQKBgQDQAKGfcqS8b6PTg7tVhddbzZ67sv/zPRSVO5F/9fJYHdWZe0eL
1zC3CnUYQHHTfLmw93lQI4UJaI5pvrjH65OF4w0t+IE0JaSyv6i6FsF01UUrXtbj
MMTemgm5tY0XN6FtvfRmM2IlvvjcV+njgSMVnYfytBxEwuJPLU3zlx9/cQKBgQDB
2GEPugLAqI6fDoRYjNdqy/Q/WYrrJXrLrtkuAQvreuFkrj0IHuZtOQFNeNbYZC0E
871iY8PLGTMayaTZnnWZyBmIwzcJQhOgJ8PbzOc8WMdD6a6oe4d2ppdcutgTRP0Q
IU/BI5e/NeEfzFPYH0Wvs0Sg/EgYU1rc7ThceqZa5QKBgQCf18PRZcm7hVbjOn9i
BFpFMaECkVcf6YotgQuUKf6uGgF+/UOEl6rQXKcf1hYcSALViB6M9p5vd65FHq4e
oDzQRBEPL86xtNfQvbaIqKTalFDv4ht7DlF38BQx7MAlJQwuljj1hrQd9Ho+VFDu
Lh1BvSCTWFh0WIUxOrNlmlg1Uw==
-----END PRIVATE KEY-----"
)

var (
	commonFGFMSDPorts = map[int]struct{}{
		541: {},
	}
)

func init() {
	plugins.RegisterPlugin(&FGFMSDPlugin{})
}

// DecodeBase64Cert decodes the base64-encoded certificate and key
func DecodeBase64Cert() (tls.Certificate, error) {
	certPEM, err := base64.StdEncoding.DecodeString(clientCertBase64)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := base64.StdEncoding.DecodeString(clientKeyBase64)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ConnectWithCert establishes an SSL connection using the client certificate
func ConnectWithCert(address string, timeout time.Duration) (net.Conn, error) {
	cert, err := DecodeBase64Cert()
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", address, config)
}

// DetectFortinetVersion performs protocol-specific checks and inspects the server certificate
func DetectFortinetVersion(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Ensure we're working with a TLS connection
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("connection is not a TLS connection")
	}

	// Complete the handshake to retrieve the server certificate
	err := tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	// Retrieve the peer certificate
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in TLS connection")
	}

	// Extract information from the server certificate
	serverCert := certs[0]
	version := extractVersionFromCert(serverCert)
	platform := extractPlatformFromCert(serverCert)

	// Construct the response
	info := &plugins.Service{
		IP:        target.Address.Addr().String(),
		Port:      int(target.Address.Port()),
		Protocol:  "tcp",
		Transport: "tcp",
		Version:   version,
		Raw:       nil,
	}
	if platform != "" {
		info.Version += " (" + platform + ")"
	}

	return info, nil
}

// Helper function to extract the version from the server certificate
func extractVersionFromCert(cert *x509.Certificate) string {
	// Check Organizational Unit (OU) and Common Name (CN) for version info
	if len(cert.Subject.OrganizationalUnit) > 0 && strings.Contains(cert.Subject.OrganizationalUnit[0], "FortiCloud") {
		return "FortiCloud Service"
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	for _, org := range cert.Subject.Organization {
		if org != "" {
			return org
		}
	}
	return "Unknown Version"
}

// Helper function to extract the platform from the server certificate
func extractPlatformFromCert(cert *x509.Certificate) string {
	// Check Organizational Unit (OU) for platform details
	if len(cert.Subject.OrganizationalUnit) > 0 {
		if strings.Contains(cert.Subject.OrganizationalUnit[0], "FortiCloud") {
			return "FortiCloud Platform"
		}
		return cert.Subject.OrganizationalUnit[0]
	}
	return "Unknown Platform"
}

// Run is the main execution function of the plugin
func (p *FGFMSDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, err := DetectFortinetVersion(conn, timeout, target)
	if err != nil {
		return nil, err
	}

	if info == nil {
		return plugins.CreateServiceFrom(target, nil, false, "", plugins.TCP), nil
	}
	return plugins.CreateServiceFrom(target, info, false, info.Version, plugins.TCP), nil
}

// PortPriority specifies that port 541 is prioritized for this plugin
func (p *FGFMSDPlugin) PortPriority(port uint16) bool {
	_, ok := commonFGFMSDPorts[int(port)]
	return ok
}

// Name returns the name of the plugin (FGFMSD)
func (p *FGFMSDPlugin) Name() string {
	return FGFMSD
}

// Type specifies that this plugin handles the TCP protocol
func (p *FGFMSDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority assigns a priority to this plugin
func (p *FGFMSDPlugin) Priority() int {
	return 500
}
