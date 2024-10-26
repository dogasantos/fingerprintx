package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcetypes"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/even/eventlog/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/even6/ieventservice/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/nrpc/logon/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
	"github.com/rs/zerolog"

	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

var (
	short    bool
	server   string
	username string
	password string
	port     string
	detect   bool
	list     bool
	security bool
)

func init() {
	flag.BoolVar(&short, "s", false, "short form")
	flag.StringVar(&server, "t", "", "target server")
	flag.StringVar(&username, "u", "", "username for authentication")
	flag.StringVar(&password, "p", "", "password for authentication")
	flag.StringVar(&port, "c", "135", "port to connect to")
	flag.BoolVar(&detect, "d", false, "detect if the ip:port is running MSRPC")
	flag.BoolVar(&list, "l", false, "list the endpoints")
	flag.BoolVar(&security, "sec", false, "detect security products")
	flag.Parse()
}

type Endpoint struct {
	UUID    string `json:"uuid"`
	Version string `json:"version"`
	Info    string `json:"info"`
	Extra   string `json:"extra"`
}

type Output struct {
	Server    string     `json:"server"`
	MSRPC     bool       `json:"msrpc"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

func main() {
	if server == "" {
		fmt.Fprintln(os.Stderr, "target server must be specified with -t")
		return
	}
	if !(detect || list) {
		fmt.Fprintln(os.Stderr, "either -d (detect) or -l (list) must be specified")
		return
	}

	output := Output{Server: fmt.Sprintf("%s:%s", server, port)}

	var ctx context.Context
	if username != "" && password != "" {
		ctx = gssapi.NewSecurityContext(context.Background())
		gssapi.AddCredential(credential.NewFromPassword(username, password))
		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.NTLM)
	} else {
		ctx = gssapi.NewSecurityContext(context.Background())
		gssapi.AddCredential(credential.Anonymous())
		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.NTLM)
	}
	// Set up logger to discard output
	zerolog.SetGlobalLevel(zerolog.Disabled)

	target := fmt.Sprintf("%s:%s", server, port)
	cc, err := dcerpc.Dial(ctx, target, well_known.EndpointMapper())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		output.MSRPC = false
		jsonOutput, _ := json.Marshal(output)
		fmt.Println(string(jsonOutput))
		return
	}
	defer cc.Close(ctx)

	cli, err := epm.NewEpmClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(server), dcerpc.WithVerifyBitMask(true), dcerpc.WithVerifyPresenetation(true), dcerpc.WithVerifyHeader2(true), dcerpc.WithLogger(zerolog.New(os.Stdout)))
	if err != nil {
		if strings.Contains(err.Error(), "ntlm: init: authenticate:") || strings.Contains(err.Error(), "ERROR_ACCESS_DENIED") {
			output.MSRPC = true
		} else if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "packet is too long") {
			output.MSRPC = false
			jsonOutput, _ := json.Marshal(output)
			fmt.Println(string(jsonOutput))
			return
		}
		fmt.Fprintln(os.Stderr, err)
		jsonOutput, _ := json.Marshal(output)
		fmt.Println(string(jsonOutput))
		return
	}

	resp, err := cli.Lookup(ctx, &epm.LookupRequest{MaxEntries: 500})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		output.MSRPC = false
		jsonOutput, _ := json.Marshal(output)
		fmt.Println(string(jsonOutput))
		return
	}
	output.MSRPC = true
	if detect {
		jsonOutput, _ := json.Marshal(output)
		fmt.Println(string(jsonOutput))
		return
	}

	if short {
		for _, entries := range resp.Entries {
			uuidStr := ""
			if entries.Tower.Floors()[0].UUID != nil {
				uuidStr = entries.Tower.Floors()[0].UUID.String()
			}
			output.Endpoints = append(output.Endpoints, Endpoint{
				UUID:    uuidStr,
				Version: fmt.Sprintf("v%d.%d", entries.Tower.Floors()[0].VersionMajor, entries.Tower.Floors()[0].VersionMinor),
				Info:    entries.Annotation,
				Extra:   "",
			})
		}
	} else {
		for _, entries := range resp.Entries {
			for _, floor := range entries.Tower.Floors() {
				uuidStr := ""
				if floor.UUID != nil {
					uuidStr = floor.UUID.String()
				}
				output.Endpoints = append(output.Endpoints, Endpoint{
					UUID:    uuidStr,
					Version: fmt.Sprintf("v%d.%d", floor.VersionMajor, floor.VersionMinor),
					Info:    entries.Annotation,
					Extra:   "",
				})
			}
		}
	}

	if list {
		if security {
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, &dcerpc.SyntaxID{IfUUID: parseUUID("93f08797-433a-4933-a042-0b809ad4a710"), IfVersionMajor: 1, IfVersionMinor: 0})...)
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, &dcerpc.SyntaxID{IfUUID: parseUUID("9056e081-7ed4-4d1d-8efc-c84a91c04808"), IfVersionMajor: 1, IfVersionMinor: 0})...)
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, &dcerpc.SyntaxID{IfUUID: parseUUID("8c1a0cc4-1f5a-442e-868a-99b745e9283e"), IfVersionMajor: 1, IfVersionMinor: 0})...)
			// Additional security UUIDs
		} else {
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, logon.LogonSyntaxV1_0)...)
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, dnsserver.DNSServerSyntaxV5_0)...)
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, epm.EpmSyntaxV3_0)...)
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, ieventservice.EventServiceSyntaxV1_0)...)
			output.Endpoints = append(output.Endpoints, mapEndpoints(ctx, cli, eventlog.EventlogSyntaxV0_0)...)
		}
	}
	jsonOutput, _ := json.Marshal(output)
	fmt.Println(string(jsonOutput))
}

func mapEndpoints(ctx context.Context, cli epm.EpmClient, syntax *dcerpc.SyntaxID) []Endpoint {
	resp, err := cli.Map(ctx, &epm.MapRequest{
		MapTower: dcetypes.FloorsToTower([]*dcetypes.Floor{
			{
				Protocol:     uint8(dcetypes.ProtocolUUID),
				UUID:         syntax.IfUUID,
				VersionMajor: syntax.IfVersionMajor,
				Data:         []byte{0, 0},
			},
			{
				Protocol:     uint8(dcetypes.ProtocolUUID),
				UUID:         dcerpc.TransferNDR,
				VersionMajor: syntax.IfVersionMajor,
				Data:         binary.LittleEndian.AppendUint16(nil, syntax.IfVersionMinor),
			},
			{
				Protocol: uint8(dcetypes.ProtocolRPC_CO),
				Data:     []byte{0, 0},
			},
			{
				Protocol: uint8(dcetypes.ProtocolTCP),
				Data:     []byte{0, 0},
			},
			{
				Protocol: uint8(dcetypes.ProtocolIP),
				Data:     []byte{0, 0, 0, 0},
			},
		}),
		MaxTowers: 100,
	})

	if err != nil {
		fmt.Println("error", err)
		return nil
	}

	var endpoints []Endpoint
	for _, tower := range resp.Towers {
		for _, floor := range tower.Floors() {
			uuidStr := ""
			if floor.UUID != nil {
				uuidStr = floor.UUID.String()
			}
			endpoints = append(endpoints, Endpoint{
				UUID:    uuidStr,
				Version: fmt.Sprintf("v%d.%d", floor.VersionMajor, floor.VersionMinor),
				Info:    "", // Update with relevant information if available
				Extra:   "", // Update with relevant information if available
			})
		}
	}
	return endpoints
}

func parseUUID(s string) *uuid.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse UUID %s: %v\n", s, err)
		os.Exit(1)
	}
	return u
}
