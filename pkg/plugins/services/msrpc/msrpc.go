package msrpc

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	utils "github.com/dogasantos/fingerprintx/pkg/plugins/pluginutils"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcetypes"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// Register the MSRPC plugin
func init() {
	plugins.RegisterPlugin(&MSRPCPlugin{})
}

// MSRPCPlugin represents the MSRPC detection plugin
type MSRPCPlugin struct{}

// Name returns the plugin name
func (p *MSRPCPlugin) Name() string {
	return "msrpc"
}

// Port returns the default MSRPC port
func (p *MSRPCPlugin) Port() int {
	return 135
}

// Detect performs MSRPC detection, listing available endpoints if the `list` option is set
func (p *MSRPCPlugin) Detect(ctx context.Context, target plugins.Target, opts *plugins.Options) (*plugins.Service, error) {
	result := &plugins.Service{
		Host:     target.Host,
		IP:       target.Address.Addr().String(),
		Port:     int(target.Address.Port()),
		Protocol: plugins.ProtoMSRPC,
	}

	// Initialize ServiceMSRPC
	service := plugins.ServiceMSRPC{}
	targetAddr := fmt.Sprintf("%s:%d", target.Host, p.Port())

	// Configure GSS-API context with authentication if provided
	var gssCtx context.Context
	if opts.Username != "" && opts.Password != "" {
		gssCtx = gssapi.NewSecurityContext(ctx)
		gssapi.AddCredential(credential.NewFromPassword(opts.Username, opts.Password))
		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.NTLM)
	} else {
		gssCtx = gssapi.NewSecurityContext(ctx)
		gssapi.AddCredential(credential.Anonymous())
		gssapi.AddMechanism(ssp.SPNEGO)
		gssapi.AddMechanism(ssp.NTLM)
	}

	// Dial into the MSRPC endpoint
	cc, err := dcerpc.Dial(gssCtx, targetAddr, well_known.EndpointMapper())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MSRPC: %w", err)
	}
	defer cc.Close(gssCtx)

	// Create EPM client
	cli, err := epm.NewEpmClient(gssCtx, cc)
	if err != nil {
		return nil, fmt.Errorf("failed to create EPM client: %w", err)
	}

	// Perform a lookup of RPC endpoints
	resp, err := cli.Lookup(gssCtx, &epm.LookupRequest{MaxEntries: 500})
	if err != nil {
		return nil, fmt.Errorf("failed to perform MSRPC lookup: %w", err)
	}

	// Set detection success flag
	result.Metadata = map[string]interface{}{"MSRPC": true}

	// Populate MSRPC endpoints in service metadata
	for _, entry := range resp.Entries {
		for _, floor := range entry.Tower.Floors() {
			uuidStr := ""
			if floor.UUID != nil {
				uuidStr = floor.UUID.String()
			}
			service.Entries = append(service.Entries, plugins.MSRPCEntry{
				UUID:     uuidStr,
				Version:  fmt.Sprintf("v%d.%d", floor.VersionMajor, floor.VersionMinor),
				Protocol: "MSRPC",
				Address:  targetAddr,
				Info:     entry.Annotation,
			})
		}
	}

	// Add service metadata to the result
	utils.AddServiceMetadata(result, "ServiceMSRPC", service)
	return result, nil
}

// mapEndpoints maps additional RPC endpoints with specific syntax IDs
func mapEndpoints(ctx context.Context, cli epm.EpmClient, syntax *dcerpc.SyntaxID) []plugins.MSRPCEntry {
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

	var endpoints []plugins.MSRPCEntry
	for _, tower := range resp.Towers {
		for _, floor := range tower.Floors() {
			uuidStr := ""
			if floor.UUID != nil {
				uuidStr = floor.UUID.String()
			}
			endpoints = append(endpoints, plugins.MSRPCEntry{
				UUID:     uuidStr,
				Version:  fmt.Sprintf("v%d.%d", floor.VersionMajor, floor.VersionMinor),
				Protocol: "MSRPC",
				Address:  "", // The actual address would be set here
			})
		}
	}
	return endpoints
}

// parseUUID safely parses a UUID string for use in the plugin
func parseUUID(s string) *uuid.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		fmt.Printf("Failed to parse UUID %s: %v\n", s, err)
		return nil
	}
	return u
}
