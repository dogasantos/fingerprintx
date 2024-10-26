package msrpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/dogasantos/fingerprintx/pkg/plugins"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
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

// PortPriority determines if this plugin takes priority on a given port
func (p *MSRPCPlugin) PortPriority(port uint16) bool {
	return port == 135
}

// Priority defines the general priority of the plugin
func (p *MSRPCPlugin) Priority() int {
	return 10
}

// Type returns the protocol type for MSRPC
func (p *MSRPCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Run is the entry point for the plugin and is called by fingerprintx
func (p *MSRPCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if target.Address.Addr().IsValid() == false {
		return nil, fmt.Errorf("invalid target address")
	}
	return p.Detect(context.Background(), target, nil)
}

// Detect performs MSRPC detection, listing available endpoints if the `list` option is set
func (p *MSRPCPlugin) Detect(ctx context.Context, target plugins.Target, opts interface{}) (*plugins.Service, error) {
	result := &plugins.Service{
		Host:     target.Host,
		IP:       target.Address.Addr().String(),
		Port:     int(target.Address.Port()),
		Protocol: plugins.ProtoMSRPC,
	}

	// Initialize ServiceMSRPC
	service := plugins.ServiceMSRPC{}
	targetAddr := fmt.Sprintf("%s:%d", target.Host, p.Port())

	// Configure GSS-API context with anonymous credentials
	gssCtx := gssapi.NewSecurityContext(ctx)
	gssapi.AddCredential(credential.Anonymous())
	gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.NTLM)

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

	// Populate MSRPC entries in service metadata
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
				Owner:    "", // Owner can be filled if additional info is available
			})
		}
	}

	// Convert ServiceMSRPC to JSON and assign it as Metadata
	/*
		metadataJSON, err := json.Marshal(service)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal service metadata: %w", err)
		}
		result.Metadata = json.RawMessage(metadataJSON)
	*/
	return result, nil
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
