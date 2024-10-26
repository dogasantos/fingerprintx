package msrpc

import (
	"context"
	"fmt"

	"github.com/dogasantos/fingerprintx/plugins"
	"github.com/dogasantos/fingerprintx/protocol"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

func init() {
	plugins.Register("msrpc", &MSRPCPlugin{})
}

// MSRPCPlugin defines the MSRPC plugin structure
type MSRPCPlugin struct{}

// Name returns the name of the plugin
func (p *MSRPCPlugin) Name() string {
	return "MSRPC"
}

// Port returns the default port for MSRPC
func (p *MSRPCPlugin) Port() int {
	return 135
}

func (p *MSRPCPlugin) Detect(ctx context.Context, host string, port int, opts *plugins.Options) (*plugins.Result, error) {
	target := fmt.Sprintf("%s:%d", host, port)
	result := &plugins.Result{
		Protocol: p.Name(),
		Host:     host,
		Port:     port,
	}

	// Initialize the ServiceMSRPC struct
	service := ServiceMSRPC{}

	// Set up context with optional authentication
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

	// Connect to MSRPC endpoint
	cc, err := dcerpc.Dial(gssCtx, target, well_known.EndpointMapper())
	if err != nil {
		return nil, fmt.Errorf("failed to dial MSRPC: %w", err)
	}
	defer cc.Close(gssCtx)

	// Query endpoints using EPM client
	cli, err := epm.NewEpmClient(gssCtx, cc)
	if err != nil {
		return nil, fmt.Errorf("failed to create EPM client: %w", err)
	}

	resp, err := cli.Lookup(gssCtx, &epm.LookupRequest{MaxEntries: 500})
	if err != nil {
		return nil, fmt.Errorf("failed to perform MSRPC lookup: %w", err)
	}

	// Populate service entries with MSRPC endpoints
	for _, entry := range resp.Entries {
		for _, floor := range entry.Tower.Floors() {
			uuidStr := ""
			if floor.UUID != nil {
				uuidStr = floor.UUID.String()
			}

			service.Entries = append(service.Entries, MSRPCEntry{
				UUID:     uuidStr,
				Version:  fmt.Sprintf("v%d.%d", floor.VersionMajor, floor.VersionMinor),
				Protocol: "MSRPC",
				Address:  target,
				Info:     entry.Annotation,
				Owner:    "", // Owner information can be set if available
			})
		}
	}

	// Attach the ServiceMSRPC data to the result
	result.Metadata = append(result.Metadata, protocol.Metadata{
		Key:   "ServiceMSRPC",
		Value: service,
	})

	return result, nil
}

// detectWindowsBuild tries to retrieve the Windows build version, if possible
func (p *MSRPCPlugin) detectWindowsBuild(ctx context.Context, cli *epm.EpmClient) (string, error) {
	// Placeholder for actual logic to retrieve build version from endpoint or other sources
	// Implement specific checks here
	return "Unknown", nil
}
