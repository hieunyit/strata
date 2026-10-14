// Package admin serves the admin API (strata.admin.v1) over gRPC and, via
// grpc-gateway, as REST/JSON. The gateway reaches the gRPC server through an
// in-process connection, so both channels pass the same authentication and
// authorization interceptors.
package admin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/strata/strata/control-plane/auth"
	adminv1 "github.com/strata/strata/control-plane/gen/strata/admin/v1"
)

// Permissions lists every admin method. A method missing here is refused
// by the interceptors.
var Permissions = auth.MethodPermissions{
	adminv1.VersionService_GetVersion_FullMethodName:               auth.PermVersionRead,
	adminv1.FleetAdminService_ListGroups_FullMethodName:            auth.PermNodesRead,
	adminv1.FleetAdminService_CreateGroup_FullMethodName:           auth.PermNodesWrite,
	adminv1.FleetAdminService_CreateEnrollmentToken_FullMethodName: auth.PermNodesWrite,
	adminv1.FleetAdminService_ListNodes_FullMethodName:             auth.PermNodesRead,
	adminv1.FleetAdminService_RevokeNode_FullMethodName:            auth.PermNodesWrite,
	adminv1.FleetAdminService_ForceShadow_FullMethodName:           auth.PermPoliciesDeploy,
	adminv1.FleetAdminService_ClearForceShadow_FullMethodName:      auth.PermPoliciesDeploy,
	adminv1.FleetAdminService_CollectDiagnostics_FullMethodName:    auth.PermNodesWrite,
	adminv1.FleetAdminService_ListCommands_FullMethodName:          auth.PermNodesRead,
	adminv1.FleetAdminService_GetCommand_FullMethodName:            auth.PermNodesRead,
	adminv1.FleetAdminService_EmergencyDisableRule_FullMethodName:  auth.PermRulesDisable,
	adminv1.FleetAdminService_EnableRule_FullMethodName:            auth.PermRulesDisable,
	adminv1.FleetAdminService_ListDisabledRules_FullMethodName:     auth.PermNodesRead,
	adminv1.PolicyService_ListPolicies_FullMethodName:              auth.PermPoliciesRead,
	adminv1.PolicyService_GetPolicy_FullMethodName:                 auth.PermPoliciesRead,
	adminv1.PolicyService_CreatePolicy_FullMethodName:              auth.PermPoliciesWrite,
	adminv1.PolicyService_UpdatePolicy_FullMethodName:              auth.PermPoliciesWrite,
	adminv1.PolicyService_ListPolicyVersions_FullMethodName:        auth.PermPoliciesRead,
	adminv1.PolicyService_GetPolicyVersion_FullMethodName:          auth.PermPoliciesRead,
	adminv1.PolicyService_DeployPolicy_FullMethodName:              auth.PermPoliciesDeploy,
	adminv1.RolloutService_ListBundles_FullMethodName:              auth.PermNodesRead,
	adminv1.RolloutService_ListRollouts_FullMethodName:             auth.PermNodesRead,
	adminv1.RolloutService_GetRollout_FullMethodName:               auth.PermNodesRead,
	adminv1.RolloutService_PauseRollout_FullMethodName:             auth.PermPoliciesDeploy,
	adminv1.RolloutService_ResumeRollout_FullMethodName:            auth.PermPoliciesDeploy,
	adminv1.RolloutService_AbortRollout_FullMethodName:             auth.PermPoliciesDeploy,
}

// Deps are the services behind the admin API. A nil field leaves its
// service unregistered (its routes answer Unimplemented).
type Deps struct {
	Fleet    FleetStore
	Presence NodePresence
	Policies PolicyStore
	Deployer Deployer // nil: DeployPolicy answers FailedPrecondition
	Rollouts RolloutStore
	Kicker   Kicker
	// Commands and CommandKicker enable ForceShadow and diagnostics.
	Commands      CommandStore
	CommandKicker Kicker
	// KillSwitch enables the emergency rule kill switch (with Commands).
	KillSwitch RuleStore
	// CanaryTrips: clearForceShadow on a group also ends the canary
	// fallback's hold of the policy there (W12-G2-01).
	CanaryTrips TripClearer
	Now         func() time.Time
}

// BuildInfo is reported by VersionService.
type BuildInfo struct {
	Version string
	Commit  string
}

// Server is the admin gRPC server and its REST gateway.
type Server struct {
	GRPC    *grpc.Server
	Gateway http.Handler

	lis  *bufconn.Listener
	conn *grpc.ClientConn
}

// New builds the admin API. opts are extra gRPC server options (TLS).
func New(ctx context.Context, a auth.Authenticator, info BuildInfo, deps Deps, opts ...grpc.ServerOption) (*Server, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	opts = append(opts,
		grpc.ChainUnaryInterceptor(auth.UnaryInterceptor(a, Permissions)),
		grpc.ChainStreamInterceptor(auth.StreamInterceptor(a, Permissions)),
	)
	gs := grpc.NewServer(opts...)
	adminv1.RegisterVersionServiceServer(gs, &versionServer{info: info})
	if deps.Fleet != nil && deps.Presence != nil {
		adminv1.RegisterFleetAdminServiceServer(gs, &fleetAdmin{store: deps.Fleet, presence: deps.Presence,
			commands: deps.Commands, kick: deps.CommandKicker, rules: deps.KillSwitch, trips: deps.CanaryTrips, now: deps.Now})
	}
	if deps.Policies != nil {
		adminv1.RegisterPolicyServiceServer(gs, &policyAdmin{store: deps.Policies, deploy: deps.Deployer})
	}
	if deps.Rollouts != nil {
		adminv1.RegisterRolloutServiceServer(gs, &rolloutAdmin{store: deps.Rollouts, kick: deps.Kicker})
	}

	lis := bufconn.Listen(1 << 20)
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///admin",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		gs.Stop()
		return nil, fmt.Errorf("admin: in-process connection: %w", err)
	}

	// snake_case field names like the rest of the REST API, and zero values
	// written out.
	mux := runtime.NewServeMux(runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
		MarshalOptions:   protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true},
		UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
	}))
	for _, register := range []func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error{
		adminv1.RegisterVersionServiceHandler,
		adminv1.RegisterFleetAdminServiceHandler,
		adminv1.RegisterPolicyServiceHandler,
		adminv1.RegisterRolloutServiceHandler,
	} {
		if err := register(ctx, mux, conn); err != nil {
			_ = conn.Close()
			gs.Stop()
			return nil, fmt.Errorf("admin: gateway: %w", err)
		}
	}
	return &Server{GRPC: gs, Gateway: mux, lis: lis, conn: conn}, nil
}

// Close stops the gRPC server, on every listener, and the gateway's
// connection.
func (s *Server) Close() {
	_ = s.conn.Close()
	s.GRPC.Stop()
}

type versionServer struct {
	adminv1.UnimplementedVersionServiceServer
	info BuildInfo
}

func (v *versionServer) GetVersion(context.Context, *adminv1.GetVersionRequest) (*adminv1.GetVersionResponse, error) {
	return &adminv1.GetVersionResponse{Version: v.info.Version, Commit: v.info.Commit, ApiVersion: "v1"}, nil
}
