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
	adminv1.VersionService_GetVersion_FullMethodName: auth.PermVersionRead,
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
func New(ctx context.Context, a auth.Authenticator, info BuildInfo, opts ...grpc.ServerOption) (*Server, error) {
	opts = append(opts,
		grpc.ChainUnaryInterceptor(auth.UnaryInterceptor(a, Permissions)),
		grpc.ChainStreamInterceptor(auth.StreamInterceptor(a, Permissions)),
	)
	gs := grpc.NewServer(opts...)
	adminv1.RegisterVersionServiceServer(gs, &versionServer{info: info})

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
	if err := adminv1.RegisterVersionServiceHandler(ctx, mux, conn); err != nil {
		_ = conn.Close()
		gs.Stop()
		return nil, fmt.Errorf("admin: gateway: %w", err)
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
