package auth

import (
	"context"
	"errors"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// MethodPermissions maps full gRPC method names
// (/strata.admin.v1.VersionService/GetVersion) to the permission they need.
// A method that is not listed is refused: new methods are denied until
// they are given a permission.
type MethodPermissions map[string]Permission

func (m MethodPermissions) authorize(ctx context.Context, a Authenticator, method string) (context.Context, error) {
	perm, ok := m[method]
	if !ok {
		return nil, status.Errorf(codes.PermissionDenied, "no permission is defined for %s", method)
	}
	var raw string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("authorization"); len(v) > 0 {
			raw = BearerToken(v[0])
		}
	}
	p, err := a.Authenticate(ctx, raw)
	if err != nil {
		if !errors.Is(err, ErrUnauthenticated) {
			log.Printf("[ERROR] auth: %v", err)
		}
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	if !p.Can(perm) {
		return nil, status.Errorf(codes.PermissionDenied, "permission denied: %s", perm)
	}
	return WithPrincipal(ctx, p), nil
}

// UnaryInterceptor authenticates and authorizes unary calls.
func UnaryInterceptor(a Authenticator, m MethodPermissions) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		ctx, err := m.authorize(ctx, a, info.FullMethod)
		if err != nil {
			return nil, err
		}
		p := FromContext(ctx)
		if !p.ScopedRPC(info.FullMethod, req, m[info.FullMethod]) {
			return nil, status.Error(codes.PermissionDenied, "resource outside assigned scope")
		}
		out, err := h(ctx, req)
		if err != nil {
			return nil, err
		}
		return p.FilterRPC(info.FullMethod, out), nil
	}
}

// StreamInterceptor authenticates and authorizes streaming calls.
func StreamInterceptor(a Authenticator, m MethodPermissions) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		ctx, err := m.authorize(ss.Context(), a, info.FullMethod)
		if err != nil {
			return err
		}
		if FromContext(ctx).Access != nil {
			return status.Error(codes.PermissionDenied, "stream outside assigned scope")
		}
		return h(srv, &principalStream{ServerStream: ss, ctx: ctx})
	}
}

type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }
