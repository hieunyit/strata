package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Config selects the OIDC provider whose access tokens are accepted.
type Config struct {
	// Issuer is the provider URL, e.g. https://sso.example.test/realms/strata.
	// Tokens must carry it as iss.
	Issuer string
	// DiscoveryURL, when set, is where the control plane reads the
	// provider's metadata instead of Issuer: in a container network the
	// provider is reached under another name than the one in its tokens.
	DiscoveryURL string
	// Audience must appear in the token's aud claim.
	Audience string
	// RolesClaim is a dotted path to a list of role names; Keycloak puts
	// realm roles at realm_access.roles (the default).
	RolesClaim string
}

// ErrUnauthenticated means no valid token was presented.
var ErrUnauthenticated = errors.New("unauthenticated")

// Verifier checks bearer tokens.
type Verifier struct {
	v          *oidc.IDTokenVerifier
	rolesClaim []string
}

// NewVerifier discovers the provider, retrying until ctx ends (the
// provider may start after the control plane), and returns a verifier that
// caches its signing keys.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("auth: OIDC issuer and audience are required")
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "realm_access.roles"
	}
	discovery := cfg.Issuer
	dctx := ctx
	if cfg.DiscoveryURL != "" {
		discovery = cfg.DiscoveryURL
		dctx = oidc.InsecureIssuerURLContext(ctx, cfg.Issuer)
	}
	var (
		provider *oidc.Provider
		err      error
	)
	for delay := 500 * time.Millisecond; ; delay = min(2*delay, 10*time.Second) {
		provider, err = oidc.NewProvider(dctx, discovery)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("auth: OIDC discovery at %s: %w", discovery, err)
		case <-time.After(delay):
		}
	}
	return &Verifier{
		// Access tokens, not ID tokens: the client id check is replaced by
		// the audience check, which go-oidc does with ClientID.
		v: provider.Verifier(&oidc.Config{
			ClientID:             cfg.Audience,
			SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256, oidc.PS256},
		}),
		rolesClaim: strings.Split(cfg.RolesClaim, "."),
	}, nil
}

// Authenticate verifies a raw token (signature, issuer, audience, expiry)
// and returns its caller.
func (v *Verifier) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	if raw == "" {
		return nil, ErrUnauthenticated
	}
	tok, err := v.v.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrUnauthenticated, err)
	}
	name, _ := claims["preferred_username"].(string)
	return &Principal{
		Subject: tok.Subject,
		Name:    name,
		Roles:   ParseRoles(stringsAt(claims, v.rolesClaim)),
	}, nil
}

// stringsAt returns the strings of the list at path, or nil.
func stringsAt(claims map[string]any, path []string) []string {
	var cur any = claims
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	list, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// BearerToken returns the token of an "Authorization: Bearer <token>"
// value, or "".
func BearerToken(header string) string {
	scheme, tok, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}
