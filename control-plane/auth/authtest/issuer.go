// Package authtest is a fake OIDC provider for tests: it serves discovery
// and JWKS from httptest and signs access tokens with its own RSA key.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Audience is the audience tokens carry unless a test overrides it.
const Audience = "strata-api"

// Issuer is a running fake provider.
type Issuer struct {
	URL    string
	key    *rsa.PrivateKey
	signer jose.Signer
}

// New starts a provider, stopped when the test ends.
func New(t testing.TB) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	is := &Issuer{key: key, signer: signer}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	is.URL = srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                is.URL,
			"jwks_uri":                              is.URL + "/jwks",
			"authorization_endpoint":                is.URL + "/auth",
			"token_endpoint":                        is.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"},
		}})
	})
	return is
}

// Claims of a token; zero fields get defaults in Token.
type Claims struct {
	Issuer   string
	Audience string
	Subject  string
	Expiry   time.Time
	Roles    []string
}

// Token signs an access token. Roles go to realm_access.roles, as
// Keycloak puts them.
func (is *Issuer) Token(t testing.TB, c Claims) string {
	t.Helper()
	if c.Issuer == "" {
		c.Issuer = is.URL
	}
	if c.Audience == "" {
		c.Audience = Audience
	}
	if c.Subject == "" {
		c.Subject = "user-1"
	}
	if c.Expiry.IsZero() {
		c.Expiry = time.Now().Add(5 * time.Minute)
	}
	std := jwt.Claims{
		Issuer: c.Issuer, Subject: c.Subject, Audience: jwt.Audience{c.Audience},
		Expiry: jwt.NewNumericDate(c.Expiry), IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}
	extra := map[string]any{
		"preferred_username": c.Subject,
		"realm_access":       map[string]any{"roles": c.Roles},
	}
	raw, err := jwt.Signed(is.signer).Claims(std).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ForeignToken is signed by a key the provider does not publish.
func (is *Issuer) ForeignToken(t testing.TB, roles ...string) string {
	t.Helper()
	other := New(t)
	return other.Token(t, Claims{Issuer: is.URL, Roles: roles})
}
