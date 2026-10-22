// Package config reads the control plane's YAML configuration file
// (CP-A02, docs/plan/compact-ops-plan.md). Every setting maps to one of
// the command line flags, which stay the single place where values are
// parsed and checked: a key in the file sets its flag unless that flag was
// given on the command line. Secrets are never written in the file: a
// *_file key names a file whose content becomes the environment variable
// the control plane already reads, unless that variable is set.
//
// Precedence: command line flag > environment variable (secrets) > file >
// default.
package config

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/strata/strata/control-plane/apidiscovery"
	"gopkg.in/yaml.v3"
)

// Duration is a YAML duration that must carry a unit ("30s", "8h"); a bare
// number is refused, since time.Duration would read it as nanoseconds.
type Duration struct{ time.Duration }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return fmt.Errorf("line %d: a duration needs a unit, as in \"30s\" or \"8h\"", n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %v", n.Line, err)
	}
	d.Duration = v
	return nil
}

// File is the configuration file. Pointer fields are unset when nil.
type File struct {
	Version int `yaml:"version"`

	Server struct {
		HTTP struct {
			Listen         *string  `yaml:"listen" flag:"addr"`
			CORSOrigins    []string `yaml:"cors_origins" flag:"cors-origins"`
			TrustedProxies []string `yaml:"trusted_proxies" flag:"trusted-proxies"`
			UI             *bool    `yaml:"ui" flag:"ui"`
		} `yaml:"http"`
		Fleet struct {
			Listen      *string `yaml:"listen" flag:"grpc-addr"`
			TLSCA       *string `yaml:"tls_ca" flag:"tls-ca"`
			TLSCert     *string `yaml:"tls_cert" flag:"tls-cert"`
			TLSKey      *string `yaml:"tls_key" flag:"tls-key"`
			NodeCACert  *string `yaml:"node_ca_cert" flag:"node-ca-cert"`
			NodeCAKey   *string `yaml:"node_ca_key" flag:"node-ca-key"`
			TrustBundle *string `yaml:"trust_bundle" flag:"fleet-trust-bundle"`
		} `yaml:"fleet"`
		Admin struct {
			GRPCListen    *string `yaml:"grpc_listen" flag:"admin-grpc-addr"`
			TLSCert       *string `yaml:"tls_cert" flag:"admin-tls-cert"`
			TLSKey        *string `yaml:"tls_key" flag:"admin-tls-key"`
			GRPCPlaintext *bool   `yaml:"grpc_plaintext" flag:"admin-grpc-plaintext"`
		} `yaml:"admin"`
		Metrics struct {
			Listen *string `yaml:"listen" flag:"metrics-addr"`
		} `yaml:"metrics"`
		SingleControlPlane *bool     `yaml:"single_control_plane" flag:"single-control-plane"`
		LeaseTTL           *Duration `yaml:"lease_ttl" flag:"lease-ttl"`
	} `yaml:"server"`

	Database struct {
		DSNFile *string `yaml:"dsn_file" env:"STRATA_POSTGRES_DSN"`
	} `yaml:"database"`

	Auth struct {
		Local struct {
			MFAKeyFile        *string   `yaml:"mfa_key_file" flag:"local-mfa-key-file"`
			Enabled           *bool     `yaml:"enabled" flag:"local-auth"`
			SessionTTL        *Duration `yaml:"session_ttl" flag:"local-session-ttl"`
			AdminUser         *string   `yaml:"admin_user" flag:"local-admin-user"`
			AdminPasswordFile *string   `yaml:"admin_password_file" env:"STRATA_LOCAL_ADMIN_PASSWORD"`
		} `yaml:"local"`
		OIDC struct {
			Issuer       *string `yaml:"issuer" flag:"oidc-issuer"`
			DiscoveryURL *string `yaml:"discovery_url" flag:"oidc-discovery-url"`
			Audience     *string `yaml:"audience" flag:"oidc-audience"`
			RolesClaim   *string `yaml:"roles_claim" flag:"oidc-roles-claim"`
			UIClientID   *string `yaml:"ui_client_id" flag:"ui-oidc-client-id"`
		} `yaml:"oidc"`
	} `yaml:"auth"`

	Events struct {
		InMemory            *bool `yaml:"in_memory" flag:"in-memory"`
		Seed                *bool `yaml:"seed" flag:"seed"`
		RetentionDays       *int  `yaml:"retention_days" flag:"events-ttl-days"`
		GeoAggregatesMonths *int  `yaml:"geo_aggregates_months" flag:"geo-aggregates-months"`
		ClickHouse          struct {
			Address      *string `yaml:"address" flag:"clickhouse-addr"`
			Username     *string `yaml:"username" flag:"clickhouse-user"`
			PasswordFile *string `yaml:"password_file" env:"STRATA_CLICKHOUSE_PASSWORD"`
		} `yaml:"clickhouse"`
	} `yaml:"events"`

	Bundles struct {
		Compiler        *string  `yaml:"compiler" flag:"compiler"`
		Rules           []string `yaml:"rules" flag:"rules"`
		BlockPage       *string  `yaml:"block_page" flag:"block-page"`
		SupportContact  *string  `yaml:"support_contact" flag:"support-contact"`
		CostBudget      *uint64  `yaml:"cost_budget" flag:"cost-budget"`
		IdentityKeyFile *string  `yaml:"identity_key_file" env:"STRATA_IDENTITY_HMAC_KEY"`
		Storage         struct {
			// Local: a directory in place of an object store (CP-A07)
			Local struct {
				Path          *string   `yaml:"path" flag:"objects-dir"`
				KeepBundles   *int      `yaml:"keep_bundles" flag:"objects-keep-bundles"`
				SampleDays    *int      `yaml:"sample_days" flag:"objects-sample-days"`
				PruneInterval *Duration `yaml:"prune_interval" flag:"objects-prune-interval"`
			} `yaml:"local"`
			S3 struct {
				Endpoint      *string `yaml:"endpoint" flag:"s3-endpoint"`
				Bucket        *string `yaml:"bucket" flag:"s3-bucket"`
				Secure        *bool   `yaml:"secure" flag:"s3-secure"`
				AccessKeyFile *string `yaml:"access_key_file" env:"STRATA_S3_ACCESS_KEY"`
				SecretKeyFile *string `yaml:"secret_key_file" env:"STRATA_S3_SECRET_KEY"`
			} `yaml:"s3"`
		} `yaml:"storage"`
		Signer struct {
			Type      *string `yaml:"type" flag:"bundle-signer"`
			KeyFile   *string `yaml:"key_file" flag:"bundle-signing-key"`
			PublicKey *string `yaml:"public_key" flag:"bundle-pubkey"`
			Vault     struct {
				Address      *string `yaml:"address" flag:"vault-addr"`
				TransitMount *string `yaml:"transit_mount" flag:"vault-transit-mount"`
				TransitKey   *string `yaml:"transit_key" flag:"vault-transit-key"`
				KeyVersion   *int    `yaml:"key_version" flag:"vault-transit-key-version"`
				TokenFile    *string `yaml:"token_file" flag:"vault-token-file"`
			} `yaml:"vault"`
		} `yaml:"signer"`
	} `yaml:"bundles"`

	Replay struct {
		Binary           *string   `yaml:"binary" flag:"replay"`
		Corpus           *string   `yaml:"corpus" flag:"replay-corpus"`
		Threads          *int      `yaml:"threads" flag:"replay-threads"`
		Timeout          *Duration `yaml:"timeout" flag:"replay-timeout"`
		SamplingApproved *bool     `yaml:"sampling_approved" flag:"replay-sampling-approved"`
	} `yaml:"replay"`

	Canary struct {
		MinRequests   *uint64   `yaml:"min_requests" flag:"canary-min-requests"`
		BlockFactor   *float64  `yaml:"block_factor" flag:"canary-block-factor"`
		BlockFloor    *float64  `yaml:"block_floor" flag:"canary-block-floor"`
		ErrorFactor   *float64  `yaml:"error_factor" flag:"canary-error-factor"`
		ErrorDelta    *float64  `yaml:"error_delta" flag:"canary-error-delta"`
		LatencyFactor *float64  `yaml:"latency_factor" flag:"canary-latency-factor"`
		LatencyDelta  *Duration `yaml:"latency_delta" flag:"canary-latency-delta"`
		HealthShadow  *bool     `yaml:"health_shadow" flag:"canary-health-shadow"`
	} `yaml:"canary"`
	Rollouts struct {
		Waves []string  `yaml:"waves" flag:"rollout-waves"`
		Soak  *Duration `yaml:"soak" flag:"rollout-soak"`
	} `yaml:"rollouts"`

	GeoIP struct {
		City           *string   `yaml:"city" flag:"geoip-city"`
		ASN            *string   `yaml:"asn" flag:"geoip-asn"`
		UpdateInterval *Duration `yaml:"update_interval" flag:"geoip-update-interval"`
	} `yaml:"geoip"`

	GoodBots struct {
		Interval *Duration `yaml:"interval" flag:"good-bots-interval"`
	} `yaml:"good_bots"`
	Discovery struct {
		Enabled           *bool    `yaml:"enabled" flag:"discovery-enabled"`
		ApprovalReference *string  `yaml:"approval_reference" flag:"discovery-approval-reference"`
		ApprovalExpires   *string  `yaml:"approval_expires_at" flag:"discovery-approval-expires"`
		TrustedCollectors []string `yaml:"trusted_collectors" flag:"discovery-trusted-collectors"`
		KeyFile           *string  `yaml:"identity_key_file" flag:"discovery-identity-key-file"`
	} `yaml:"discovery"`
	Notifications struct {
		WebhookURL  *string `yaml:"webhook_url" flag:"notification-webhook"`
		KeyFile     *string `yaml:"key_file" flag:"notification-webhook-key-file"`
		AllowCIDRs  *string `yaml:"allow_cidrs" flag:"notification-webhook-allow-cidrs"`
		AuditExport *bool   `yaml:"audit_export" flag:"audit-export-enabled"`
	} `yaml:"notifications"`
}

// Load reads and decodes a configuration file; unknown keys, a missing or
// unknown version and bare-number durations are errors.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("config: %s: version must be 1 (got %d)", path, f.Version)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := f.resolvePaths(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	return &f, f.check()
}

// Source of an effective value.
type Source string

const (
	FromDefault Source = "default"
	FromFile    Source = "file"
	FromFlag    Source = "flag"
	FromEnv     Source = "env"
)

type leaf struct {
	key  string // dotted YAML key
	flag string
	env  string
	v    reflect.Value
}

func walk(v reflect.Value, prefix string, out *[]leaf) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		name := strings.Split(sf.Tag.Get("yaml"), ",")[0]
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		fv := v.Field(i)
		if sf.Type.Kind() == reflect.Struct && sf.Type != reflect.TypeOf(Duration{}) {
			walk(fv, key, out)
			continue
		}
		if f, e := sf.Tag.Get("flag"), sf.Tag.Get("env"); f != "" || e != "" {
			*out = append(*out, leaf{key: key, flag: f, env: e, v: fv})
		}
	}
}

func (f *File) leaves() []leaf {
	var out []leaf
	walk(reflect.ValueOf(f).Elem(), "", &out)
	return out
}

// Keys maps each YAML key to its flag ("" for secret files) and environment
// variable ("" for flags): the documented table, and what tests check
// against the flags of the control plane.
func Keys() map[string][2]string {
	out := map[string][2]string{}
	for _, l := range (&File{}).leaves() {
		out[l.key] = [2]string{l.flag, l.env}
	}
	return out
}

func text(v reflect.Value) (string, bool) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return "", false
		}
		e := v.Elem()
		if d, ok := e.Interface().(Duration); ok {
			return d.String(), true
		}
		return fmt.Sprint(e.Interface()), true
	case reflect.Slice:
		if v.IsNil() {
			return "", false
		}
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = fmt.Sprint(v.Index(i).Interface())
		}
		return strings.Join(parts, ","), true
	}
	return "", false
}

// Apply sets the flags of fs from the file, except those in explicit (given
// on the command line), and loads the secret files into the environment
// unless their variable is set. It returns where each flag's value and each
// secret came from.
func (f *File) Apply(fs *flag.FlagSet, explicit map[string]bool) (map[string]Source, error) {
	src := map[string]Source{}
	fs.VisitAll(func(fl *flag.Flag) { src[fl.Name] = FromDefault })
	for name := range explicit {
		src[name] = FromFlag
	}
	for _, l := range f.leaves() {
		val, set := text(l.v)
		switch {
		case l.flag != "":
			if fs.Lookup(l.flag) == nil {
				return nil, fmt.Errorf("config: %s maps to unknown flag -%s", l.key, l.flag)
			}
			if !set || explicit[l.flag] {
				continue
			}
			if err := fs.Set(l.flag, val); err != nil {
				return nil, fmt.Errorf("config: %s: %w", l.key, err)
			}
			src[l.flag] = FromFile
		case l.env != "":
			if os.Getenv(l.env) != "" {
				src["$"+l.env] = FromEnv
				continue
			}
			if !set {
				continue
			}
			secret, err := readSecret(val)
			if err != nil {
				return nil, fmt.Errorf("config: %s: %w", l.key, err)
			}
			if err := os.Setenv(l.env, secret); err != nil {
				return nil, err
			}
			src["$"+l.env] = FromFile
		}
	}
	return src, nil
}

// readSecret reads a secret file: not a symlink, not readable by group or
// others, at most 64 KiB; one trailing newline is dropped.
func readSecret(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) {
		return "", fmt.Errorf("secret file %s: a symlink, refused", path)
	}
	if err != nil {
		return "", fmt.Errorf("secret file %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret file %s: not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret file %s: readable by group or others (mode %o); chmod 600", path, info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil {
		return "", err
	}
	if len(data) > 64<<10 {
		return "", fmt.Errorf("secret file %s: larger than 64 KiB", path)
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if s == "" {
		return "", fmt.Errorf("secret file %s: empty", path)
	}
	return s, nil
}

// ReadSecretFile applies the same bounded private-file checks to runtime keys.
func ReadSecretFile(path string) (string, error) { return readSecret(path) }

// resolvePaths makes the relative file paths of the file relative to the
// directory of the file, not to the working directory.
func (f *File) resolvePaths(base string) error {
	pathKeys := map[string]bool{}
	for _, k := range []string{
		"server.fleet.tls_ca", "server.fleet.tls_cert", "server.fleet.tls_key", "server.fleet.node_ca_cert",
		"server.fleet.node_ca_key", "server.fleet.trust_bundle", "server.admin.tls_cert", "server.admin.tls_key",
		"database.dsn_file", "auth.local.admin_password_file", "auth.local.mfa_key_file", "events.clickhouse.password_file",
		"bundles.rules", "bundles.block_page", "bundles.identity_key_file", "bundles.storage.local.path", "bundles.storage.s3.access_key_file",
		"bundles.storage.s3.secret_key_file", "bundles.signer.key_file", "bundles.signer.public_key",
		"bundles.signer.vault.token_file", "replay.corpus", "geoip.city", "geoip.asn", "notifications.key_file", "discovery.identity_key_file",
	} {
		pathKeys[k] = true
	}
	for _, l := range f.leaves() {
		if !pathKeys[l.key] {
			continue
		}
		switch l.v.Kind() {
		case reflect.Pointer:
			if !l.v.IsNil() {
				p := l.v.Elem().String()
				if p != "" && !filepath.IsAbs(p) {
					l.v.Elem().SetString(filepath.Join(base, p))
				}
			}
		case reflect.Slice:
			for i := 0; i < l.v.Len(); i++ {
				p := l.v.Index(i).String()
				if p != "" && !filepath.IsAbs(p) {
					l.v.Index(i).SetString(filepath.Join(base, p))
				}
			}
		}
	}
	return nil
}

// check refuses combinations the flags cannot express on their own.
func (f *File) check() error {
	if f.Discovery.Enabled != nil && *f.Discovery.Enabled {
		value := func(p *string) string {
			if p != nil {
				return *p
			}
			return ""
		}
		if _, err := apidiscovery.Settings(true, value(f.Discovery.ApprovalReference), value(f.Discovery.ApprovalExpires), strings.Join(f.Discovery.TrustedCollectors, ","), time.Now()); err != nil {
			return errors.New("config: discovery requires a current legal approval and trusted machine collectors")
		}
		if value(f.Discovery.KeyFile) == "" {
			return errors.New("config: discovery.identity_key_file required")
		}
	}

	if value := f.Notifications.WebhookURL; value != nil && *value != "" {
		u, err := url.Parse(*value)
		if err != nil || len(*value) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("config: notifications.webhook_url must be HTTPS without credentials, query or fragment")
		}
	}
	for _, v := range []*float64{f.Canary.BlockFactor, f.Canary.ErrorFactor, f.Canary.LatencyFactor} {
		if v != nil && (math.IsNaN(*v) || math.IsInf(*v, 0) || *v <= 1 || *v > 100) {
			return errors.New("config: invalid canary factor")
		}
	}
	for _, v := range []*float64{f.Canary.BlockFloor, f.Canary.ErrorDelta} {
		if v != nil && (math.IsNaN(*v) || math.IsInf(*v, 0) || *v < .0001 || *v > 1) {
			return errors.New("config: invalid canary rate floor")
		}
	}
	if v := f.Canary.MinRequests; v != nil && (*v < 10 || *v > 1000000) {
		return errors.New("config: canary.min_requests out of range")
	}
	if v := f.Canary.LatencyDelta; v != nil && (v.Duration < time.Millisecond || v.Duration > 30*time.Second) {
		return errors.New("config: canary.latency_delta out of range")
	}

	if t := f.Bundles.Signer.Type; t != nil && *t != "file" && *t != "vault" {
		return fmt.Errorf("config: bundles.signer.type must be file or vault, got %q", *t)
	}
	if t := f.Bundles.Signer.Type; t != nil && *t == "vault" && f.Bundles.Signer.KeyFile != nil {
		return errors.New("config: bundles.signer.key_file is for type file, not vault")
	}
	if f.Events.InMemory != nil && *f.Events.InMemory && f.Events.ClickHouse.Address != nil {
		return errors.New("config: events.in_memory and events.clickhouse.address exclude each other")
	}
	if f.Bundles.Storage.Local.Path != nil && f.Bundles.Storage.S3.Endpoint != nil {
		return errors.New("config: bundles.storage.local and bundles.storage.s3 exclude each other")
	}
	return nil
}

// Effective lists every flag with its value and source, and the secrets
// with their source only: one "key = value  # source" line each, sorted.
// Nothing secret is printed: secrets live only in environment variables.
func Effective(fs *flag.FlagSet, src map[string]Source) string {
	var lines []string
	fs.VisitAll(func(fl *flag.Flag) {
		s := src[fl.Name]
		if s == "" {
			s = FromDefault
		}
		lines = append(lines, fmt.Sprintf("-%s = %q  # %s", fl.Name, fl.Value.String(), s))
	})
	var envs []string
	for k := range Keys() {
		if e := Keys()[k][1]; e != "" {
			envs = append(envs, e)
		}
	}
	sort.Strings(envs)
	for _, e := range envs {
		state := "unset"
		if os.Getenv(e) != "" {
			state = "<redacted>  # " + string(src["$"+e])
			if src["$"+e] == "" {
				state = "<redacted>  # env"
			}
		}
		lines = append(lines, fmt.Sprintf("$%s = %s", e, state))
	}
	return strings.Join(lines, "\n") + "\n"
}
