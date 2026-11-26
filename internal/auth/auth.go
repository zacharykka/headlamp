package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
)

const (
	AuthSourceTSNet   = "tsnet"
	AuthSourceAPIKey  = "api_key"
	AuthSourceDevMock = "dev_mock"

	RoleUser  = "user"
	RoleAdmin = "admin"
)

var (
	// ErrUnauthenticated indicates that no authenticator could establish a caller identity.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	// ErrInvalidToken indicates that a credential was supplied but did not match any known token.
	ErrInvalidToken = errors.New("auth: invalid api token")
)

// Principal represents the authenticated caller of a Headlamp request.
type Principal struct {
	Subject     string            `json:"subject"`
	DisplayName string            `json:"display_name"`
	NodeName    string            `json:"node_name"`
	NodeIP      string            `json:"node_ip"`
	Tags        []string          `json:"tags"`
	Groups      []string          `json:"groups"`
	Roles       []string          `json:"roles"`
	RawCaps     map[string][]byte `json:"-"`
	AuthSource  string            `json:"auth_source"`
}

// HasRole reports whether the principal has the given role.
func (p *Principal) HasRole(role string) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.Roles, role)
}

// IsAdmin reports whether the principal holds the admin role.
func (p *Principal) IsAdmin() bool {
	return p.HasRole(RoleAdmin)
}

// HasGroup reports whether the principal belongs to the given group.
func (p *Principal) HasGroup(group string) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.Groups, group)
}

// HasTag reports whether the principal carries the given Tailnet node tag.
func (p *Principal) HasTag(tag string) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.Tags, tag)
}

// Clone returns a deep copy of Principal so per-request enrichers cannot mutate shared instances.
func (p *Principal) Clone() *Principal {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Tags = slices.Clone(p.Tags)
	cp.Groups = slices.Clone(p.Groups)
	cp.Roles = slices.Clone(p.Roles)
	if p.RawCaps != nil {
		cp.RawCaps = make(map[string][]byte, len(p.RawCaps))
		for k, v := range p.RawCaps {
			cp.RawCaps[k] = slices.Clone(v)
		}
	}
	return &cp
}

type principalContextKey struct{}

// WithPrincipal attaches p to ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// FromContext retrieves the Principal previously attached by WithPrincipal.
func FromContext(ctx context.Context) (*Principal, bool) {
	if ctx == nil {
		return nil, false
	}
	p, ok := ctx.Value(principalContextKey{}).(*Principal)
	return p, ok && p != nil
}

// Authenticator identifies the caller of an incoming HTTP request.
// Returning (nil, nil) means this authenticator does not apply, allowing
// a ChainAuthenticator to continue to the next authenticator.
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// ChainAuthenticator tries multiple Authenticators in order.
type ChainAuthenticator struct {
	authenticators []Authenticator
}

// NewChainAuthenticator constructs a ChainAuthenticator skipping any nil entries.
func NewChainAuthenticator(authenticators ...Authenticator) *ChainAuthenticator {
	list := make([]Authenticator, 0, len(authenticators))
	for _, a := range authenticators {
		if a != nil {
			list = append(list, a)
		}
	}
	return &ChainAuthenticator{authenticators: list}
}

// Authenticate returns the first non-nil Principal or first error from the chain.
func (c *ChainAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	for _, a := range c.authenticators {
		p, err := a.Authenticate(r)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
	return nil, ErrUnauthenticated
}

// DevAuthenticator synthesizes a local Principal for development and testing.
// Optional request headers X-Headlamp-Dev-User, X-Headlamp-Dev-Roles, and
// X-Headlamp-Dev-Tags override the defaults per request.
type DevAuthenticator struct {
	defaultSubject     string
	defaultDisplayName string
	defaultRoles       []string
	defaultGroups      []string
	defaultTags        []string
}

// NewDevAuthenticator creates a dev_mock Authenticator.
func NewDevAuthenticator(subject string, roles []string) *DevAuthenticator {
	if strings.TrimSpace(subject) == "" {
		subject = "dev@local"
	}
	if len(roles) == 0 {
		roles = []string{RoleAdmin, RoleUser}
	}
	return &DevAuthenticator{
		defaultSubject:     subject,
		defaultDisplayName: subject,
		defaultRoles:       slices.Clone(roles),
	}
}

// Authenticate always returns a mock Principal tagged with AuthSourceDevMock.
func (d *DevAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	subject := d.defaultSubject
	displayName := d.defaultDisplayName
	roles := slices.Clone(d.defaultRoles)
	tags := slices.Clone(d.defaultTags)

	if r != nil {
		if v := strings.TrimSpace(r.Header.Get("X-Headlamp-Dev-User")); v != "" {
			subject = v
			displayName = v
		}
		if v := strings.TrimSpace(r.Header.Get("X-Headlamp-Dev-Roles")); v != "" {
			roles = splitHeaderCSV(v)
		}
		if v := strings.TrimSpace(r.Header.Get("X-Headlamp-Dev-Tags")); v != "" {
			tags = splitHeaderCSV(v)
		}
	}

	return &Principal{
		Subject:     subject,
		DisplayName: displayName,
		NodeName:    "localhost",
		NodeIP:      remoteHost(r),
		Tags:        tags,
		Groups:      slices.Clone(d.defaultGroups),
		Roles:       roles,
		AuthSource:  AuthSourceDevMock,
	}, nil
}

// StaticToken binds a pre-shared API token to a Principal identity.
type StaticToken struct {
	Name        string
	Token       string
	Subject     string
	DisplayName string
	Groups      []string
	Roles       []string
	Tags        []string
}

// TokenAuthenticator authenticates requests using fallback static API tokens.
// Tokens are read from Authorization: Bearer, x-api-key, or x-goog-api-key headers.
type TokenAuthenticator struct {
	tokens        []StaticToken
	ignoreUnknown bool
}

// NewTokenAuthenticator creates a static token Authenticator.
// When ignoreUnknown is false (recommended in production), an unrecognized token
// returns ErrInvalidToken; when true, unrecognized tokens return (nil, nil) so a
// downstream authenticator (such as DevAuthenticator) can handle placeholder keys.
func NewTokenAuthenticator(tokens []StaticToken, ignoreUnknown bool) *TokenAuthenticator {
	copied := make([]StaticToken, 0, len(tokens))
	for _, t := range tokens {
		if t.Token == "" {
			continue
		}
		cp := t
		cp.Groups = slices.Clone(t.Groups)
		cp.Roles = slices.Clone(t.Roles)
		cp.Tags = slices.Clone(t.Tags)
		copied = append(copied, cp)
	}
	return &TokenAuthenticator{
		tokens:        copied,
		ignoreUnknown: ignoreUnknown,
	}
}

// Authenticate validates a bearer or vendor API key header using constant-time comparison.
func (t *TokenAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	if len(t.tokens) == 0 || r == nil {
		return nil, nil
	}

	candidate := extractRequestToken(r)
	if candidate == "" {
		return nil, nil
	}

	candidateBytes := []byte(candidate)
	matchedIdx := -1
	for i, tok := range t.tokens {
		if subtle.ConstantTimeCompare(candidateBytes, []byte(tok.Token)) == 1 {
			matchedIdx = i
		}
	}
	if matchedIdx < 0 {
		if t.ignoreUnknown {
			return nil, nil
		}
		return nil, ErrInvalidToken
	}

	tok := t.tokens[matchedIdx]
	displayName := tok.DisplayName
	if displayName == "" {
		displayName = tok.Name
	}
	if displayName == "" {
		displayName = tok.Subject
	}
	roles := slices.Clone(tok.Roles)
	if len(roles) == 0 {
		roles = []string{RoleUser}
	}

	return &Principal{
		Subject:     tok.Subject,
		DisplayName: displayName,
		NodeName:    tok.Name,
		NodeIP:      remoteHost(r),
		Tags:        slices.Clone(tok.Tags),
		Groups:      slices.Clone(tok.Groups),
		Roles:       roles,
		AuthSource:  AuthSourceAPIKey,
	}, nil
}

// Middleware authenticates each request and attaches the Principal to r.Context().
// If onError is nil, a standard 401 JSON error response is written.
func Middleware(authenticator Authenticator, onError func(http.ResponseWriter, *http.Request, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := authenticator.Authenticate(r)
			if err != nil {
				if onError != nil {
					onError(w, r, err)
					return
				}
				writeUnauthorized(w, err)
				return
			}
			if p == nil {
				if onError != nil {
					onError(w, r, ErrUnauthenticated)
					return
				}
				writeUnauthorized(w, ErrUnauthenticated)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"type":    "authentication_error",
			"message": err.Error(),
		},
	})
}

func extractRequestToken(r *http.Request) string {
	if authz := strings.TrimSpace(r.Header.Get("Authorization")); authz != "" {
		if len(authz) > 7 && strings.EqualFold(authz[:7], "Bearer ") {
			return strings.TrimSpace(authz[7:])
		}
	}
	if key := strings.TrimSpace(r.Header.Get("x-api-key")); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("x-goog-api-key")); key != "" {
		return key
	}
	return ""
}

func remoteHost(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func splitHeaderCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
