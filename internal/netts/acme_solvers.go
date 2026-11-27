package netts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// DNS01Solver presents and cleans up DNS-01 TXT challenge records for ACME validation.
type DNS01Solver interface {
	Present(ctx context.Context, fqdn, txtValue string) error
	CleanUp(ctx context.Context, fqdn, txtValue string) error
}

// CloudflareOption customizes CloudflareDNSSolver.
type CloudflareOption func(*CloudflareDNSSolver)

// WithCloudflareAPIBase overrides the Cloudflare v4 API base URL (primarily for testing).
func WithCloudflareAPIBase(baseURL string) CloudflareOption {
	return func(s *CloudflareDNSSolver) {
		if trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/"); trimmed != "" {
			s.apiBase = trimmed
		}
	}
}

// WithCloudflareHTTPClient sets the HTTP client used by CloudflareDNSSolver.
func WithCloudflareHTTPClient(client *http.Client) CloudflareOption {
	return func(s *CloudflareDNSSolver) {
		if client != nil {
			s.httpClient = client
		}
	}
}

type cloudflareRecordRef struct {
	zoneID   string
	recordID string
}

// CloudflareDNSSolver solves ACME DNS-01 challenges via the Cloudflare DNS v4 API.
type CloudflareDNSSolver struct {
	apiToken   string
	apiBase    string
	httpClient *http.Client

	mu      sync.Mutex
	records map[string]cloudflareRecordRef
}

var _ DNS01Solver = (*CloudflareDNSSolver)(nil)

// NewCloudflareDNSSolver constructs a Cloudflare v4 DNS-01 solver.
func NewCloudflareDNSSolver(apiToken string, opts ...CloudflareOption) (*CloudflareDNSSolver, error) {
	token := strings.TrimSpace(apiToken)
	if token == "" {
		return nil, errors.New("netts: cloudflare dns_api_token is required")
	}
	s := &CloudflareDNSSolver{
		apiToken:   token,
		apiBase:    defaultCloudflareAPIBase,
		httpClient: &http.Client{Timeout: defaultDNSHTTPTimeout},
		records:    make(map[string]cloudflareRecordRef),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s, nil
}

// Present creates the _acme-challenge TXT record in the matching Cloudflare DNS zone.
func (s *CloudflareDNSSolver) Present(ctx context.Context, fqdn, txtValue string) error {
	name := normalizeDNSName(fqdn)
	if name == "" {
		return errors.New("netts: cloudflare present requires non-empty fqdn")
	}

	zoneID, err := s.findZoneID(ctx, name)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": txtValue,
		"ttl":     120,
	})
	if err != nil {
		return fmt.Errorf("netts: cloudflare marshal txt record: %w", err)
	}

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", s.apiBase, url.PathEscape(zoneID))
	var resp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := s.doJSON(ctx, http.MethodPost, endpoint, payload, &resp); err != nil {
		return fmt.Errorf("netts: cloudflare create txt %q: %w", name, err)
	}
	if !resp.Success || resp.Result.ID == "" {
		return fmt.Errorf("netts: cloudflare create txt %q failed: %v", name, resp.Errors)
	}

	s.mu.Lock()
	s.records[dnsRecordKey(name, txtValue)] = cloudflareRecordRef{
		zoneID:   zoneID,
		recordID: resp.Result.ID,
	}
	s.mu.Unlock()
	return nil
}

// CleanUp deletes the TXT record created by Present.
func (s *CloudflareDNSSolver) CleanUp(ctx context.Context, fqdn, txtValue string) error {
	name := normalizeDNSName(fqdn)
	key := dnsRecordKey(name, txtValue)

	s.mu.Lock()
	ref, ok := s.records[key]
	delete(s.records, key)
	s.mu.Unlock()

	if !ok {
		zoneID, err := s.findZoneID(ctx, name)
		if err != nil {
			return err
		}
		recordID, err := s.findTXTRecordID(ctx, zoneID, name, txtValue)
		if err != nil {
			return err
		}
		if recordID == "" {
			return nil
		}
		ref = cloudflareRecordRef{zoneID: zoneID, recordID: recordID}
	}

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", s.apiBase, url.PathEscape(ref.zoneID), url.PathEscape(ref.recordID))
	var resp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := s.doJSON(ctx, http.MethodDelete, endpoint, nil, &resp); err != nil {
		return fmt.Errorf("netts: cloudflare delete txt %q: %w", name, err)
	}
	if !resp.Success {
		return fmt.Errorf("netts: cloudflare delete txt %q failed: %v", name, resp.Errors)
	}
	return nil
}

func (s *CloudflareDNSSolver) findZoneID(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(normalizeDNSName(fqdn), ".")
	// Walk parent domains from most-specific to apex (e.g. a.b.example.com -> b.example.com -> example.com).
	start := 0
	if len(labels) > 2 && labels[0] == "_acme-challenge" {
		start = 1
	}
	for i := start; i <= len(labels)-2; i++ {
		candidate := strings.Join(labels[i:], ".")
		endpoint := fmt.Sprintf("%s/zones?name=%s", s.apiBase, url.QueryEscape(candidate))
		var resp struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
			return "", fmt.Errorf("netts: cloudflare lookup zone %q: %w", candidate, err)
		}
		if resp.Success && len(resp.Result) > 0 && resp.Result[0].ID != "" {
			return resp.Result[0].ID, nil
		}
	}
	return "", fmt.Errorf("netts: cloudflare zone not found for %q", fqdn)
}

func (s *CloudflareDNSSolver) findTXTRecordID(ctx context.Context, zoneID, name, txtValue string) (string, error) {
	// Filter by type and name only; Cloudflare v4 often wraps TXT content in double quotes,
	// so match the unquoted value client-side.
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?type=TXT&name=%s",
		s.apiBase, url.PathEscape(zoneID), url.QueryEscape(name))
	var resp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	if err := s.doJSON(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return "", fmt.Errorf("netts: cloudflare lookup txt record %q: %w", name, err)
	}
	if resp.Success {
		for _, rec := range resp.Result {
			if strings.Trim(strings.TrimSpace(rec.Content), "\"") == txtValue {
				return rec.ID, nil
			}
		}
	}
	return "", nil
}

func (s *CloudflareDNSSolver) doJSON(ctx context.Context, method, endpoint string, body []byte, out any) error {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// WebhookDNSSolver solves ACME DNS-01 challenges by POSTing present/cleanup JSON actions to a webhook URL.
type WebhookDNSSolver struct {
	webhookURL string
	apiToken   string
	httpClient *http.Client
}

var _ DNS01Solver = (*WebhookDNSSolver)(nil)

// NewWebhookDNSSolver constructs a generic webhook DNS-01 solver.
func NewWebhookDNSSolver(webhookURL, apiToken string, httpClient *http.Client) (*WebhookDNSSolver, error) {
	u := strings.TrimSpace(webhookURL)
	if u == "" {
		return nil, errors.New("netts: dns_webhook_url is required for webhook DNS-01 solver")
	}
	parsed, err := url.Parse(u)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("netts: invalid dns_webhook_url %q", webhookURL)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultDNSHTTPTimeout}
	}
	return &WebhookDNSSolver{
		webhookURL: u,
		apiToken:   strings.TrimSpace(apiToken),
		httpClient: httpClient,
	}, nil
}

// Present POSTs {"action":"present","fqdn":"...","value":"..."} to the configured webhook URL.
func (s *WebhookDNSSolver) Present(ctx context.Context, fqdn, txtValue string) error {
	return s.call(ctx, "present", normalizeDNSName(fqdn), txtValue)
}

// CleanUp POSTs {"action":"cleanup","fqdn":"...","value":"..."} to the configured webhook URL.
func (s *WebhookDNSSolver) CleanUp(ctx context.Context, fqdn, txtValue string) error {
	return s.call(ctx, "cleanup", normalizeDNSName(fqdn), txtValue)
}

func (s *WebhookDNSSolver) call(ctx context.Context, action, fqdn, value string) error {
	payload, err := json.Marshal(map[string]string{
		"action": action,
		"fqdn":   fqdn,
		"value":  value,
	})
	if err != nil {
		return fmt.Errorf("netts: webhook dns marshal %s: %w", action, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiToken)
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("netts: webhook dns %s %q: %w", action, fqdn, err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("netts: webhook dns %s %q returned http %d: %s", action, fqdn, res.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func normalizeDNSName(fqdn string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
}

func dnsRecordKey(name, txtValue string) string {
	return name + "\x00" + txtValue
}
