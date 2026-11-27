package mcp

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	clientSessionIDPrefix = "hl-mcp-"
	sseCallbackPathPrefix = "/_sse/"
	maxTrackedSessions    = 10000
)

var (
	errSessionNotFound  = errors.New("mcp: session not found or expired")
	errSessionForbidden = errors.New("mcp: session does not belong to caller")
)

type mcpSession struct {
	clientID        string
	subject         string
	serverName      string
	upstreamID      string
	sseCallbackPath string
	expiresAt       time.Time
}

// sessionStore binds opaque Headlamp-issued client session IDs ("hl-mcp-<uuid>")
// to a specific (subject, serverName) owner along with either an upstream Streamable HTTP
// Mcp-Session-Id or a legacy SSE callback path emitted by upstream's "event: endpoint".
type sessionStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	now      func() time.Time
	sessions map[string]*mcpSession
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	return &sessionStore{
		ttl:      ttl,
		now:      time.Now,
		sessions: make(map[string]*mcpSession),
	}
}

func (s *sessionStore) createSSECallback(subject, serverName, callbackPath string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.evictLocked(now)

	clientID := clientSessionIDPrefix + uuid.NewString()
	s.sessions[clientID] = &mcpSession{
		clientID:        clientID,
		subject:         subject,
		serverName:      serverName,
		sseCallbackPath: callbackPath,
		expiresAt:       now.Add(s.ttl),
	}
	return clientID
}

// lookup validates that clientID exists, is unexpired, and belongs to (subject, serverName),
// refreshing its sliding TTL on success.
func (s *sessionStore) lookup(clientID, subject, serverName string) (mcpSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entry, ok := s.sessions[clientID]
	if !ok {
		return mcpSession{}, errSessionNotFound
	}
	if !now.Before(entry.expiresAt) {
		delete(s.sessions, clientID)
		return mcpSession{}, errSessionNotFound
	}
	if entry.subject != subject || entry.serverName != serverName {
		return mcpSession{}, errSessionForbidden
	}
	entry.expiresAt = now.Add(s.ttl)
	return *entry, nil
}

// updateUpstreamID updates or binds upstreamID for an existing owned client session,
// or creates a new client session if clientID is empty or missing.
func (s *sessionStore) bindUpstreamID(existingClientID, subject, serverName, upstreamID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	if existingClientID != "" {
		if entry, ok := s.sessions[existingClientID]; ok && now.Before(entry.expiresAt) &&
			entry.subject == subject && entry.serverName == serverName {
			entry.upstreamID = upstreamID
			entry.expiresAt = now.Add(s.ttl)
			return entry.clientID
		}
	}

	s.evictLocked(now)
	clientID := clientSessionIDPrefix + uuid.NewString()
	s.sessions[clientID] = &mcpSession{
		clientID:   clientID,
		subject:    subject,
		serverName: serverName,
		upstreamID: upstreamID,
		expiresAt:  now.Add(s.ttl),
	}
	return clientID
}

// delete removes clientID ONLY after verifying ownership by (subject, serverName).
func (s *sessionStore) delete(clientID, subject, serverName string) (mcpSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	entry, ok := s.sessions[clientID]
	if !ok {
		return mcpSession{}, errSessionNotFound
	}
	if !now.Before(entry.expiresAt) {
		delete(s.sessions, clientID)
		return mcpSession{}, errSessionNotFound
	}
	if entry.subject != subject || entry.serverName != serverName {
		return mcpSession{}, errSessionForbidden
	}
	cp := *entry
	delete(s.sessions, clientID)
	return cp, nil
}

func (s *sessionStore) evictLocked(now time.Time) {
	if len(s.sessions) < maxTrackedSessions {
		return
	}
	for id, entry := range s.sessions {
		if !now.Before(entry.expiresAt) {
			delete(s.sessions, id)
		}
	}
	// If still at capacity, evict the soonest-expiring entry.
	for len(s.sessions) >= maxTrackedSessions {
		var oldestID string
		var oldestExp time.Time
		for id, entry := range s.sessions {
			if oldestID == "" || entry.expiresAt.Before(oldestExp) {
				oldestID = id
				oldestExp = entry.expiresAt
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.sessions, oldestID)
	}
}
