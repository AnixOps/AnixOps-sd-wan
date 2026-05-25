package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type SessionManager interface {
	Issue(Subject, time.Duration, time.Time) (Session, error)
	Authenticate(string, time.Time) (Subject, bool)
	Revoke(string) bool
}

type Session struct {
	Token     string    `json:"token"`
	Subject   Subject   `json:"subject"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]Session)}
}

func NewSessionStoreFromSessions(sessions []Session) *SessionStore {
	store := NewSessionStore()
	for _, session := range sessions {
		if session.Token == "" {
			continue
		}
		store.sessions[session.Token] = session
	}
	return store
}

func (s *SessionStore) Issue(subject Subject, ttl time.Duration, now time.Time) (Session, error) {
	if subject.ID == "" {
		return Session{}, fmt.Errorf("subject id is required")
	}
	if subject.TenantID == "" {
		return Session{}, fmt.Errorf("subject tenant id is required")
	}
	if len(subject.Roles) == 0 {
		return Session{}, fmt.Errorf("subject roles are required")
	}
	if ttl <= 0 {
		return Session{}, fmt.Errorf("session ttl must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return Session{}, fmt.Errorf("generate session token: %w", err)
	}
	session := Session{
		Token:     base64.RawURLEncoding.EncodeToString(tokenBytes),
		Subject:   subject,
		ExpiresAt: now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.Token] = session
	return session, nil
}

func (s *SessionStore) Authenticate(token string, now time.Time) (Subject, bool) {
	if token == "" {
		return Subject{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.sessions[token]
	if !exists || session.Revoked || !now.Before(session.ExpiresAt) {
		return Subject{}, false
	}
	return session.Subject, true
}

func (s *SessionStore) Revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, exists := s.sessions[token]
	if !exists {
		return false
	}
	session.Revoked = true
	s.sessions[token] = session
	return true
}

func (s *SessionStore) Snapshot() []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

type FileSessionStore struct {
	*SessionStore
	path string
}

func NewFileSessionStore(path string) (*FileSessionStore, error) {
	if path == "" {
		return nil, fmt.Errorf("session file path is required")
	}
	sessions, err := loadSessions(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return &FileSessionStore{
		SessionStore: NewSessionStoreFromSessions(sessions),
		path:         path,
	}, nil
}

func (s *FileSessionStore) Issue(subject Subject, ttl time.Duration, now time.Time) (Session, error) {
	session, err := s.SessionStore.Issue(subject, ttl, now)
	if err != nil {
		return Session{}, err
	}
	return session, s.save()
}

func (s *FileSessionStore) Revoke(token string) bool {
	revoked := s.SessionStore.Revoke(token)
	if revoked {
		_ = s.save()
	}
	return revoked
}

func (s *FileSessionStore) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	if dir != "." {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod session directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".sessions-*.tmp")
	if err != nil {
		return fmt.Errorf("create session temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(s.Snapshot()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode sessions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close session temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return fmt.Errorf("chmod session temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace session file: %w", err)
	}
	return nil
}

func loadSessions(path string) ([]Session, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sessions []Session
	if err := json.NewDecoder(file).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("decode sessions: %w", err)
	}
	return sessions, nil
}

var _ SessionManager = (*SessionStore)(nil)
var _ SessionManager = (*FileSessionStore)(nil)
