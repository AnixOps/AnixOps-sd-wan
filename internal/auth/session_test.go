package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSessionStoreIssuesAuthenticatesAndRevokes(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	session, err := store.Issue(Subject{
		ID:       "admin-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleAdmin},
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	subject, ok := store.Authenticate(session.Token, now.Add(time.Minute))
	if !ok {
		t.Fatal("expected session to authenticate")
	}
	if subject.ID != "admin-a" {
		t.Fatalf("expected admin-a, got %+v", subject)
	}
	if !store.Revoke(session.Token) {
		t.Fatal("expected revoke to succeed")
	}
	if _, ok := store.Authenticate(session.Token, now.Add(2*time.Minute)); ok {
		t.Fatal("expected revoked session to fail")
	}
}

func TestSessionStoreRejectsExpiredSession(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	store := NewSessionStore()
	session, err := store.Issue(Subject{
		ID:       "viewer-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleViewer},
	}, time.Minute, now)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	if _, ok := store.Authenticate(session.Token, now.Add(2*time.Minute)); ok {
		t.Fatal("expected expired session to fail")
	}
}

func TestFileSessionStorePersistsSessions(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state", "sessions.json")
	store, err := NewFileSessionStore(path)
	if err != nil {
		t.Fatalf("new file session store: %v", err)
	}
	session, err := store.Issue(Subject{
		ID:       "operator-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleOperator},
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	assertPrivateSessionFile(t, path)

	reloaded, err := NewFileSessionStore(path)
	if err != nil {
		t.Fatalf("reload file session store: %v", err)
	}
	subject, ok := reloaded.Authenticate(session.Token, now.Add(time.Minute))
	if !ok {
		t.Fatal("expected persisted session to authenticate")
	}
	if subject.ID != "operator-a" {
		t.Fatalf("expected operator-a, got %+v", subject)
	}
	if !reloaded.Revoke(session.Token) {
		t.Fatal("expected revoke to succeed")
	}
	assertPrivateSessionFile(t, path)

	reloadedAgain, err := NewFileSessionStore(path)
	if err != nil {
		t.Fatalf("reload revoked session store: %v", err)
	}
	if _, ok := reloadedAgain.Authenticate(session.Token, now.Add(2*time.Minute)); ok {
		t.Fatal("expected persisted revoke to deny session")
	}
}

func assertPrivateSessionFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not reliable on Windows")
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat session dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected private session dir mode 700, got %o", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat session file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected private session file mode 600, got %o", got)
	}
}
