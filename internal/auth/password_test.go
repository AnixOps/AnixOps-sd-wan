package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPasswordAuthenticatorAuthenticatesHashedUser(t *testing.T) {
	user, err := NewPasswordUser("tenant-a", "admin-a", "correct-password", []Role{RoleAdmin}, 1000)
	if err != nil {
		t.Fatalf("new password user: %v", err)
	}
	authenticator, err := NewPasswordAuthenticator([]PasswordUser{user})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	subject, ok, err := authenticator.Authenticate("tenant-a", "admin-a", "correct-password")
	if err != nil {
		t.Fatalf("authenticate password: %v", err)
	}
	if !ok {
		t.Fatal("expected password authentication to succeed")
	}
	if subject.ID != "admin-a" || subject.TenantID != "tenant-a" || len(subject.Roles) != 1 || subject.Roles[0] != RoleAdmin {
		t.Fatalf("unexpected subject: %+v", subject)
	}

	if _, ok, err := authenticator.Authenticate("tenant-a", "admin-a", "wrong-password"); err != nil || ok {
		t.Fatalf("expected wrong password denial, ok=%v err=%v", ok, err)
	}
	if _, ok, err := authenticator.Authenticate("tenant-b", "admin-a", "correct-password"); err != nil || ok {
		t.Fatalf("expected cross-tenant password denial, ok=%v err=%v", ok, err)
	}
}

func TestLoadPasswordAuthenticatorFromFile(t *testing.T) {
	user, err := NewPasswordUser("tenant-a", "operator-a", "password", []Role{RoleOperator}, 1000)
	if err != nil {
		t.Fatalf("new password user: %v", err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	data, err := json.Marshal([]PasswordUser{user})
	if err != nil {
		t.Fatalf("marshal users: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}

	authenticator, err := LoadPasswordAuthenticator(path)
	if err != nil {
		t.Fatalf("load password authenticator: %v", err)
	}
	if _, ok, err := authenticator.Authenticate("tenant-a", "operator-a", "password"); err != nil || !ok {
		t.Fatalf("expected loaded password user to authenticate, ok=%v err=%v", ok, err)
	}
}

func TestLoadPasswordAuthenticatorRejectsOverlyPermissiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not reliable on Windows")
	}
	user, err := NewPasswordUser("tenant-a", "operator-a", "password", []Role{RoleOperator}, 1000)
	if err != nil {
		t.Fatalf("new password user: %v", err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	data, err := json.Marshal([]PasswordUser{user})
	if err != nil {
		t.Fatalf("marshal users: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write users file: %v", err)
	}
	if _, err := LoadPasswordAuthenticator(path); err == nil {
		t.Fatal("expected overly permissive password users file to be rejected")
	}
}

func TestPasswordAuthenticatorRejectsDuplicateUsers(t *testing.T) {
	first, err := NewPasswordUser("tenant-a", "admin-a", "first", []Role{RoleAdmin}, 1000)
	if err != nil {
		t.Fatalf("new first user: %v", err)
	}
	second, err := NewPasswordUser("tenant-a", "admin-a", "second", []Role{RoleAdmin}, 1000)
	if err != nil {
		t.Fatalf("new second user: %v", err)
	}
	if _, err := NewPasswordAuthenticator([]PasswordUser{first, second}); err == nil {
		t.Fatal("expected duplicate password user to be rejected")
	}
}
