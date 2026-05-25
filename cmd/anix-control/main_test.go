package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"anixops-sd-wan/internal/auth"
	certpkg "anixops-sd-wan/internal/cert"
	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/store"
)

func TestLoadConfigSignerCreatesAndReloadsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control", "config-signing-key.pem")
	first, err := loadConfigSigner(path)
	if err != nil {
		t.Fatalf("create config signer: %v", err)
	}
	assertPrivateControlFile(t, path)
	second, err := loadConfigSigner(path)
	if err != nil {
		t.Fatalf("reload config signer: %v", err)
	}
	if !bytes.Equal(first.PublicKey(), second.PublicKey()) {
		t.Fatal("expected config signing key file to preserve public key")
	}

	rotated, err := config.NewConfigSigner()
	if err != nil {
		t.Fatalf("new rotated signer: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("make config signing key overly permissive: %v", err)
	}
	if err := persistConfigSigner(path, rotated); err != nil {
		t.Fatalf("persist rotated signer: %v", err)
	}
	assertPrivateControlFile(t, path)
	reloaded, err := loadConfigSigner(path)
	if err != nil {
		t.Fatalf("reload rotated signer: %v", err)
	}
	if !bytes.Equal(rotated.PublicKey(), reloaded.PublicKey()) {
		t.Fatal("expected persisted rotated key to reload")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("make config signing key overly permissive for load test: %v", err)
		}
		if _, err := loadConfigSigner(path); err == nil {
			t.Fatal("expected overly permissive config signing key file to be rejected")
		}
	}
}

func TestLoadPasswordAuthenticator(t *testing.T) {
	user, err := auth.NewPasswordUser("tenant-a", "admin-a", "password", []auth.Role{auth.RoleAdmin}, 1000)
	if err != nil {
		t.Fatalf("new password user: %v", err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	data, err := json.Marshal([]auth.PasswordUser{user})
	if err != nil {
		t.Fatalf("marshal users: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	authenticator := loadPasswordAuthenticator(path)
	if _, ok, err := authenticator.Authenticate("tenant-a", "admin-a", "password"); err != nil || !ok {
		t.Fatalf("expected loaded password authenticator to authenticate, ok=%v err=%v", ok, err)
	}
}

func TestLoadOIDCAuthenticator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oidc.json")
	data, err := json.Marshal(auth.OIDCConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "anixops-control",
		HMACSecret: "secret",
	})
	if err != nil {
		t.Fatalf("marshal oidc config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write oidc config: %v", err)
	}
	authenticator := loadOIDCAuthenticator(path)
	if authenticator == nil {
		t.Fatal("expected oidc authenticator")
	}
}

func TestStoreBackupAndRestoreHelpers(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "state", "control-store.json")
	repository, err := store.NewFileRepository(storePath)
	if err != nil {
		t.Fatalf("new file repository: %v", err)
	}
	if _, err := repository.CreateTenant(context.Background(), domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup", "control-store.backup.json")
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	backup, err := writeStoreBackup(storePath, backupPath, createdAt)
	if err != nil {
		t.Fatalf("write store backup: %v", err)
	}
	if backup.Counts.Tenants != 1 || !backup.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected backup metadata: %+v", backup)
	}
	assertPrivateControlFile(t, backupPath)

	restoredPath := filepath.Join(t.TempDir(), "restore", "control-store.json")
	if _, err := restoreStoreBackup(restoredPath, backupPath); err != nil {
		t.Fatalf("restore store backup: %v", err)
	}
	assertPrivateControlFile(t, restoredPath)
	restored, err := store.NewFileRepository(restoredPath)
	if err != nil {
		t.Fatalf("load restored repository: %v", err)
	}
	inventory, err := restored.Inventory(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("restored inventory: %v", err)
	}
	if inventory.Tenant.Name != "Tenant A" {
		t.Fatalf("expected restored tenant, got %+v", inventory.Tenant)
	}
}

func TestCABackupAndRestoreHelpers(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := certpkg.NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	bundle, err := authority.ExportCA()
	if err != nil {
		t.Fatalf("export authority: %v", err)
	}
	sourceDir := filepath.Join(t.TempDir(), "ca")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("mkdir source ca dir: %v", err)
	}
	certPath := filepath.Join(sourceDir, "ca.pem")
	keyPath := filepath.Join(sourceDir, "ca-key.pem")
	if err := os.WriteFile(certPath, bundle.CertificatePEM, 0o600); err != nil {
		t.Fatalf("write source ca cert: %v", err)
	}
	if err := os.WriteFile(keyPath, bundle.PrivateKeyPEM, 0o600); err != nil {
		t.Fatalf("write source ca key: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "backup", "ca.backup.json")
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	backup, err := writeCABackup(certPath, keyPath, backupPath, createdAt)
	if err != nil {
		t.Fatalf("write ca backup: %v", err)
	}
	if backup.Version != certpkg.AuthorityBackupVersion || !backup.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected ca backup metadata: %+v", backup)
	}
	assertPrivateControlFile(t, backupPath)

	restoredCertPath := filepath.Join(t.TempDir(), "restore", "ca.pem")
	restoredKeyPath := filepath.Join(t.TempDir(), "restore", "ca-key.pem")
	if _, err := restoreCABackup(restoredCertPath, restoredKeyPath, backupPath); err != nil {
		t.Fatalf("restore ca backup: %v", err)
	}
	assertPrivateControlFile(t, restoredCertPath)
	assertPrivateControlFile(t, restoredKeyPath)
	restoredCertPEM, err := os.ReadFile(restoredCertPath)
	if err != nil {
		t.Fatalf("read restored ca cert: %v", err)
	}
	restoredKeyPEM, err := os.ReadFile(restoredKeyPath)
	if err != nil {
		t.Fatalf("read restored ca key: %v", err)
	}
	restored, err := certpkg.NewAuthorityFromPEM(restoredCertPEM, restoredKeyPEM)
	if err != nil {
		t.Fatalf("load restored authority: %v", err)
	}
	if !bytes.Equal(restored.CAPEM(), authority.CAPEM()) {
		t.Fatal("expected restored CA certificate to match original")
	}
}

func assertPrivateControlFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not reliable on Windows")
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat control dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected private control dir mode 700, got %o", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat control file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected private control file mode 600, got %o", got)
	}
}
