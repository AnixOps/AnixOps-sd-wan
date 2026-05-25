package cert

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestAuthorityBackupSaveLoadAndRestore(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup", "ca.backup.json")
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	backup, err := authority.Backup(backupPath, createdAt)
	if err != nil {
		t.Fatalf("backup authority: %v", err)
	}
	assertPrivateAuthorityFile(t, backupPath)
	if backup.Version != AuthorityBackupVersion || !backup.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected backup metadata: %+v", backup)
	}

	loaded, err := LoadAuthorityBackup(backupPath)
	if err != nil {
		t.Fatalf("load authority backup: %v", err)
	}
	certPath := filepath.Join(t.TempDir(), "restore", "ca.pem")
	keyPath := filepath.Join(t.TempDir(), "restore", "ca-key.pem")
	if _, err := RestoreAuthorityBackupFile(certPath, keyPath, backupPath); err != nil {
		t.Fatalf("restore authority backup file: %v", err)
	}
	assertPrivateAuthorityFile(t, certPath)
	assertPrivateAuthorityFile(t, keyPath)
	restoredCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read restored cert: %v", err)
	}
	restoredKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read restored key: %v", err)
	}
	restored, err := NewAuthorityFromPEM(restoredCertPEM, restoredKeyPEM)
	if err != nil {
		t.Fatalf("load restored authority: %v", err)
	}
	if !bytes.Equal(restored.CAPEM(), authority.CAPEM()) {
		t.Fatal("expected restored CA certificate to match original")
	}
	if loaded.CertificateSHA256 != backup.CertificateSHA256 || loaded.PrivateKeySHA256 != backup.PrivateKeySHA256 {
		t.Fatalf("expected loaded backup checksums to match: loaded=%+v backup=%+v", loaded, backup)
	}
}

func TestAuthorityBackupRejectsTamperedPrivateKey(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup", "ca.backup.json")
	if _, err := authority.Backup(backupPath, now); err != nil {
		t.Fatalf("backup authority: %v", err)
	}
	backup, err := LoadAuthorityBackup(backupPath)
	if err != nil {
		t.Fatalf("load backup before tamper: %v", err)
	}
	backup.Authority.PrivateKeyPEM = append(backup.Authority.PrivateKeyPEM, '\n')
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered backup: %v", err)
	}
	if err := os.WriteFile(backupPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write tampered backup: %v", err)
	}
	if _, err := LoadAuthorityBackup(backupPath); err == nil {
		t.Fatal("expected tampered authority backup to be rejected")
	}
}

func TestNewAuthorityFromPEMRejectsMismatchedPrivateKey(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	first, err := NewAuthority("first-ca", now)
	if err != nil {
		t.Fatalf("new first authority: %v", err)
	}
	second, err := NewAuthority("second-ca", now)
	if err != nil {
		t.Fatalf("new second authority: %v", err)
	}
	firstBundle, err := first.ExportCA()
	if err != nil {
		t.Fatalf("export first authority: %v", err)
	}
	secondBundle, err := second.ExportCA()
	if err != nil {
		t.Fatalf("export second authority: %v", err)
	}
	if _, err := NewAuthorityFromPEM(firstBundle.CertificatePEM, secondBundle.PrivateKeyPEM); err == nil {
		t.Fatal("expected mismatched authority private key to be rejected")
	}
}

func assertPrivateAuthorityFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not reliable on Windows")
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat authority file dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected private authority file dir mode 700, got %o", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat authority file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected private authority file mode 600, got %o", got)
	}
}
