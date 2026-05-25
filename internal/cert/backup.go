package cert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const AuthorityBackupVersion = 1

type AuthorityBackup struct {
	Version           int             `json:"version"`
	CreatedAt         time.Time       `json:"created_at"`
	CertificateSHA256 string          `json:"certificate_sha256"`
	PrivateKeySHA256  string          `json:"private_key_sha256"`
	Authority         AuthorityBundle `json:"authority"`
}

func NewAuthorityBackup(authority *Authority, createdAt time.Time) (AuthorityBackup, error) {
	if authority == nil {
		return AuthorityBackup{}, fmt.Errorf("authority is required")
	}
	bundle, err := authority.ExportCA()
	if err != nil {
		return AuthorityBackup{}, err
	}
	return NewAuthorityBackupFromBundle(bundle, createdAt)
}

func NewAuthorityBackupFromBundle(bundle AuthorityBundle, createdAt time.Time) (AuthorityBackup, error) {
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	backup := AuthorityBackup{
		Version:           AuthorityBackupVersion,
		CreatedAt:         createdAt.UTC(),
		CertificateSHA256: sha256Hex(bundle.CertificatePEM),
		PrivateKeySHA256:  sha256Hex(bundle.PrivateKeyPEM),
		Authority:         AuthorityBundle{CertificatePEM: append([]byte(nil), bundle.CertificatePEM...), PrivateKeyPEM: append([]byte(nil), bundle.PrivateKeyPEM...)},
	}
	if err := backup.Validate(); err != nil {
		return AuthorityBackup{}, err
	}
	return backup, nil
}

func (a *Authority) Backup(path string, createdAt time.Time) (AuthorityBackup, error) {
	if path == "" {
		return AuthorityBackup{}, fmt.Errorf("authority backup path is required")
	}
	backup, err := NewAuthorityBackup(a, createdAt)
	if err != nil {
		return AuthorityBackup{}, err
	}
	if err := SaveAuthorityBackup(path, backup); err != nil {
		return AuthorityBackup{}, err
	}
	return backup, nil
}

func SaveAuthorityBackup(path string, backup AuthorityBackup) error {
	if err := backup.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("encode authority backup: %w", err)
	}
	return writePrivateFile(path, append(data, '\n'))
}

func LoadAuthorityBackup(path string) (AuthorityBackup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return AuthorityBackup{}, fmt.Errorf("read authority backup: %w", err)
	}
	var backup AuthorityBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return AuthorityBackup{}, fmt.Errorf("decode authority backup: %w", err)
	}
	if err := backup.Validate(); err != nil {
		return AuthorityBackup{}, err
	}
	return backup, nil
}

func RestoreAuthorityBackup(certPath, keyPath string, backup AuthorityBackup) error {
	if certPath == "" {
		return fmt.Errorf("authority certificate restore path is required")
	}
	if keyPath == "" {
		return fmt.Errorf("authority private key restore path is required")
	}
	if err := backup.Validate(); err != nil {
		return err
	}
	if err := writePrivateFile(certPath, backup.Authority.CertificatePEM); err != nil {
		return fmt.Errorf("restore authority certificate: %w", err)
	}
	if err := writePrivateFile(keyPath, backup.Authority.PrivateKeyPEM); err != nil {
		return fmt.Errorf("restore authority private key: %w", err)
	}
	return nil
}

func RestoreAuthorityBackupFile(certPath, keyPath, backupPath string) (AuthorityBackup, error) {
	backup, err := LoadAuthorityBackup(backupPath)
	if err != nil {
		return AuthorityBackup{}, err
	}
	if err := RestoreAuthorityBackup(certPath, keyPath, backup); err != nil {
		return AuthorityBackup{}, err
	}
	return backup, nil
}

func (b AuthorityBackup) Validate() error {
	if b.Version != AuthorityBackupVersion {
		return fmt.Errorf("unsupported authority backup version %d", b.Version)
	}
	if b.CreatedAt.IsZero() {
		return fmt.Errorf("authority backup created_at is required")
	}
	if err := validateSHA256Hex("authority certificate", b.CertificateSHA256); err != nil {
		return err
	}
	if err := validateSHA256Hex("authority private key", b.PrivateKeySHA256); err != nil {
		return err
	}
	if sha256Hex(b.Authority.CertificatePEM) != b.CertificateSHA256 {
		return fmt.Errorf("authority certificate sha256 mismatch")
	}
	if sha256Hex(b.Authority.PrivateKeyPEM) != b.PrivateKeySHA256 {
		return fmt.Errorf("authority private key sha256 mismatch")
	}
	if _, err := NewAuthorityFromPEM(b.Authority.CertificatePEM, b.Authority.PrivateKeyPEM); err != nil {
		return fmt.Errorf("validate authority backup bundle: %w", err)
	}
	return nil
}

func validateSHA256Hex(name, value string) error {
	if len(value) != 64 {
		return fmt.Errorf("%s sha256 must be 64 hex characters", name)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s sha256 must be hex: %w", name, err)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create private file directory: %w", err)
	}
	if dir != "." {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod private file directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".authority-*.tmp")
	if err != nil {
		return fmt.Errorf("create private temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod private temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write private temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close private temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace private file: %w", err)
	}
	return nil
}
