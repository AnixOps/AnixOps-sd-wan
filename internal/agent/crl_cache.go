package agent

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"anixops-sd-wan/internal/cert"
)

var ErrCRLCacheMiss = errors.New("agent crl cache miss")

type CRLCache interface {
	Load() (cert.RevocationList, error)
	Save(cert.RevocationList) error
}

type FileCRLCache struct {
	path string
}

func NewFileCRLCache(path string) (*FileCRLCache, error) {
	if path == "" {
		return nil, fmt.Errorf("crl cache path is required")
	}
	return &FileCRLCache{path: path}, nil
}

func (c *FileCRLCache) Load() (cert.RevocationList, error) {
	file, err := os.Open(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return cert.RevocationList{}, ErrCRLCacheMiss
	}
	if err != nil {
		return cert.RevocationList{}, fmt.Errorf("open crl cache: %w", err)
	}
	defer file.Close()

	var list cert.RevocationList
	if err := json.NewDecoder(file).Decode(&list); err != nil {
		return cert.RevocationList{}, fmt.Errorf("decode crl cache: %w", err)
	}
	if err := validateRevocationList(list); err != nil {
		return cert.RevocationList{}, fmt.Errorf("validate crl cache: %w", err)
	}
	return list, nil
}

func (c *FileCRLCache) Save(list cert.RevocationList) error {
	if err := validateRevocationList(list); err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	if err := ensurePrivateStateDir(dir); err != nil {
		return fmt.Errorf("create crl cache directory: %w", err)
	}
	tmp, tmpName, err := createPrivateStateTempFile(dir, ".crl-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create crl cache temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(list); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode crl cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close crl cache temp file: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return fmt.Errorf("replace crl cache: %w", err)
	}
	return nil
}

func validateRevocationList(list cert.RevocationList) error {
	if list.TenantID == "" {
		return fmt.Errorf("crl tenant id is required")
	}
	if list.Issuer == "" {
		return fmt.Errorf("crl issuer is required")
	}
	if list.GeneratedAt.IsZero() {
		return fmt.Errorf("crl generated time is required")
	}
	if list.NextUpdate.IsZero() {
		return fmt.Errorf("crl next update is required")
	}
	if !list.NextUpdate.After(list.GeneratedAt) {
		return fmt.Errorf("crl next update must be after generated time")
	}
	block, _ := pem.Decode(list.CRLPEM)
	if block == nil || block.Type != "X509 CRL" {
		return fmt.Errorf("x509 crl pem is required")
	}
	if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
		return fmt.Errorf("parse x509 crl: %w", err)
	}
	for _, record := range list.Records {
		if record.TenantID != list.TenantID {
			return fmt.Errorf("crl record tenant %q does not match list tenant %q", record.TenantID, list.TenantID)
		}
		if !record.Revoked {
			return fmt.Errorf("crl record %q is not revoked", record.Serial)
		}
	}
	return nil
}
