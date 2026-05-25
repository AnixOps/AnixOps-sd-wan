package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	configsign "anixops-sd-wan/internal/config"
)

var ErrSigningKeyCacheMiss = errors.New("agent signing key cache miss")

type SigningKeyCache interface {
	Load() (configsign.SigningPublicKey, error)
	Save(configsign.SigningPublicKey) error
}

type FileSigningKeyCache struct {
	path string
}

func NewFileSigningKeyCache(path string) (*FileSigningKeyCache, error) {
	if path == "" {
		return nil, fmt.Errorf("signing key cache path is required")
	}
	return &FileSigningKeyCache{path: path}, nil
}

func (c *FileSigningKeyCache) Load() (configsign.SigningPublicKey, error) {
	file, err := os.Open(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return configsign.SigningPublicKey{}, ErrSigningKeyCacheMiss
	}
	if err != nil {
		return configsign.SigningPublicKey{}, fmt.Errorf("open signing key cache: %w", err)
	}
	defer file.Close()

	var key configsign.SigningPublicKey
	if err := json.NewDecoder(file).Decode(&key); err != nil {
		return configsign.SigningPublicKey{}, fmt.Errorf("decode signing key cache: %w", err)
	}
	if _, err := configsign.NewConfigVerifierFromSigningKey(key); err != nil {
		return configsign.SigningPublicKey{}, fmt.Errorf("validate signing key cache: %w", err)
	}
	return key, nil
}

func (c *FileSigningKeyCache) Save(key configsign.SigningPublicKey) error {
	if _, err := configsign.NewConfigVerifierFromSigningKey(key); err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	if err := ensurePrivateStateDir(dir); err != nil {
		return fmt.Errorf("create signing key cache directory: %w", err)
	}
	tmp, tmpName, err := createPrivateStateTempFile(dir, ".signing-key-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create signing key cache temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(key); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode signing key cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close signing key cache temp file: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return fmt.Errorf("replace signing key cache: %w", err)
	}
	return nil
}
