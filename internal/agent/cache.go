package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"anixops-sd-wan/internal/domain"
)

var ErrConfigCacheMiss = errors.New("agent config cache miss")

type ConfigCache interface {
	Load() (domain.ConfigBundle, error)
	Save(domain.ConfigBundle) error
}

type FileConfigCache struct {
	path string
}

func NewFileConfigCache(path string) (*FileConfigCache, error) {
	if path == "" {
		return nil, fmt.Errorf("config cache path is required")
	}
	return &FileConfigCache{path: path}, nil
}

func (c *FileConfigCache) Load() (domain.ConfigBundle, error) {
	file, err := os.Open(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return domain.ConfigBundle{}, ErrConfigCacheMiss
	}
	if err != nil {
		return domain.ConfigBundle{}, fmt.Errorf("open config cache: %w", err)
	}
	defer file.Close()

	var bundle domain.ConfigBundle
	if err := json.NewDecoder(file).Decode(&bundle); err != nil {
		return domain.ConfigBundle{}, fmt.Errorf("decode config cache: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return domain.ConfigBundle{}, fmt.Errorf("validate config cache: %w", err)
	}
	return bundle, nil
}

func (c *FileConfigCache) Save(bundle domain.ConfigBundle) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	if err := ensurePrivateStateDir(dir); err != nil {
		return fmt.Errorf("create config cache directory: %w", err)
	}
	tmp, tmpName, err := createPrivateStateTempFile(dir, ".config-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create config cache temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(bundle); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode config cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config cache temp file: %w", err)
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return fmt.Errorf("replace config cache: %w", err)
	}
	return nil
}
