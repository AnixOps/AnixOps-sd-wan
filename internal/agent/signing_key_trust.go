package agent

import (
	"encoding/hex"
	"fmt"
	"strings"

	configsign "anixops-sd-wan/internal/config"
)

type SigningKeyTrustPolicy struct {
	PinnedSHA256 string
}

func NewSigningKeyTrustPolicy(pinnedSHA256 string) (SigningKeyTrustPolicy, error) {
	normalized, err := normalizeSigningKeyPin(pinnedSHA256)
	if err != nil {
		return SigningKeyTrustPolicy{}, err
	}
	return SigningKeyTrustPolicy{PinnedSHA256: normalized}, nil
}

func (p SigningKeyTrustPolicy) Validate(key configsign.SigningPublicKey) error {
	if p.PinnedSHA256 == "" {
		return nil
	}
	got, err := key.SHA256Fingerprint()
	if err != nil {
		return err
	}
	if got != p.PinnedSHA256 {
		return fmt.Errorf("config signing key fingerprint %s does not match pinned sha256 %s", got, p.PinnedSHA256)
	}
	return nil
}

func normalizeSigningKeyPin(pin string) (string, error) {
	pin = strings.TrimSpace(strings.ToLower(pin))
	pin = strings.TrimPrefix(pin, "sha256:")
	if pin == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(pin)
	if err != nil {
		return "", fmt.Errorf("config signing key sha256 pin must be hex: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("config signing key sha256 pin must decode to 32 bytes")
	}
	return pin, nil
}
