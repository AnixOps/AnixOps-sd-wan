package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	configsign "anixops-sd-wan/internal/config"
)

const SigningKeyApprovalVersion = 1

type SigningKeyApproval struct {
	Version              int        `json:"version"`
	Algorithm            string     `json:"algorithm"`
	PublicKey            string     `json:"public_key"`
	SHA256FingerprintHex string     `json:"sha256_fingerprint"`
	ApprovedBy           string     `json:"approved_by"`
	ApprovedAt           time.Time  `json:"approved_at"`
	Source               string     `json:"source,omitempty"`
	Note                 string     `json:"note,omitempty"`
	RequestedBy          string     `json:"requested_by,omitempty"`
	RequestedAt          *time.Time `json:"requested_at,omitempty"`
}

func NewSigningKeyApproval(key configsign.SigningPublicKey, approvedBy string, approvedAt time.Time) (SigningKeyApproval, error) {
	approvedBy = strings.TrimSpace(approvedBy)
	if approvedBy == "" {
		return SigningKeyApproval{}, fmt.Errorf("signing key approval approver is required")
	}
	if approvedAt.IsZero() {
		approvedAt = time.Now().UTC()
	}
	if _, err := configsign.NewConfigVerifierFromSigningKey(key); err != nil {
		return SigningKeyApproval{}, fmt.Errorf("validate signing key for approval: %w", err)
	}
	fingerprint, err := key.SHA256Fingerprint()
	if err != nil {
		return SigningKeyApproval{}, err
	}
	if key.SHA256FingerprintHex != "" {
		normalized, err := normalizeSigningKeyPin(key.SHA256FingerprintHex)
		if err != nil {
			return SigningKeyApproval{}, err
		}
		if normalized != fingerprint {
			return SigningKeyApproval{}, fmt.Errorf("signing key envelope fingerprint %s does not match public key fingerprint %s", normalized, fingerprint)
		}
	}
	return SigningKeyApproval{
		Version:              SigningKeyApprovalVersion,
		Algorithm:            key.Algorithm,
		PublicKey:            key.PublicKey,
		SHA256FingerprintHex: fingerprint,
		ApprovedBy:           approvedBy,
		ApprovedAt:           approvedAt,
	}, nil
}

func NewSigningKeyApprovalFromRequest(request configsign.SigningKeyApprovalRequest, approvedBy string, approvedAt time.Time) (SigningKeyApproval, error) {
	key, err := request.SigningPublicKey()
	if err != nil {
		return SigningKeyApproval{}, err
	}
	approval, err := NewSigningKeyApproval(key, approvedBy, approvedAt)
	if err != nil {
		return SigningKeyApproval{}, err
	}
	approval.Source = strings.TrimSpace(request.Source)
	approval.Note = strings.TrimSpace(request.Reason)
	approval.RequestedBy = strings.TrimSpace(request.RequestedBy)
	requestedAt := request.RequestedAt
	approval.RequestedAt = &requestedAt
	return approval, nil
}

func (a SigningKeyApproval) SigningPublicKey() (configsign.SigningPublicKey, error) {
	if a.Version != SigningKeyApprovalVersion {
		return configsign.SigningPublicKey{}, fmt.Errorf("unsupported signing key approval version %d", a.Version)
	}
	if strings.TrimSpace(a.ApprovedBy) == "" {
		return configsign.SigningPublicKey{}, fmt.Errorf("signing key approval approver is required")
	}
	if a.ApprovedAt.IsZero() {
		return configsign.SigningPublicKey{}, fmt.Errorf("signing key approval time is required")
	}
	normalized, err := normalizeSigningKeyPin(a.SHA256FingerprintHex)
	if err != nil {
		return configsign.SigningPublicKey{}, err
	}
	if normalized == "" {
		return configsign.SigningPublicKey{}, fmt.Errorf("signing key approval sha256 fingerprint is required")
	}
	key := configsign.SigningPublicKey{
		Algorithm:            a.Algorithm,
		PublicKey:            a.PublicKey,
		SHA256FingerprintHex: normalized,
		RotatedAt:            a.ApprovedAt,
	}
	fingerprint, err := key.SHA256Fingerprint()
	if err != nil {
		return configsign.SigningPublicKey{}, err
	}
	if fingerprint != normalized {
		return configsign.SigningPublicKey{}, fmt.Errorf("signing key approval fingerprint %s does not match public key fingerprint %s", normalized, fingerprint)
	}
	return key, nil
}

func (a SigningKeyApproval) TrustPolicy() (SigningKeyTrustPolicy, error) {
	key, err := a.SigningPublicKey()
	if err != nil {
		return SigningKeyTrustPolicy{}, err
	}
	return NewSigningKeyTrustPolicy(key.SHA256FingerprintHex)
}

func (a SigningKeyApproval) ValidateSigningKey(key configsign.SigningPublicKey) error {
	approved, err := a.SigningPublicKey()
	if err != nil {
		return err
	}
	if approved.Algorithm != key.Algorithm || approved.PublicKey != key.PublicKey {
		return fmt.Errorf("config signing key does not match approved public key")
	}
	policy, err := a.TrustPolicy()
	if err != nil {
		return err
	}
	return policy.Validate(key)
}

func LoadSigningKeyApproval(path string) (SigningKeyApproval, error) {
	if strings.TrimSpace(path) == "" {
		return SigningKeyApproval{}, fmt.Errorf("signing key approval path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return SigningKeyApproval{}, fmt.Errorf("open signing key approval: %w", err)
	}
	defer file.Close()

	var approval SigningKeyApproval
	if err := json.NewDecoder(file).Decode(&approval); err != nil {
		return SigningKeyApproval{}, fmt.Errorf("decode signing key approval: %w", err)
	}
	if _, err := approval.SigningPublicKey(); err != nil {
		return SigningKeyApproval{}, fmt.Errorf("validate signing key approval: %w", err)
	}
	return approval, nil
}

func SaveSigningKeyApproval(path string, approval SigningKeyApproval) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("signing key approval path is required")
	}
	if _, err := approval.SigningPublicKey(); err != nil {
		return fmt.Errorf("validate signing key approval: %w", err)
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateStateDir(dir); err != nil {
		return fmt.Errorf("create signing key approval directory: %w", err)
	}
	tmp, tmpName, err := createPrivateStateTempFile(dir, ".signing-key-approval-*.tmp")
	if err != nil {
		return fmt.Errorf("create signing key approval temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(approval); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode signing key approval: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close signing key approval temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace signing key approval: %w", err)
	}
	return nil
}
