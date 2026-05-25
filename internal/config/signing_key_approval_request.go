package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	SigningKeyApprovalRequestVersion = 1
	SigningKeyApprovalRequestKind    = "config_signing_key_approval_request"
)

type SigningKeyApprovalRequest struct {
	Version              int       `json:"version"`
	Kind                 string    `json:"kind"`
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	SHA256FingerprintHex string    `json:"sha256_fingerprint"`
	RotatedAt            time.Time `json:"rotated_at"`
	RequestedBy          string    `json:"requested_by"`
	RequestedAt          time.Time `json:"requested_at"`
	Source               string    `json:"source,omitempty"`
	Reason               string    `json:"reason,omitempty"`
}

func NewSigningKeyApprovalRequest(key SigningPublicKey, requestedBy string, requestedAt time.Time) (SigningKeyApprovalRequest, error) {
	requestedBy = strings.TrimSpace(requestedBy)
	if requestedBy == "" {
		return SigningKeyApprovalRequest{}, fmt.Errorf("signing key approval request requester is required")
	}
	if requestedAt.IsZero() {
		requestedAt = time.Now().UTC()
	}
	fingerprint, err := validateSigningPublicKeyFingerprint(key)
	if err != nil {
		return SigningKeyApprovalRequest{}, err
	}
	return SigningKeyApprovalRequest{
		Version:              SigningKeyApprovalRequestVersion,
		Kind:                 SigningKeyApprovalRequestKind,
		Algorithm:            key.Algorithm,
		PublicKey:            key.PublicKey,
		SHA256FingerprintHex: fingerprint,
		RotatedAt:            key.RotatedAt,
		RequestedBy:          requestedBy,
		RequestedAt:          requestedAt,
	}, nil
}

func (r SigningKeyApprovalRequest) SigningPublicKey() (SigningPublicKey, error) {
	if r.Version != SigningKeyApprovalRequestVersion {
		return SigningPublicKey{}, fmt.Errorf("unsupported signing key approval request version %d", r.Version)
	}
	if r.Kind != SigningKeyApprovalRequestKind {
		return SigningPublicKey{}, fmt.Errorf("unsupported signing key approval request kind %q", r.Kind)
	}
	if strings.TrimSpace(r.RequestedBy) == "" {
		return SigningPublicKey{}, fmt.Errorf("signing key approval request requester is required")
	}
	if r.RequestedAt.IsZero() {
		return SigningPublicKey{}, fmt.Errorf("signing key approval request time is required")
	}
	if strings.TrimSpace(r.SHA256FingerprintHex) == "" {
		return SigningPublicKey{}, fmt.Errorf("signing key approval request sha256 fingerprint is required")
	}
	key := SigningPublicKey{
		Algorithm:            r.Algorithm,
		PublicKey:            r.PublicKey,
		SHA256FingerprintHex: r.SHA256FingerprintHex,
		RotatedAt:            r.RotatedAt,
	}
	fingerprint, err := validateSigningPublicKeyFingerprint(key)
	if err != nil {
		return SigningPublicKey{}, err
	}
	key.SHA256FingerprintHex = fingerprint
	return key, nil
}

func LoadSigningKeyApprovalRequest(path string) (SigningKeyApprovalRequest, error) {
	if strings.TrimSpace(path) == "" {
		return SigningKeyApprovalRequest{}, fmt.Errorf("signing key approval request path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return SigningKeyApprovalRequest{}, fmt.Errorf("open signing key approval request: %w", err)
	}
	defer file.Close()

	var request SigningKeyApprovalRequest
	if err := json.NewDecoder(file).Decode(&request); err != nil {
		return SigningKeyApprovalRequest{}, fmt.Errorf("decode signing key approval request: %w", err)
	}
	if _, err := request.SigningPublicKey(); err != nil {
		return SigningKeyApprovalRequest{}, fmt.Errorf("validate signing key approval request: %w", err)
	}
	return request, nil
}

func validateSigningPublicKeyFingerprint(key SigningPublicKey) (string, error) {
	if _, err := NewConfigVerifierFromSigningKey(key); err != nil {
		return "", err
	}
	fingerprint, err := key.SHA256Fingerprint()
	if err != nil {
		return "", err
	}
	normalized, err := normalizeSHA256FingerprintHex(key.SHA256FingerprintHex)
	if err != nil {
		return "", err
	}
	if normalized == "" {
		normalized = fingerprint
	}
	if normalized != fingerprint {
		return "", fmt.Errorf("signing key envelope fingerprint %s does not match public key fingerprint %s", normalized, fingerprint)
	}
	return normalized, nil
}

func normalizeSHA256FingerprintHex(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "sha256:")
	if raw == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("signing key sha256 fingerprint must be hex: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("signing key sha256 fingerprint must decode to 32 bytes")
	}
	return raw, nil
}
