package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"anixops-sd-wan/internal/domain"
)

const ConfigSignatureAlgorithm = "ed25519"
const configSigningPrivateKeyPEMType = "PRIVATE KEY"

type ConfigSigner struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

type SignedBundle struct {
	Bundle    domain.ConfigBundle `json:"bundle"`
	Algorithm string              `json:"algorithm"`
	Signature string              `json:"signature"`
	SignedAt  time.Time           `json:"signed_at"`
}

type SigningPublicKey struct {
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	SHA256FingerprintHex string    `json:"sha256_fingerprint,omitempty"`
	RotatedAt            time.Time `json:"rotated_at"`
}

func NewConfigSigner() (*ConfigSigner, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate config signing key: %w", err)
	}
	return &ConfigSigner{publicKey: publicKey, privateKey: privateKey}, nil
}

func NewConfigSignerFromPrivateKey(privateKey ed25519.PrivateKey) (*ConfigSigner, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("config signing private key must be %d bytes", ed25519.PrivateKeySize)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("derive config signing public key")
	}
	return &ConfigSigner{
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

func NewConfigSignerFromPEM(data []byte) (*ConfigSigner, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != configSigningPrivateKeyPEMType {
		return nil, fmt.Errorf("config signing private key PEM is required")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse config signing private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("config signing private key must be Ed25519")
	}
	return NewConfigSignerFromPrivateKey(privateKey)
}

func NewConfigVerifier(publicKey ed25519.PublicKey) (*ConfigSigner, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("config signing public key must be %d bytes", ed25519.PublicKeySize)
	}
	return &ConfigSigner{publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

func NewConfigVerifierFromSigningKey(key SigningPublicKey) (*ConfigSigner, error) {
	publicKey, err := key.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	return NewConfigVerifier(publicKey)
}

func NewSigningPublicKey(publicKey ed25519.PublicKey, rotatedAt time.Time) (SigningPublicKey, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return SigningPublicKey{}, fmt.Errorf("config signing public key must be %d bytes", ed25519.PublicKeySize)
	}
	if rotatedAt.IsZero() {
		rotatedAt = time.Now().UTC()
	}
	sum := sha256.Sum256(publicKey)
	return SigningPublicKey{
		Algorithm:            ConfigSignatureAlgorithm,
		PublicKey:            base64.StdEncoding.EncodeToString(publicKey),
		SHA256FingerprintHex: hex.EncodeToString(sum[:]),
		RotatedAt:            rotatedAt,
	}, nil
}

func (k SigningPublicKey) PublicKeyBytes() (ed25519.PublicKey, error) {
	if k.Algorithm != ConfigSignatureAlgorithm {
		return nil, fmt.Errorf("unsupported config signature algorithm %q", k.Algorithm)
	}
	publicKey, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode config signing public key: %w", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("config signing public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
}

func (k SigningPublicKey) SHA256Fingerprint() (string, error) {
	publicKey, err := k.PublicKeyBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:]), nil
}

func (s *ConfigSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.publicKey...)
}

func (s *ConfigSigner) PrivateKeyPEM() ([]byte, error) {
	if len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("config signer private key is required")
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal config signing private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: configSigningPrivateKeyPEMType, Bytes: encoded}), nil
}

func (s *ConfigSigner) Sign(bundle domain.ConfigBundle, now time.Time) (SignedBundle, error) {
	if s.privateKey == nil {
		return SignedBundle{}, fmt.Errorf("config signer private key is required")
	}
	if err := bundle.Validate(); err != nil {
		return SignedBundle{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	payload, err := canonicalConfigPayload(bundle)
	if err != nil {
		return SignedBundle{}, err
	}
	signature := ed25519.Sign(s.privateKey, payload)
	return SignedBundle{
		Bundle:    bundle,
		Algorithm: ConfigSignatureAlgorithm,
		Signature: base64.StdEncoding.EncodeToString(signature),
		SignedAt:  now,
	}, nil
}

func (s *ConfigSigner) Verify(signed SignedBundle) error {
	if len(s.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("config signing public key is required")
	}
	if signed.Algorithm != ConfigSignatureAlgorithm {
		return fmt.Errorf("unsupported config signature algorithm %q", signed.Algorithm)
	}
	if err := signed.Bundle.Validate(); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode config signature: %w", err)
	}
	payload, err := canonicalConfigPayload(signed.Bundle)
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.publicKey, payload, signature) {
		return fmt.Errorf("config signature verification failed")
	}
	return nil
}

func canonicalConfigPayload(bundle domain.ConfigBundle) ([]byte, error) {
	payload := struct {
		ID        string            `json:"id"`
		TenantID  string            `json:"tenant_id"`
		TargetID  string            `json:"target_id"`
		Version   string            `json:"version"`
		Values    map[string]string `json:"values"`
		CreatedAt time.Time         `json:"created_at"`
	}{
		ID:        bundle.ID,
		TenantID:  bundle.TenantID,
		TargetID:  bundle.TargetID,
		Version:   bundle.Version,
		Values:    bundle.Values,
		CreatedAt: bundle.CreatedAt,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize config bundle: %w", err)
	}
	return encoded, nil
}
