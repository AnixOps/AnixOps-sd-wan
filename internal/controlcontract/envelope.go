package controlcontract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

const (
	SignatureAlgorithm = "ed25519"
	signingDomainV1    = "anixops.sdwan.delivery-signature/v1"
)

type UnsignedEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	BundleKind    BundleKind      `json:"bundle_kind"`
	BundleID      string          `json:"bundle_id"`
	TenantID      string          `json:"tenant_id"`
	TargetID      string          `json:"target_id"`
	Sequence      uint64          `json:"sequence"`
	IssuedAt      time.Time       `json:"issued_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	KeyID         string          `json:"key_id"`
	Payload       json.RawMessage `json:"payload"`
}

func (e UnsignedEnvelope) ValidateMetadata() error {
	if e.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("unsupported envelope schema %q", e.SchemaVersion)
	}
	if e.BundleKind != BundleKindClient && e.BundleKind != BundleKindPop {
		return fmt.Errorf("unsupported envelope bundle kind %q", e.BundleKind)
	}
	if err := validateIdentifier("bundle id", e.BundleID); err != nil {
		return err
	}
	if err := validateIdentifier("tenant id", e.TenantID); err != nil {
		return err
	}
	if err := validateIdentifier("target ID", e.TargetID); err != nil {
		return err
	}
	if e.Sequence == 0 {
		return fmt.Errorf("sequence must be positive")
	}
	if e.IssuedAt.IsZero() {
		return fmt.Errorf("issued at is required")
	}
	if e.ExpiresAt.IsZero() {
		return fmt.Errorf("expires at is required")
	}
	if !e.ExpiresAt.After(e.IssuedAt) {
		return fmt.Errorf("expires at must be after issued at")
	}
	if err := validateIdentifier("signing key id", e.KeyID); err != nil {
		return err
	}
	if len(bytes.TrimSpace(e.Payload)) == 0 {
		return fmt.Errorf("payload is required")
	}
	if !json.Valid(e.Payload) {
		return fmt.Errorf("payload must be valid JSON")
	}
	return nil
}

func (e UnsignedEnvelope) Validate() error {
	if err := e.ValidateMetadata(); err != nil {
		return err
	}
	return e.validateProfileBinding()
}

func (e UnsignedEnvelope) validateProfileBinding() error {
	profile, err := ParseProfile(e.Payload)
	if err != nil {
		return fmt.Errorf("parse profile payload: %w", err)
	}
	if profile.SchemaVersion != e.SchemaVersion {
		return fmt.Errorf("profile schema does not match envelope schema")
	}
	if profile.Kind != e.BundleKind {
		return fmt.Errorf("profile kind does not match envelope bundle kind")
	}
	if profilePrincipalID(profile) != e.TargetID {
		return fmt.Errorf("profile principal id does not match envelope target ID")
	}
	return nil
}

func ParseProfile(payload []byte) (Profile, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, err
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Profile{}, fmt.Errorf("profile payload contains multiple JSON values")
		}
		return Profile{}, err
	}
	if err := profile.Validate(); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func profilePrincipalID(profile Profile) string {
	switch profile.Kind {
	case BundleKindClient:
		if profile.Client != nil {
			return profile.Client.PrincipalID
		}
	case BundleKindPop:
		if profile.Pop != nil {
			return profile.Pop.PrincipalID
		}
	}
	return ""
}

type SignedEnvelope struct {
	UnsignedEnvelope
	Algorithm     string `json:"algorithm"`
	PayloadSHA256 string `json:"payload_sha256"`
	Signature     string `json:"signature"`
}

func (e SignedEnvelope) validateIntegrity() ([]byte, error) {
	if e.Algorithm != SignatureAlgorithm {
		return nil, fmt.Errorf("unsupported signature algorithm %q", e.Algorithm)
	}
	if err := e.UnsignedEnvelope.ValidateMetadata(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(e.Payload)
	expectedDigest := hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(e.PayloadSHA256), []byte(expectedDigest)) != 1 {
		return nil, fmt.Errorf("payload hash does not match payload")
	}
	signature, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	return signature, nil
}

type Signer struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewSigner(privateKey ed25519.PrivateKey) (*Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing private key must be %d bytes", ed25519.PrivateKeySize)
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("derive signing public key")
	}
	return &Signer{
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

func NewVerifier(publicKey ed25519.PublicKey) (*Signer, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing public key must be %d bytes", ed25519.PublicKeySize)
	}
	return &Signer{publicKey: append(ed25519.PublicKey(nil), publicKey...)}, nil
}

func (s *Signer) Sign(envelope UnsignedEnvelope) (SignedEnvelope, error) {
	if len(s.privateKey) != ed25519.PrivateKeySize {
		return SignedEnvelope{}, fmt.Errorf("signing private key is required")
	}
	if err := envelope.Validate(); err != nil {
		return SignedEnvelope{}, err
	}
	input, err := SigningInputV1(envelope)
	if err != nil {
		return SignedEnvelope{}, err
	}
	digest := sha256.Sum256(envelope.Payload)
	return SignedEnvelope{
		UnsignedEnvelope: cloneUnsignedEnvelope(envelope),
		Algorithm:        SignatureAlgorithm,
		PayloadSHA256:    hex.EncodeToString(digest[:]),
		Signature:        base64.StdEncoding.EncodeToString(ed25519.Sign(s.privateKey, input)),
	}, nil
}

func (s *Signer) Verify(envelope SignedEnvelope, now time.Time) error {
	if len(s.publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("signing public key is required")
	}
	signature, err := envelope.validateIntegrity()
	if err != nil {
		return err
	}
	input, err := SigningInputV1(envelope.UnsignedEnvelope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.publicKey, input, signature) {
		return fmt.Errorf("signature verification failed")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !envelope.ExpiresAt.After(now) {
		return fmt.Errorf("envelope expired at %s", envelope.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	if err := envelope.UnsignedEnvelope.validateProfileBinding(); err != nil {
		return err
	}
	return nil
}

func SigningInputV1(envelope UnsignedEnvelope) ([]byte, error) {
	if err := envelope.ValidateMetadata(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(envelope.Payload)
	fields := [][]byte{
		[]byte(signingDomainV1),
		[]byte(envelope.SchemaVersion),
		[]byte(envelope.BundleKind),
		[]byte(envelope.BundleID),
		[]byte(envelope.TenantID),
		[]byte(envelope.TargetID),
		[]byte(strconv.FormatUint(envelope.Sequence, 10)),
		[]byte(envelope.IssuedAt.UTC().Format(time.RFC3339Nano)),
		[]byte(envelope.ExpiresAt.UTC().Format(time.RFC3339Nano)),
		[]byte(envelope.KeyID),
		digest[:],
	}

	var output bytes.Buffer
	for _, field := range fields {
		if err := writeLengthPrefixed(&output, field); err != nil {
			return nil, err
		}
	}
	return output.Bytes(), nil
}

func cloneUnsignedEnvelope(envelope UnsignedEnvelope) UnsignedEnvelope {
	envelope.Payload = append(json.RawMessage(nil), envelope.Payload...)
	return envelope
}

func writeLengthPrefixed(output *bytes.Buffer, field []byte) error {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return fmt.Errorf("signing field exceeds maximum length")
	}
	if err := binary.Write(output, binary.BigEndian, uint32(len(field))); err != nil {
		return err
	}
	if _, err := output.Write(field); err != nil {
		return err
	}
	return nil
}
