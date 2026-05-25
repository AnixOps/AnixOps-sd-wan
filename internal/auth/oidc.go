package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type OIDCConfig struct {
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	HMACSecret string `json:"hmac_secret"`
}

type OIDCAuthenticator struct {
	issuer     string
	audience   string
	hmacSecret []byte
}

type oidcHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ,omitempty"`
}

type oidcClaims struct {
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	Subject   string          `json:"sub"`
	TenantID  string          `json:"tenant_id"`
	Roles     []Role          `json:"roles"`
	ExpiresAt int64           `json:"exp"`
	NotBefore int64           `json:"nbf,omitempty"`
	IssuedAt  int64           `json:"iat,omitempty"`
}

func LoadOIDCAuthenticator(path string) (*OIDCAuthenticator, error) {
	if path == "" {
		return nil, fmt.Errorf("oidc config file is required")
	}
	if err := validatePrivateAuthFile(path, "oidc config file"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read oidc config file: %w", err)
	}
	var config OIDCConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("decode oidc config file: %w", err)
	}
	return NewOIDCAuthenticator(config)
}

func NewOIDCAuthenticator(config OIDCConfig) (*OIDCAuthenticator, error) {
	if strings.TrimSpace(config.Issuer) == "" {
		return nil, fmt.Errorf("oidc issuer is required")
	}
	if strings.TrimSpace(config.Audience) == "" {
		return nil, fmt.Errorf("oidc audience is required")
	}
	if config.HMACSecret == "" {
		return nil, fmt.Errorf("oidc hmac secret is required")
	}
	return &OIDCAuthenticator{
		issuer:     strings.TrimSpace(config.Issuer),
		audience:   strings.TrimSpace(config.Audience),
		hmacSecret: []byte(config.HMACSecret),
	}, nil
}

func (a *OIDCAuthenticator) AuthenticateIDToken(raw string, now time.Time) (Subject, bool, error) {
	if a == nil {
		return Subject{}, false, fmt.Errorf("oidc authenticator is not configured")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Subject{}, false, fmt.Errorf("oidc id token is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Subject{}, false, fmt.Errorf("oidc id token must have three jwt segments")
	}
	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return Subject{}, false, fmt.Errorf("decode oidc header: %w", err)
	}
	var header oidcHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Subject{}, false, fmt.Errorf("decode oidc header json: %w", err)
	}
	if header.Algorithm != "HS256" {
		return Subject{}, false, fmt.Errorf("unsupported oidc id token alg %q", header.Algorithm)
	}

	signature, err := decodeJWTPart(parts[2])
	if err != nil {
		return Subject{}, false, fmt.Errorf("decode oidc signature: %w", err)
	}
	if !hmac.Equal(signature, signHS256(parts[0]+"."+parts[1], a.hmacSecret)) {
		return Subject{}, false, nil
	}

	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return Subject{}, false, fmt.Errorf("decode oidc payload: %w", err)
	}
	var claims oidcClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return Subject{}, false, fmt.Errorf("decode oidc payload json: %w", err)
	}
	if claims.Issuer != a.issuer {
		return Subject{}, false, nil
	}
	audienceOK, err := oidcAudienceContains(claims.Audience, a.audience)
	if err != nil {
		return Subject{}, false, err
	}
	if !audienceOK {
		return Subject{}, false, nil
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return Subject{}, false, fmt.Errorf("oidc subject is required")
	}
	if strings.TrimSpace(claims.TenantID) == "" {
		return Subject{}, false, fmt.Errorf("oidc tenant_id is required")
	}
	if len(claims.Roles) == 0 {
		return Subject{}, false, fmt.Errorf("oidc roles are required")
	}
	unixNow := now.UTC().Unix()
	if claims.ExpiresAt <= unixNow {
		return Subject{}, false, nil
	}
	if claims.NotBefore > 0 && unixNow < claims.NotBefore {
		return Subject{}, false, nil
	}
	return Subject{
		ID:       claims.Subject,
		TenantID: claims.TenantID,
		Roles:    append([]Role(nil), claims.Roles...),
	}, true, nil
}

func decodeJWTPart(raw string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(raw)
}

func oidcAudienceContains(raw json.RawMessage, want string) (bool, error) {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return false, fmt.Errorf("oidc audience must be a string or string array: %w", err)
	}
	for _, audience := range many {
		if audience == want {
			return true, nil
		}
	}
	return false, nil
}

func signHS256(input string, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return mac.Sum(nil)
}
