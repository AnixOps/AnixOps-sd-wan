package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOIDCAuthenticatorAuthenticatesIDToken(t *testing.T) {
	authenticator, err := NewOIDCAuthenticator(OIDCConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "anixops-control",
		HMACSecret: "secret",
	})
	if err != nil {
		t.Fatalf("new oidc authenticator: %v", err)
	}
	now := time.Unix(1700000000, 0).UTC()
	token := testOIDCIDToken(t, "secret", map[string]interface{}{
		"iss":       "https://idp.example.com",
		"aud":       []string{"other", "anixops-control"},
		"sub":       "admin-a",
		"tenant_id": "tenant-a",
		"roles":     []string{"admin"},
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})

	subject, ok, err := authenticator.AuthenticateIDToken(token, now)
	if err != nil {
		t.Fatalf("authenticate id token: %v", err)
	}
	if !ok {
		t.Fatal("expected id token to authenticate")
	}
	if subject.ID != "admin-a" || subject.TenantID != "tenant-a" || len(subject.Roles) != 1 || subject.Roles[0] != RoleAdmin {
		t.Fatalf("unexpected subject: %+v", subject)
	}
}

func TestOIDCAuthenticatorRejectsInvalidIDTokens(t *testing.T) {
	authenticator, err := NewOIDCAuthenticator(OIDCConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "anixops-control",
		HMACSecret: "secret",
	})
	if err != nil {
		t.Fatalf("new oidc authenticator: %v", err)
	}
	now := time.Unix(1700000000, 0).UTC()
	baseClaims := map[string]interface{}{
		"iss":       "https://idp.example.com",
		"aud":       "anixops-control",
		"sub":       "admin-a",
		"tenant_id": "tenant-a",
		"roles":     []string{"admin"},
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}

	wrongIssuer := cloneClaims(baseClaims)
	wrongIssuer["iss"] = "https://other-idp.example.com"
	assertOIDCDenied(t, authenticator, testOIDCIDToken(t, "secret", wrongIssuer), now)

	wrongAudience := cloneClaims(baseClaims)
	wrongAudience["aud"] = "other-audience"
	assertOIDCDenied(t, authenticator, testOIDCIDToken(t, "secret", wrongAudience), now)

	expired := cloneClaims(baseClaims)
	expired["exp"] = now.Add(-time.Minute).Unix()
	assertOIDCDenied(t, authenticator, testOIDCIDToken(t, "secret", expired), now)

	notYetValid := cloneClaims(baseClaims)
	notYetValid["nbf"] = now.Add(time.Minute).Unix()
	assertOIDCDenied(t, authenticator, testOIDCIDToken(t, "secret", notYetValid), now)

	badSignature := testOIDCIDToken(t, "wrong-secret", baseClaims)
	assertOIDCDenied(t, authenticator, badSignature, now)

	noneHeader := encodeJWTJSON(t, map[string]string{"alg": "none", "typ": "JWT"})
	payload := encodeJWTJSON(t, baseClaims)
	if _, ok, err := authenticator.AuthenticateIDToken(noneHeader+"."+payload+".", now); err == nil || ok {
		t.Fatalf("expected alg none token to fail, ok=%v err=%v", ok, err)
	}
}

func TestLoadOIDCAuthenticatorFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oidc.json")
	data, err := json.Marshal(OIDCConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "anixops-control",
		HMACSecret: "secret",
	})
	if err != nil {
		t.Fatalf("marshal oidc config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write oidc config: %v", err)
	}

	authenticator, err := LoadOIDCAuthenticator(path)
	if err != nil {
		t.Fatalf("load oidc authenticator: %v", err)
	}
	now := time.Unix(1700000000, 0).UTC()
	token := testOIDCIDToken(t, "secret", map[string]interface{}{
		"iss":       "https://idp.example.com",
		"aud":       "anixops-control",
		"sub":       "operator-a",
		"tenant_id": "tenant-a",
		"roles":     []string{"operator"},
		"exp":       now.Add(time.Hour).Unix(),
	})
	if _, ok, err := authenticator.AuthenticateIDToken(token, now); err != nil || !ok {
		t.Fatalf("expected loaded oidc authenticator to authenticate, ok=%v err=%v", ok, err)
	}
}

func TestLoadOIDCAuthenticatorRejectsOverlyPermissiveFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not reliable on Windows")
	}
	path := filepath.Join(t.TempDir(), "oidc.json")
	data, err := json.Marshal(OIDCConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "anixops-control",
		HMACSecret: "secret",
	})
	if err != nil {
		t.Fatalf("marshal oidc config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write oidc config: %v", err)
	}
	if _, err := LoadOIDCAuthenticator(path); err == nil {
		t.Fatal("expected overly permissive oidc config to be rejected")
	}
}

func assertOIDCDenied(t *testing.T, authenticator *OIDCAuthenticator, token string, now time.Time) {
	t.Helper()
	if _, ok, err := authenticator.AuthenticateIDToken(token, now); err != nil || ok {
		t.Fatalf("expected id token denial, ok=%v err=%v", ok, err)
	}
}

func testOIDCIDToken(t *testing.T, secret string, claims map[string]interface{}) string {
	t.Helper()
	header := encodeJWTJSON(t, map[string]string{"alg": "HS256", "typ": "JWT"})
	payload := encodeJWTJSON(t, claims)
	signingInput := header + "." + payload
	signature := base64.RawURLEncoding.EncodeToString(signHS256(signingInput, []byte(secret)))
	return signingInput + "." + signature
}

func encodeJWTJSON(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal jwt json: %v", err)
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(data), "=")
}

func cloneClaims(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
