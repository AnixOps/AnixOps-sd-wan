package cert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type PublishedRevocationList struct {
	TenantID     string    `json:"tenant_id"`
	Issuer       string    `json:"issuer"`
	GeneratedAt  time.Time `json:"generated_at"`
	NextUpdate   time.Time `json:"next_update"`
	RevokedCount int       `json:"revoked_count"`
	SHA256       string    `json:"sha256"`
	CRLPath      string    `json:"crl_path"`
	ManifestPath string    `json:"manifest_path"`
}

type VerifiedPublishedRevocationList struct {
	Manifest PublishedRevocationList `json:"manifest"`
	CRLPEM   []byte                  `json:"crl_pem"`
	Parsed   *x509.RevocationList    `json:"-"`
}

type RevocationListPublisher interface {
	PublishRevocationList(context.Context, RevocationList) (PublishedRevocationList, error)
}

type FileRevocationListPublisher struct {
	Dir string
}

func NewFileRevocationListPublisher(dir string) (*FileRevocationListPublisher, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("crl publish directory is required")
	}
	return &FileRevocationListPublisher{Dir: dir}, nil
}

func (p *FileRevocationListPublisher) PublishRevocationList(ctx context.Context, list RevocationList) (PublishedRevocationList, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return PublishedRevocationList{}, err
	}
	if strings.TrimSpace(p.Dir) == "" {
		return PublishedRevocationList{}, fmt.Errorf("crl publish directory is required")
	}
	if _, err := ParseRevocationListPEM(list.CRLPEM); err != nil {
		return PublishedRevocationList{}, err
	}
	fileName, err := tenantCRLFileName(list.TenantID)
	if err != nil {
		return PublishedRevocationList{}, err
	}
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return PublishedRevocationList{}, fmt.Errorf("create crl publish directory: %w", err)
	}

	crlPath := filepath.Join(p.Dir, fileName+".pem")
	manifestPath := filepath.Join(p.Dir, fileName+".json")
	sum := sha256.Sum256(list.CRLPEM)
	published := PublishedRevocationList{
		TenantID:     list.TenantID,
		Issuer:       list.Issuer,
		GeneratedAt:  list.GeneratedAt,
		NextUpdate:   list.NextUpdate,
		RevokedCount: len(list.Records),
		SHA256:       hex.EncodeToString(sum[:]),
		CRLPath:      crlPath,
		ManifestPath: manifestPath,
	}

	if err := os.WriteFile(crlPath, list.CRLPEM, 0o644); err != nil {
		return PublishedRevocationList{}, fmt.Errorf("write crl pem: %w", err)
	}
	manifest, err := json.MarshalIndent(published, "", "  ")
	if err != nil {
		return PublishedRevocationList{}, fmt.Errorf("marshal crl manifest: %w", err)
	}
	manifest = append(manifest, '\n')
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		return PublishedRevocationList{}, fmt.Errorf("write crl manifest: %w", err)
	}
	return published, nil
}

func ParseRevocationListPEM(crlPEM []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("X509 CRL PEM is required")
	}
	parsed, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse X509 CRL: %w", err)
	}
	return parsed, nil
}

func VerifyPublishedRevocationList(dir, tenantID string) (VerifiedPublishedRevocationList, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl publish directory is required")
	}
	fileName, err := tenantCRLFileName(tenantID)
	if err != nil {
		return VerifiedPublishedRevocationList{}, err
	}
	crlPath := filepath.Join(dir, fileName+".pem")
	manifestPath := filepath.Join(dir, fileName+".json")

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("read crl manifest: %w", err)
	}
	crlPEM, err := os.ReadFile(crlPath)
	if err != nil {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("read crl pem: %w", err)
	}
	return verifyPublishedRevocationListArtifacts(tenantID, crlPath, manifestPath, manifestData, crlPEM)
}

func VerifyPublishedRevocationListHTTP(ctx context.Context, client *http.Client, baseURL, tenantID string) (VerifiedPublishedRevocationList, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl base url is required")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl base url must be absolute")
	}
	fileName, err := tenantCRLFileName(tenantID)
	if err != nil {
		return VerifiedPublishedRevocationList{}, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	crlURL := joinArtifactURL(parsedBase, fileName+".pem")
	manifestURL := joinArtifactURL(parsedBase, fileName+".json")
	manifestData, err := fetchCRLArtifact(ctx, client, manifestURL)
	if err != nil {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("fetch crl manifest: %w", err)
	}
	crlPEM, err := fetchCRLArtifact(ctx, client, crlURL)
	if err != nil {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("fetch crl pem: %w", err)
	}
	return verifyPublishedRevocationListArtifacts(tenantID, crlURL, manifestURL, manifestData, crlPEM)
}

func verifyPublishedRevocationListArtifacts(tenantID, expectedCRLPath, expectedManifestPath string, manifestData, crlPEM []byte) (VerifiedPublishedRevocationList, error) {
	var manifest PublishedRevocationList
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("decode crl manifest: %w", err)
	}
	if manifest.TenantID != strings.TrimSpace(tenantID) {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl manifest tenant %q does not match requested tenant %q", manifest.TenantID, tenantID)
	}
	if artifactBase(manifest.CRLPath) != artifactBase(expectedCRLPath) {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl manifest path %q does not match expected %q", manifest.CRLPath, expectedCRLPath)
	}
	if artifactBase(manifest.ManifestPath) != artifactBase(expectedManifestPath) {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl manifest self path %q does not match expected %q", manifest.ManifestPath, expectedManifestPath)
	}

	sum := sha256.Sum256(crlPEM)
	if manifest.SHA256 != hex.EncodeToString(sum[:]) {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl sha256 mismatch")
	}
	parsed, err := ParseRevocationListPEM(crlPEM)
	if err != nil {
		return VerifiedPublishedRevocationList{}, err
	}
	if manifest.RevokedCount != parsedRevokedCount(parsed) {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl revoked count %d does not match manifest %d", parsedRevokedCount(parsed), manifest.RevokedCount)
	}
	if !manifest.NextUpdate.IsZero() && !parsed.NextUpdate.IsZero() && !parsed.NextUpdate.Equal(manifest.NextUpdate) {
		return VerifiedPublishedRevocationList{}, fmt.Errorf("crl next update %s does not match manifest %s", parsed.NextUpdate.Format(time.RFC3339), manifest.NextUpdate.Format(time.RFC3339))
	}
	return VerifiedPublishedRevocationList{
		Manifest: manifest,
		CRLPEM:   crlPEM,
		Parsed:   parsed,
	}, nil
}

func joinArtifactURL(base *url.URL, fileName string) string {
	joined := *base
	joined.Path = strings.TrimRight(joined.Path, "/") + "/" + fileName
	joined.RawQuery = ""
	joined.Fragment = ""
	return joined.String()
}

func fetchCRLArtifact(ctx context.Context, client *http.Client, artifactURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", artifactURL, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func artifactBase(pathOrURL string) string {
	parsed, err := url.Parse(pathOrURL)
	if err == nil && parsed.Scheme != "" && parsed.Path != "" {
		return path.Base(parsed.Path)
	}
	return filepath.Base(pathOrURL)
}

func parsedRevokedCount(parsed *x509.RevocationList) int {
	if parsed == nil {
		return 0
	}
	return len(parsed.RevokedCertificates)
}

func tenantCRLFileName(tenantID string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", fmt.Errorf("tenant id is required")
	}
	if tenantID == "." || tenantID == ".." {
		return "", fmt.Errorf("tenant id %q cannot be used as a crl file name", tenantID)
	}
	for _, r := range tenantID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", fmt.Errorf("tenant id %q contains characters unsafe for crl file names", tenantID)
	}
	return tenantID + ".crl", nil
}
