package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

type Identity struct {
	TenantID string
	DeviceID string
	Role     string
}

func (i Identity) commonName() string {
	return fmt.Sprintf("%s:%s:%s", i.TenantID, i.Role, i.DeviceID)
}

type Record struct {
	Serial    string    `json:"serial"`
	TenantID  string    `json:"tenant_id"`
	DeviceID  string    `json:"device_id"`
	Role      string    `json:"role"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	CertPEM   []byte    `json:"cert_pem"`
}

type Issued struct {
	Record        Record `json:"record"`
	PrivateKeyPEM []byte `json:"private_key_pem"`
}

type AuthorityBundle struct {
	CertificatePEM []byte `json:"certificate_pem"`
	PrivateKeyPEM  []byte `json:"private_key_pem"`
}

type RevocationList struct {
	TenantID    string    `json:"tenant_id"`
	Issuer      string    `json:"issuer"`
	GeneratedAt time.Time `json:"generated_at"`
	NextUpdate  time.Time `json:"next_update"`
	Records     []Record  `json:"records"`
	CRLPEM      []byte    `json:"crl_pem"`
}

type CertificateState string

const (
	CertificateGood        CertificateState = "good"
	CertificateRevoked     CertificateState = "revoked"
	CertificateExpired     CertificateState = "expired"
	CertificateNotYetValid CertificateState = "not_yet_valid"
	CertificateUnknown     CertificateState = "unknown"
)

type CertificateStatus struct {
	TenantID  string           `json:"tenant_id"`
	Serial    string           `json:"serial"`
	State     CertificateState `json:"state"`
	Revoked   bool             `json:"revoked"`
	RevokedAt time.Time        `json:"revoked_at,omitempty"`
	NotBefore time.Time        `json:"not_before,omitempty"`
	NotAfter  time.Time        `json:"not_after,omitempty"`
	CheckedAt time.Time        `json:"checked_at"`
}

type Authority struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	issued  map[string]Record
}

func NewAuthority(name string, now time.Time) (*Authority, error) {
	if name == "" {
		return nil, fmt.Errorf("authority name is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	keyID, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          keyID,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}
	parsedCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca certificate: %w", err)
	}

	return &Authority{
		cert:    parsedCert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		issued:  make(map[string]Record),
	}, nil
}

func NewAuthorityFromPEM(certPEM, keyPEM []byte) (*Authority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("authority certificate PEM is required")
	}
	parsedCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse authority certificate: %w", err)
	}
	if !parsedCert.IsCA {
		return nil, fmt.Errorf("authority certificate must be a CA")
	}
	if len(parsedCert.SubjectKeyId) == 0 {
		keyID, err := subjectKeyID(parsedCert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("derive authority subject key id: %w", err)
		}
		parsedCert.SubjectKeyId = keyID
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("authority EC private key PEM is required")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse authority private key: %w", err)
	}
	certPublicKey, ok := parsedCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("authority certificate must use an EC public key")
	}
	if certPublicKey.X.Cmp(key.X) != 0 || certPublicKey.Y.Cmp(key.Y) != 0 {
		return nil, fmt.Errorf("authority certificate does not match private key")
	}
	return &Authority{
		cert:    parsedCert,
		key:     key,
		certPEM: append([]byte(nil), certPEM...),
		issued:  make(map[string]Record),
	}, nil
}

func (a *Authority) CAPEM() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return append([]byte(nil), a.certPEM...)
}

func (a *Authority) ExportCA() (AuthorityBundle, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	keyBytes, err := x509.MarshalECPrivateKey(a.key)
	if err != nil {
		return AuthorityBundle{}, fmt.Errorf("marshal authority private key: %w", err)
	}
	return AuthorityBundle{
		CertificatePEM: append([]byte(nil), a.certPEM...),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	}, nil
}

func (a *Authority) Issue(identity Identity, ttl time.Duration, now time.Time) (Issued, error) {
	if identity.TenantID == "" {
		return Issued{}, fmt.Errorf("tenant id is required")
	}
	if identity.DeviceID == "" {
		return Issued{}, fmt.Errorf("device id is required")
	}
	if identity.Role == "" {
		return Issued{}, fmt.Errorf("role is required")
	}
	if ttl <= 0 {
		return Issued{}, fmt.Errorf("ttl must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Issued{}, fmt.Errorf("generate device key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Issued{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: identity.commonName(),
		},
		NotBefore: now,
		NotAfter:  now.Add(ttl),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return Issued{}, fmt.Errorf("create device certificate: %w", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return Issued{}, fmt.Errorf("marshal private key: %w", err)
	}
	record := Record{
		Serial:    serial.String(),
		TenantID:  identity.TenantID,
		DeviceID:  identity.DeviceID,
		Role:      identity.Role,
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
	a.issued[record.Serial] = record
	return Issued{
		Record:        record,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	}, nil
}

func (a *Authority) Revoke(serial string, now time.Time) (Record, error) {
	if serial == "" {
		return Record{}, fmt.Errorf("serial is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	record, exists := a.issued[serial]
	if !exists {
		return Record{}, fmt.Errorf("certificate %q not found", serial)
	}
	record.Revoked = true
	record.RevokedAt = now
	a.issued[serial] = record
	return record, nil
}

func (a *Authority) Rotate(serial string, ttl time.Duration, now time.Time) (Issued, error) {
	if serial == "" {
		return Issued{}, fmt.Errorf("serial is required")
	}
	if ttl <= 0 {
		return Issued{}, fmt.Errorf("ttl must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	a.mu.Lock()
	record, exists := a.issued[serial]
	if !exists {
		a.mu.Unlock()
		return Issued{}, fmt.Errorf("certificate %q not found", serial)
	}
	if record.Revoked {
		a.mu.Unlock()
		return Issued{}, fmt.Errorf("certificate %q is already revoked", serial)
	}
	record.Revoked = true
	record.RevokedAt = now
	a.issued[serial] = record
	a.mu.Unlock()

	return a.Issue(Identity{
		TenantID: record.TenantID,
		DeviceID: record.DeviceID,
		Role:     record.Role,
	}, ttl, now)
}

func (a *Authority) Record(serial string) (Record, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	record, exists := a.issued[serial]
	return record, exists
}

func (a *Authority) CertificateStatus(tenantID, serial string, now time.Time) (CertificateStatus, error) {
	if tenantID == "" {
		return CertificateStatus{}, fmt.Errorf("tenant id is required")
	}
	if serial == "" {
		return CertificateStatus{}, fmt.Errorf("serial is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	a.mu.RLock()
	record, exists := a.issued[serial]
	a.mu.RUnlock()
	if !exists || record.TenantID != tenantID {
		return CertificateStatus{
			TenantID:  tenantID,
			Serial:    serial,
			State:     CertificateUnknown,
			CheckedAt: now,
		}, nil
	}
	status := CertificateStatus{
		TenantID:  tenantID,
		Serial:    serial,
		NotBefore: record.NotBefore,
		NotAfter:  record.NotAfter,
		Revoked:   record.Revoked,
		RevokedAt: record.RevokedAt,
		CheckedAt: now,
	}
	switch {
	case record.Revoked:
		status.State = CertificateRevoked
	case now.Before(record.NotBefore):
		status.State = CertificateNotYetValid
	case now.After(record.NotAfter):
		status.State = CertificateExpired
	default:
		status.State = CertificateGood
	}
	return status, nil
}

func (a *Authority) RecordsByTenant(tenantID string) []Record {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var records []Record
	for _, record := range a.issued {
		if record.TenantID == tenantID {
			records = append(records, record)
		}
	}
	sortRecords(records)
	return records
}

func (a *Authority) RevokedRecordsByTenant(tenantID string) []Record {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var records []Record
	for _, record := range a.issued {
		if record.TenantID == tenantID && record.Revoked {
			records = append(records, record)
		}
	}
	sortRecords(records)
	return records
}

func (a *Authority) RevocationListByTenant(tenantID string, now time.Time, ttl time.Duration) (RevocationList, error) {
	if tenantID == "" {
		return RevocationList{}, fmt.Errorf("tenant id is required")
	}
	if ttl <= 0 {
		return RevocationList{}, fmt.Errorf("ttl must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	records := make([]Record, 0)
	revokedCertificates := make([]pkix.RevokedCertificate, 0)
	for _, record := range a.issued {
		if record.TenantID != tenantID || !record.Revoked {
			continue
		}
		serial, ok := new(big.Int).SetString(record.Serial, 10)
		if !ok {
			return RevocationList{}, fmt.Errorf("certificate serial %q is not a base-10 integer", record.Serial)
		}
		records = append(records, record)
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: record.RevokedAt,
		})
	}
	sortRecords(records)
	sort.Slice(revokedCertificates, func(i, j int) bool {
		return revokedCertificates[i].SerialNumber.Cmp(revokedCertificates[j].SerialNumber) < 0
	})

	nextUpdate := now.Add(ttl)
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm:  a.cert.SignatureAlgorithm,
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(now.Unix()),
		ThisUpdate:          now,
		NextUpdate:          nextUpdate,
	}, a.cert, a.key)
	if err != nil {
		return RevocationList{}, fmt.Errorf("create certificate revocation list: %w", err)
	}

	return RevocationList{
		TenantID:    tenantID,
		Issuer:      a.cert.Subject.CommonName,
		GeneratedAt: now,
		NextUpdate:  nextUpdate,
		Records:     records,
		CRLPEM:      pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes}),
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func subjectKeyID(publicKey interface{}) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha1.Sum(encoded)
	return append([]byte(nil), sum[:]...), nil
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i, j int) bool {
		return records[i].Serial < records[j].Serial
	})
}
