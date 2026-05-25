package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type OCSPResponseStatus int

const (
	OCSPSuccessful      OCSPResponseStatus = 0
	OCSPMalformed       OCSPResponseStatus = 1
	OCSPInternalError   OCSPResponseStatus = 2
	OCSPTryLater        OCSPResponseStatus = 3
	OCSPSignatureNeeded OCSPResponseStatus = 5
	OCSPUnauthorized    OCSPResponseStatus = 6
)

var (
	oidSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidOCSPBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
)

type OCSPRequest struct {
	Serial       string
	SerialNumber *big.Int
	certID       ocspCertID
}

type ParsedOCSPResponse struct {
	Status            OCSPResponseStatus
	CertificateStatus CertificateState
	Serial            string
	ProducedAt        time.Time
	ThisUpdate        time.Time
	NextUpdate        time.Time
	RevokedAt         time.Time
}

type ocspAlgorithmIdentifier = pkix.AlgorithmIdentifier

type ocspCertID struct {
	HashAlgorithm ocspAlgorithmIdentifier
	IssuerName    []byte
	IssuerKey     []byte
	SerialNumber  *big.Int
}

type ocspRequestASN1 struct {
	TBSRequest ocspTBSRequest
}

type ocspTBSRequest struct {
	Version           int           `asn1:"explicit,tag:0,optional,default:0"`
	RequestorName     asn1.RawValue `asn1:"explicit,tag:1,optional"`
	RequestList       []ocspRequest1
	RequestExtensions asn1.RawValue `asn1:"explicit,tag:2,optional"`
}

type ocspRequest1 struct {
	ReqCert                 ocspCertID
	SingleRequestExtensions asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspSuccessResponseASN1 struct {
	Status        int `asn1:"enumerated"`
	ResponseBytes asn1.RawValue
}

type ocspErrorResponseASN1 struct {
	Status int `asn1:"enumerated"`
}

type ocspResponseASN1 struct {
	Status        int           `asn1:"enumerated"`
	ResponseBytes asn1.RawValue `asn1:"optional"`
}

type ocspBasicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm ocspAlgorithmIdentifier
	Signature          asn1.BitString
}

type ocspResponseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingleResponse
}

type ocspSingleResponse struct {
	CertID     ocspCertID
	CertStatus asn1.RawValue
	ThisUpdate time.Time `asn1:"generalized"`
	NextUpdate time.Time `asn1:"explicit,tag:0,optional,generalized"`
}

type ocspRevokedInfo struct {
	RevocationTime time.Time `asn1:"generalized"`
}

type ocspSubjectPublicKeyInfo struct {
	Algorithm        ocspAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func NewOCSPRequest(certificate, issuer *x509.Certificate) ([]byte, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if issuer == nil {
		return nil, fmt.Errorf("issuer certificate is required")
	}
	certID, err := newOCSPCertID(issuer, certificate.SerialNumber)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ocspRequestASN1{
		TBSRequest: ocspTBSRequest{
			RequestList: []ocspRequest1{{ReqCert: certID}},
		},
	})
}

func ParseOCSPRequestDER(der []byte) (OCSPRequest, error) {
	if len(der) == 0 {
		return OCSPRequest{}, fmt.Errorf("OCSP request is required")
	}
	var parsed ocspRequestASN1
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return OCSPRequest{}, fmt.Errorf("parse OCSP request: %w", err)
	}
	if len(rest) != 0 {
		return OCSPRequest{}, fmt.Errorf("parse OCSP request: trailing data")
	}
	if len(parsed.TBSRequest.RequestList) != 1 {
		return OCSPRequest{}, fmt.Errorf("OCSP request must contain exactly one certificate request")
	}
	certID := parsed.TBSRequest.RequestList[0].ReqCert
	if certID.SerialNumber == nil {
		return OCSPRequest{}, fmt.Errorf("OCSP request serial number is required")
	}
	if !certID.HashAlgorithm.Algorithm.Equal(oidSHA1) {
		return OCSPRequest{}, fmt.Errorf("OCSP request hash algorithm %s is not supported", certID.HashAlgorithm.Algorithm.String())
	}
	if len(certID.IssuerName) == 0 || len(certID.IssuerKey) == 0 {
		return OCSPRequest{}, fmt.Errorf("OCSP request issuer hashes are required")
	}
	return OCSPRequest{
		Serial:       certID.SerialNumber.String(),
		SerialNumber: new(big.Int).Set(certID.SerialNumber),
		certID:       cloneOCSPCertID(certID),
	}, nil
}

func (r *StatusResponder) RespondOCSPDER(tenantID string, requestDER []byte, now time.Time) ([]byte, error) {
	if r == nil || r.authority == nil {
		return nil, fmt.Errorf("authority is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	if r.maxAge < time.Second || r.maxAge%time.Second != 0 {
		return nil, fmt.Errorf("status max age must be whole seconds and at least one second")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	request, err := ParseOCSPRequestDER(requestDER)
	if err != nil {
		return NewOCSPErrorResponse(OCSPMalformed)
	}

	r.authority.mu.RLock()
	issuer := r.authority.cert
	key := r.authority.key
	expectedCertID, certIDErr := newOCSPCertID(issuer, request.SerialNumber)
	r.authority.mu.RUnlock()
	if certIDErr != nil {
		return nil, certIDErr
	}
	if !sameOCSPCertIssuer(request.certID, expectedCertID) {
		return NewOCSPErrorResponse(OCSPUnauthorized)
	}

	status, err := r.authority.CertificateStatus(tenantID, request.Serial, now)
	if err != nil {
		return nil, err
	}
	return newOCSPSuccessResponse(request.certID, status, issuer, key, now, now.Add(r.maxAge))
}

func (r *StatusResponder) ServeOCSPHTTP(tenantID string, w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer req.Body.Close()
	requestDER, err := io.ReadAll(req.Body)
	if err != nil {
		writeStatusResponderError(w, http.StatusBadRequest, fmt.Errorf("read OCSP request: %w", err))
		return
	}
	responseDER, err := r.RespondOCSPDER(tenantID, requestDER, r.now())
	if err != nil {
		writeStatusResponderError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(r.maxAge/time.Second)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseDER)
}

func NewOCSPErrorResponse(status OCSPResponseStatus) ([]byte, error) {
	return asn1.Marshal(ocspErrorResponseASN1{Status: int(status)})
}

func ParseOCSPResponseDER(der []byte) (ParsedOCSPResponse, error) {
	var response ocspResponseASN1
	rest, err := asn1.Unmarshal(der, &response)
	if err != nil {
		return ParsedOCSPResponse{}, fmt.Errorf("parse OCSP response: %w", err)
	}
	if len(rest) != 0 {
		return ParsedOCSPResponse{}, fmt.Errorf("parse OCSP response: trailing data")
	}
	parsed := ParsedOCSPResponse{Status: OCSPResponseStatus(response.Status)}
	if parsed.Status != OCSPSuccessful {
		return parsed, nil
	}
	responseBytes, err := parseOCSPResponseBytes(response.ResponseBytes)
	if err != nil {
		return ParsedOCSPResponse{}, err
	}
	basic, err := parseOCSPBasicResponse(responseBytes.Response)
	if err != nil {
		return ParsedOCSPResponse{}, err
	}
	data, err := parseOCSPResponseData(basic.TBSResponseData)
	if err != nil {
		return ParsedOCSPResponse{}, err
	}
	if len(data.Responses) != 1 {
		return ParsedOCSPResponse{}, fmt.Errorf("OCSP response must contain exactly one single response")
	}
	single := data.Responses[0]
	certificateStatus, revokedAt, err := parseOCSPCertStatus(single.CertStatus)
	if err != nil {
		return ParsedOCSPResponse{}, err
	}
	parsed.CertificateStatus = certificateStatus
	parsed.Serial = single.CertID.SerialNumber.String()
	parsed.ProducedAt = data.ProducedAt
	parsed.ThisUpdate = single.ThisUpdate
	parsed.NextUpdate = single.NextUpdate
	parsed.RevokedAt = revokedAt
	return parsed, nil
}

func VerifyOCSPResponseSignature(der []byte, issuer *x509.Certificate) error {
	if issuer == nil {
		return fmt.Errorf("issuer certificate is required")
	}
	responseBytes, err := parseSuccessfulOCSPResponseBytes(der)
	if err != nil {
		return err
	}
	basic, err := parseOCSPBasicResponse(responseBytes.Response)
	if err != nil {
		return err
	}
	if !basic.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA256) {
		return fmt.Errorf("OCSP signature algorithm %s is not supported", basic.SignatureAlgorithm.Algorithm.String())
	}
	publicKey, ok := issuer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("issuer certificate must use an EC public key")
	}
	digest := sha256.Sum256(basic.TBSResponseData.FullBytes)
	if !ecdsa.VerifyASN1(publicKey, digest[:], basic.Signature.RightAlign()) {
		return fmt.Errorf("OCSP response signature verification failed")
	}
	return nil
}

func newOCSPSuccessResponse(certID ocspCertID, status CertificateStatus, issuer *x509.Certificate, key *ecdsa.PrivateKey, producedAt, nextUpdate time.Time) ([]byte, error) {
	if issuer == nil || key == nil {
		return nil, fmt.Errorf("authority certificate and key are required")
	}
	producedAt = producedAt.UTC()
	nextUpdate = nextUpdate.UTC()
	certStatus, err := newOCSPCertStatus(status)
	if err != nil {
		return nil, err
	}
	responderID, err := newOCSPResponderIDByKey(issuer)
	if err != nil {
		return nil, err
	}
	tbsDER, err := asn1.Marshal(ocspResponseData{
		ResponderID: responderID,
		ProducedAt:  producedAt,
		Responses: []ocspSingleResponse{{
			CertID:     cloneOCSPCertID(certID),
			CertStatus: certStatus,
			ThisUpdate: producedAt,
			NextUpdate: nextUpdate,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("encode OCSP response data: %w", err)
	}
	digest := sha256.Sum256(tbsDER)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign OCSP response: %w", err)
	}
	basicDER, err := asn1.Marshal(ocspBasicResponse{
		TBSResponseData: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: ocspAlgorithmIdentifier{
			Algorithm: oidECDSAWithSHA256,
		},
		Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("encode OCSP basic response: %w", err)
	}
	responseBytesDER, err := asn1.Marshal(ocspResponseBytes{
		ResponseType: oidOCSPBasicResponse,
		Response:     basicDER,
	})
	if err != nil {
		return nil, fmt.Errorf("encode OCSP response bytes: %w", err)
	}
	return asn1.Marshal(ocspSuccessResponseASN1{
		Status: int(OCSPSuccessful),
		ResponseBytes: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      responseBytesDER,
		},
	})
}

func newOCSPCertStatus(status CertificateStatus) (asn1.RawValue, error) {
	switch status.State {
	case CertificateRevoked:
		if status.RevokedAt.IsZero() {
			return asn1.RawValue{}, fmt.Errorf("revoked OCSP status requires revoked_at")
		}
		revokedDER, err := asn1.Marshal(ocspRevokedInfo{RevocationTime: status.RevokedAt.UTC()})
		if err != nil {
			return asn1.RawValue{}, fmt.Errorf("encode OCSP revoked info: %w", err)
		}
		content, err := asn1Content(revokedDER)
		if err != nil {
			return asn1.RawValue{}, err
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: content}, nil
	case CertificateUnknown:
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2}, nil
	case CertificateGood, CertificateExpired, CertificateNotYetValid:
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}, nil
	default:
		return asn1.RawValue{}, fmt.Errorf("unknown certificate state %q", status.State)
	}
}

func parseOCSPCertStatus(raw asn1.RawValue) (CertificateState, time.Time, error) {
	if raw.Class != asn1.ClassContextSpecific {
		return "", time.Time{}, fmt.Errorf("OCSP cert status must be context-specific")
	}
	switch raw.Tag {
	case 0:
		return CertificateGood, time.Time{}, nil
	case 1:
		var revoked ocspRevokedInfo
		if _, err := asn1.Unmarshal(wrapASN1Sequence(raw.Bytes), &revoked); err != nil {
			return "", time.Time{}, fmt.Errorf("parse OCSP revoked info: %w", err)
		}
		return CertificateRevoked, revoked.RevocationTime, nil
	case 2:
		return CertificateUnknown, time.Time{}, nil
	default:
		return "", time.Time{}, fmt.Errorf("unsupported OCSP cert status tag %d", raw.Tag)
	}
}

func newOCSPCertID(issuer *x509.Certificate, serial *big.Int) (ocspCertID, error) {
	if issuer == nil {
		return ocspCertID{}, fmt.Errorf("issuer certificate is required")
	}
	if serial == nil {
		return ocspCertID{}, fmt.Errorf("certificate serial number is required")
	}
	nameHash := sha1.Sum(issuer.RawSubject)
	keyBytes, err := issuerPublicKeyBytes(issuer)
	if err != nil {
		return ocspCertID{}, err
	}
	keyHash := sha1.Sum(keyBytes)
	return ocspCertID{
		HashAlgorithm: ocspAlgorithmIdentifier{
			Algorithm:  oidSHA1,
			Parameters: asn1.NullRawValue,
		},
		IssuerName:   append([]byte(nil), nameHash[:]...),
		IssuerKey:    append([]byte(nil), keyHash[:]...),
		SerialNumber: new(big.Int).Set(serial),
	}, nil
}

func newOCSPResponderIDByKey(issuer *x509.Certificate) (asn1.RawValue, error) {
	keyBytes, err := issuerPublicKeyBytes(issuer)
	if err != nil {
		return asn1.RawValue{}, err
	}
	keyHash := sha1.Sum(keyBytes)
	keyHashDER, err := asn1.Marshal(keyHash[:])
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("encode OCSP responder key hash: %w", err)
	}
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        2,
		IsCompound: true,
		Bytes:      keyHashDER,
	}, nil
}

func issuerPublicKeyBytes(issuer *x509.Certificate) ([]byte, error) {
	var spki ocspSubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("parse issuer public key info: %w", err)
	}
	return spki.SubjectPublicKey.RightAlign(), nil
}

func sameOCSPCertIssuer(a, b ocspCertID) bool {
	return a.HashAlgorithm.Algorithm.Equal(b.HashAlgorithm.Algorithm) &&
		string(a.IssuerName) == string(b.IssuerName) &&
		string(a.IssuerKey) == string(b.IssuerKey)
}

func cloneOCSPCertID(certID ocspCertID) ocspCertID {
	var serial *big.Int
	if certID.SerialNumber != nil {
		serial = new(big.Int).Set(certID.SerialNumber)
	}
	return ocspCertID{
		HashAlgorithm: certID.HashAlgorithm,
		IssuerName:    append([]byte(nil), certID.IssuerName...),
		IssuerKey:     append([]byte(nil), certID.IssuerKey...),
		SerialNumber:  serial,
	}
}

func parseSuccessfulOCSPResponseBytes(der []byte) (ocspResponseBytes, error) {
	var response ocspResponseASN1
	rest, err := asn1.Unmarshal(der, &response)
	if err != nil {
		return ocspResponseBytes{}, fmt.Errorf("parse OCSP response: %w", err)
	}
	if len(rest) != 0 {
		return ocspResponseBytes{}, fmt.Errorf("parse OCSP response: trailing data")
	}
	if OCSPResponseStatus(response.Status) != OCSPSuccessful {
		return ocspResponseBytes{}, fmt.Errorf("OCSP response status is %d", response.Status)
	}
	return parseOCSPResponseBytes(response.ResponseBytes)
}

func parseOCSPResponseBytes(raw asn1.RawValue) (ocspResponseBytes, error) {
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return ocspResponseBytes{}, fmt.Errorf("OCSP successful response is missing response bytes")
	}
	var responseBytes ocspResponseBytes
	rest, err := asn1.Unmarshal(raw.Bytes, &responseBytes)
	if err != nil {
		return ocspResponseBytes{}, fmt.Errorf("parse OCSP response bytes: %w", err)
	}
	if len(rest) != 0 {
		return ocspResponseBytes{}, fmt.Errorf("parse OCSP response bytes: trailing data")
	}
	if !responseBytes.ResponseType.Equal(oidOCSPBasicResponse) {
		return ocspResponseBytes{}, fmt.Errorf("OCSP response type %s is not basic OCSP", responseBytes.ResponseType.String())
	}
	return responseBytes, nil
}

func parseOCSPBasicResponse(der []byte) (ocspBasicResponse, error) {
	var basic ocspBasicResponse
	rest, err := asn1.Unmarshal(der, &basic)
	if err != nil {
		return ocspBasicResponse{}, fmt.Errorf("parse OCSP basic response: %w", err)
	}
	if len(rest) != 0 {
		return ocspBasicResponse{}, fmt.Errorf("parse OCSP basic response: trailing data")
	}
	return basic, nil
}

func parseOCSPResponseData(raw asn1.RawValue) (ocspResponseData, error) {
	var data ocspResponseData
	rest, err := asn1.Unmarshal(raw.FullBytes, &data)
	if err != nil {
		return ocspResponseData{}, fmt.Errorf("parse OCSP response data: %w", err)
	}
	if len(rest) != 0 {
		return ocspResponseData{}, fmt.Errorf("parse OCSP response data: trailing data")
	}
	return data, nil
}

func asn1Content(der []byte) ([]byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("parse ASN.1 value: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("parse ASN.1 value: trailing data")
	}
	return raw.Bytes, nil
}

func wrapASN1Sequence(content []byte) []byte {
	return append(append([]byte{0x30}, derLength(len(content))...), content...)
}

func derLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	length := len(buf) - i
	out := []byte{0x80 | byte(length)}
	return append(out, buf[i:]...)
}
