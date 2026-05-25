package cert

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const DefaultStatusMaxAge = 5 * time.Minute

type StatusRequest struct {
	TenantID string `json:"tenant_id"`
	Serial   string `json:"serial"`
}

type StatusResponse struct {
	CertificateStatus
	ThisUpdate    time.Time `json:"this_update"`
	NextUpdate    time.Time `json:"next_update"`
	MaxAgeSeconds int       `json:"max_age_seconds"`
}

type StatusResponder struct {
	authority *Authority
	maxAge    time.Duration
	Clock     func() time.Time
}

func NewStatusResponder(authority *Authority, maxAge time.Duration) (*StatusResponder, error) {
	if authority == nil {
		return nil, fmt.Errorf("authority is required")
	}
	if maxAge < time.Second {
		return nil, fmt.Errorf("status max age must be at least one second")
	}
	if maxAge%time.Second != 0 {
		return nil, fmt.Errorf("status max age must use whole-second precision")
	}
	return &StatusResponder{
		authority: authority,
		maxAge:    maxAge,
	}, nil
}

func (r *StatusResponder) MaxAge() time.Duration {
	if r == nil {
		return 0
	}
	return r.maxAge
}

func (r *StatusResponder) Respond(request StatusRequest, now time.Time) (StatusResponse, error) {
	if r == nil || r.authority == nil {
		return StatusResponse{}, fmt.Errorf("authority is required")
	}
	if r.maxAge < time.Second || r.maxAge%time.Second != 0 {
		return StatusResponse{}, fmt.Errorf("status max age must be whole seconds and at least one second")
	}
	normalized, err := normalizeStatusRequest(request)
	if err != nil {
		return StatusResponse{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	status, err := r.authority.CertificateStatus(normalized.TenantID, normalized.Serial, now)
	if err != nil {
		return StatusResponse{}, err
	}
	return StatusResponse{
		CertificateStatus: status,
		ThisUpdate:        now,
		NextUpdate:        now.Add(r.maxAge),
		MaxAgeSeconds:     int(r.maxAge / time.Second),
	}, nil
}

func (r *StatusResponder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var request StatusRequest
	switch req.Method {
	case http.MethodGet:
		request = StatusRequest{
			TenantID: req.URL.Query().Get("tenant_id"),
			Serial:   req.URL.Query().Get("serial"),
		}
	case http.MethodPost:
		defer req.Body.Close()
		if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
			writeStatusResponderError(w, http.StatusBadRequest, fmt.Errorf("decode status request: %w", err))
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	response, err := r.Respond(request, r.now())
	if err != nil {
		writeStatusResponderError(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", response.MaxAgeSeconds))
	writeStatusResponderJSON(w, http.StatusOK, response)
}

func ValidateStatusResponse(response StatusResponse, request StatusRequest, at time.Time) error {
	normalized, err := normalizeStatusRequest(request)
	if err != nil {
		return err
	}
	if response.TenantID != normalized.TenantID {
		return fmt.Errorf("status tenant %q does not match request tenant %q", response.TenantID, normalized.TenantID)
	}
	if response.Serial != normalized.Serial {
		return fmt.Errorf("status serial %q does not match request serial %q", response.Serial, normalized.Serial)
	}
	if !validCertificateState(response.State) {
		return fmt.Errorf("unknown certificate state %q", response.State)
	}
	if response.ThisUpdate.IsZero() {
		return fmt.Errorf("status this_update is required")
	}
	if response.NextUpdate.IsZero() {
		return fmt.Errorf("status next_update is required")
	}
	if response.MaxAgeSeconds <= 0 {
		return fmt.Errorf("status max_age_seconds must be positive")
	}
	if !response.NextUpdate.After(response.ThisUpdate) {
		return fmt.Errorf("status next_update must be after this_update")
	}
	if want := response.ThisUpdate.Add(time.Duration(response.MaxAgeSeconds) * time.Second); !response.NextUpdate.Equal(want) {
		return fmt.Errorf("status next_update does not match max_age_seconds")
	}
	if response.CheckedAt.IsZero() {
		return fmt.Errorf("status checked_at is required")
	}
	if !response.CheckedAt.Equal(response.ThisUpdate) {
		return fmt.Errorf("status checked_at must match this_update")
	}
	if response.Revoked && response.State != CertificateRevoked {
		return fmt.Errorf("revoked status flag does not match state %q", response.State)
	}
	if response.State == CertificateRevoked && !response.Revoked {
		return fmt.Errorf("revoked state requires revoked flag")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	if response.ThisUpdate.After(at) {
		return fmt.Errorf("status this_update is in the future")
	}
	if !at.Before(response.NextUpdate) {
		return fmt.Errorf("status response is stale")
	}
	return nil
}

func (r *StatusResponder) now() time.Time {
	if r != nil && r.Clock != nil {
		return r.Clock()
	}
	return time.Now().UTC()
}

func normalizeStatusRequest(request StatusRequest) (StatusRequest, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Serial = strings.TrimSpace(request.Serial)
	if request.TenantID == "" {
		return StatusRequest{}, fmt.Errorf("tenant id is required")
	}
	if request.Serial == "" {
		return StatusRequest{}, fmt.Errorf("serial is required")
	}
	return request, nil
}

func validCertificateState(state CertificateState) bool {
	switch state {
	case CertificateGood, CertificateRevoked, CertificateExpired, CertificateNotYetValid, CertificateUnknown:
		return true
	default:
		return false
	}
}

func writeStatusResponderJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeStatusResponderError(w http.ResponseWriter, statusCode int, err error) {
	writeStatusResponderJSON(w, statusCode, map[string]string{"error": err.Error()})
}
