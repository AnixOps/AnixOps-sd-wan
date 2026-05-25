package edge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type IngressAssignment struct {
	TenantID     string    `json:"tenant_id"`
	DeviceID     string    `json:"device_id"`
	EgressNodeID string    `json:"egress_node_id"`
	Region       string    `json:"region"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type IngressHandler struct {
	auth      *Authenticator
	limiter   *WindowLimiter
	tracker   *HealthTracker
	scheduler Scheduler
	now       func() time.Time
	ttl       time.Duration
}

func NewIngressHandler(auth *Authenticator, limiter *WindowLimiter, tracker *HealthTracker, scheduler Scheduler) (*IngressHandler, error) {
	if auth == nil {
		return nil, fmt.Errorf("authenticator is required")
	}
	if limiter == nil {
		return nil, fmt.Errorf("limiter is required")
	}
	if tracker == nil {
		return nil, fmt.Errorf("health tracker is required")
	}
	return &IngressHandler{
		auth:      auth,
		limiter:   limiter,
		tracker:   tracker,
		scheduler: scheduler,
		now:       func() time.Time { return time.Now().UTC() },
		ttl:       time.Minute,
	}, nil
}

func (h *IngressHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/edge/assignments", h.handleAssignment)
	return mux
}

func (h *IngressHandler) handleAssignment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := edgeToken(r)
	credential, ok := h.auth.Authenticate(token)
	if !ok {
		writeEdgeError(w, http.StatusUnauthorized, fmt.Errorf("edge credential is invalid"))
		return
	}
	now := h.now()
	limitKey := credential.TenantID + ":" + credential.DeviceID
	if !h.limiter.Allow(limitKey, now) {
		writeEdgeError(w, http.StatusTooManyRequests, fmt.Errorf("edge request rate limit exceeded"))
		return
	}
	selected, err := h.scheduler.Pick(h.tracker.Candidates(now))
	if err != nil {
		writeEdgeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeEdgeJSON(w, http.StatusOK, IngressAssignment{
		TenantID:     credential.TenantID,
		DeviceID:     credential.DeviceID,
		EgressNodeID: selected.ID,
		Region:       selected.Region,
		ExpiresAt:    now.Add(h.ttl),
	})
}

func edgeToken(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get("X-Edge-Token")); token != "" {
		return token
	}
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(header, prefix))
	}
	return ""
}

func writeEdgeError(w http.ResponseWriter, status int, err error) {
	writeEdgeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeEdgeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
