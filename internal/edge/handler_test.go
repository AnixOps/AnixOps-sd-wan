package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIngressHandlerAuthenticatesLimitsAndSchedules(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	handler := newTestIngressHandler(t, now, 2)

	req := httptest.NewRequest(http.MethodPost, "/v1/edge/assignments", nil)
	req.Header.Set("Authorization", "Bearer token-a")
	rec := httptest.NewRecorder()
	handler.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected assignment, got %d: %s", rec.Code, rec.Body.String())
	}
	var assignment IngressAssignment
	if err := json.NewDecoder(rec.Body).Decode(&assignment); err != nil {
		t.Fatalf("decode assignment: %v", err)
	}
	if assignment.TenantID != "tenant-a" || assignment.DeviceID != "agent-a" {
		t.Fatalf("unexpected identity in assignment: %+v", assignment)
	}
	if assignment.EgressNodeID != "egress-b" || assignment.Region != "jp" {
		t.Fatalf("expected lowest-load egress-b, got %+v", assignment)
	}
}

func TestIngressHandlerRejectsInvalidCredential(t *testing.T) {
	handler := newTestIngressHandler(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 2)

	req := httptest.NewRequest(http.MethodPost, "/v1/edge/assignments", nil)
	req.Header.Set("X-Edge-Token", "unknown")
	rec := httptest.NewRecorder()
	handler.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rec.Code)
	}
}

func TestIngressHandlerEnforcesRateLimit(t *testing.T) {
	handler := newTestIngressHandler(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 1)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/edge/assignments", nil)
		req.Header.Set("X-Edge-Token", "token-a")
		rec := httptest.NewRecorder()
		handler.Handler().ServeHTTP(rec, req)
		if i == 0 && rec.Code != http.StatusOK {
			t.Fatalf("first request should pass, got %d: %s", rec.Code, rec.Body.String())
		}
		if i == 1 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("second request should be rate limited, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

func TestIngressHandlerReportsNoHealthyEgress(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	auth, err := NewAuthenticator([]Credential{{Token: "token-a", TenantID: "tenant-a", DeviceID: "agent-a"}})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	limiter, err := NewWindowLimiter(2, time.Minute)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	tracker, err := NewHealthTracker(time.Second)
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}
	if err := tracker.Observe(Heartbeat{ID: "egress-a", Region: "hk", Load: 1, Observed: now.Add(-time.Minute)}); err != nil {
		t.Fatalf("observe heartbeat: %v", err)
	}
	handler, err := NewIngressHandler(auth, limiter, tracker, NewScheduler())
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	handler.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/v1/edge/assignments", nil)
	req.Header.Set("X-Edge-Token", "token-a")
	rec := httptest.NewRecorder()
	handler.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected no healthy egress, got %d: %s", rec.Code, rec.Body.String())
	}
}

func newTestIngressHandler(t *testing.T, now time.Time, limit int) *IngressHandler {
	t.Helper()

	auth, err := NewAuthenticator([]Credential{{Token: "token-a", TenantID: "tenant-a", DeviceID: "agent-a"}})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	limiter, err := NewWindowLimiter(limit, time.Minute)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	tracker, err := NewHealthTracker(time.Minute)
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}
	if err := tracker.Observe(Heartbeat{ID: "egress-a", Region: "hk", Load: 20, Observed: now}); err != nil {
		t.Fatalf("observe egress-a: %v", err)
	}
	if err := tracker.Observe(Heartbeat{ID: "egress-b", Region: "jp", Load: 5, Observed: now}); err != nil {
		t.Fatalf("observe egress-b: %v", err)
	}
	handler, err := NewIngressHandler(auth, limiter, tracker, NewScheduler())
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	handler.now = func() time.Time { return now }
	return handler
}
