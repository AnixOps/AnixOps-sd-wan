package edge

import (
	"testing"
	"time"
)

func TestAuthenticatorAcceptsKnownToken(t *testing.T) {
	auth, err := NewAuthenticator([]Credential{{
		Token:    "token-a",
		TenantID: "tenant-a",
		DeviceID: "agent-a",
	}})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	credential, ok := auth.Authenticate("token-a")
	if !ok {
		t.Fatal("expected token to authenticate")
	}
	if credential.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", credential.TenantID)
	}
}

func TestWindowLimiterEnforcesLimitAndResets(t *testing.T) {
	limiter, err := NewWindowLimiter(2, time.Minute)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)

	if !limiter.Allow("tenant-a", now) {
		t.Fatal("first request should be allowed")
	}
	if !limiter.Allow("tenant-a", now.Add(time.Second)) {
		t.Fatal("second request should be allowed")
	}
	if limiter.Allow("tenant-a", now.Add(2*time.Second)) {
		t.Fatal("third request should be denied")
	}
	if !limiter.Allow("tenant-a", now.Add(time.Minute)) {
		t.Fatal("request after window should be allowed")
	}
}

func TestSchedulerPicksLowestLoadHealthyCandidate(t *testing.T) {
	selected, err := NewScheduler().Pick([]Candidate{
		{ID: "edge-a", Region: "hk", Healthy: true, Load: 20},
		{ID: "edge-b", Region: "jp", Healthy: true, Load: 5},
		{ID: "edge-c", Region: "sg", Healthy: false, Load: 1},
	})
	if err != nil {
		t.Fatalf("pick candidate: %v", err)
	}
	if selected.ID != "edge-b" {
		t.Fatalf("expected edge-b, got %s", selected.ID)
	}
}

func TestSchedulerRanksHealthyCandidatesByLoad(t *testing.T) {
	ranked, err := NewScheduler().Rank([]Candidate{
		{ID: "edge-a", Region: "hk", Healthy: true, Load: 20},
		{ID: "edge-b", Region: "jp", Healthy: true, Load: 5},
		{ID: "edge-c", Region: "sg", Healthy: false, Load: 1},
		{ID: "edge-d", Region: "us", Healthy: true, Load: 5},
	})
	if err != nil {
		t.Fatalf("rank candidates: %v", err)
	}
	got := []string{ranked[0].ID, ranked[1].ID, ranked[2].ID}
	want := []string{"edge-b", "edge-d", "edge-a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected ranked candidates %v, got %v", want, got)
		}
	}
}

func TestHealthTrackerMarksStaleNodesUnhealthy(t *testing.T) {
	tracker, err := NewHealthTracker(30 * time.Second)
	if err != nil {
		t.Fatalf("new health tracker: %v", err)
	}
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	if err := tracker.Observe(Heartbeat{ID: "edge-a", Region: "hk", Load: 10, Observed: now.Add(-10 * time.Second)}); err != nil {
		t.Fatalf("observe edge-a: %v", err)
	}
	if err := tracker.Observe(Heartbeat{ID: "edge-b", Region: "jp", Load: 1, Observed: now.Add(-time.Minute)}); err != nil {
		t.Fatalf("observe edge-b: %v", err)
	}

	candidates := tracker.Candidates(now)
	if len(candidates) != 2 {
		t.Fatalf("expected two candidates, got %+v", candidates)
	}
	byID := map[string]Candidate{}
	for _, candidate := range candidates {
		byID[candidate.ID] = candidate
	}
	if !byID["edge-a"].Healthy {
		t.Fatal("expected fresh edge-a to be healthy")
	}
	if byID["edge-b"].Healthy {
		t.Fatal("expected stale edge-b to be unhealthy")
	}
}

func TestSchedulerUsesHealthTrackerCandidates(t *testing.T) {
	tracker, err := NewHealthTracker(time.Minute)
	if err != nil {
		t.Fatalf("new health tracker: %v", err)
	}
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	_ = tracker.Observe(Heartbeat{ID: "edge-a", Region: "hk", Load: 50, Observed: now})
	_ = tracker.Observe(Heartbeat{ID: "edge-b", Region: "jp", Load: 5, Observed: now})

	selected, err := NewScheduler().Pick(tracker.Candidates(now))
	if err != nil {
		t.Fatalf("pick candidate: %v", err)
	}
	if selected.ID != "edge-b" {
		t.Fatalf("expected lowest load healthy edge-b, got %s", selected.ID)
	}
}
