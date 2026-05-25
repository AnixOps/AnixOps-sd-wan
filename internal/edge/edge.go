package edge

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type Credential struct {
	Token    string
	TenantID string
	DeviceID string
}

type Authenticator struct {
	credentials map[string]Credential
}

func NewAuthenticator(credentials []Credential) (*Authenticator, error) {
	auth := &Authenticator{credentials: make(map[string]Credential, len(credentials))}
	for _, credential := range credentials {
		if credential.Token == "" {
			return nil, fmt.Errorf("credential token is required")
		}
		if credential.TenantID == "" {
			return nil, fmt.Errorf("credential tenant id is required")
		}
		if credential.DeviceID == "" {
			return nil, fmt.Errorf("credential device id is required")
		}
		auth.credentials[credential.Token] = credential
	}
	return auth, nil
}

func (a *Authenticator) Authenticate(token string) (Credential, bool) {
	credential, ok := a.credentials[token]
	return credential, ok
}

type WindowLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]counter
}

type counter struct {
	start time.Time
	used  int
}

func NewWindowLimiter(limit int, window time.Duration) (*WindowLimiter, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	if window <= 0 {
		return nil, fmt.Errorf("window must be positive")
	}
	return &WindowLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[string]counter),
	}, nil
}

func (l *WindowLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	current := l.counters[key]
	if current.start.IsZero() || now.Sub(current.start) >= l.window {
		current = counter{start: now}
	}
	if current.used >= l.limit {
		l.counters[key] = current
		return false
	}
	current.used++
	l.counters[key] = current
	return true
}

type Candidate struct {
	ID      string
	Region  string
	Healthy bool
	Load    int
}

type Heartbeat struct {
	ID       string
	Region   string
	Load     int
	Observed time.Time
}

type HealthTracker struct {
	mu    sync.RWMutex
	ttl   time.Duration
	nodes map[string]Heartbeat
}

func NewHealthTracker(ttl time.Duration) (*HealthTracker, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("health ttl must be positive")
	}
	return &HealthTracker{ttl: ttl, nodes: make(map[string]Heartbeat)}, nil
}

func (t *HealthTracker) Observe(heartbeat Heartbeat) error {
	if heartbeat.ID == "" {
		return fmt.Errorf("heartbeat id is required")
	}
	if heartbeat.Region == "" {
		return fmt.Errorf("heartbeat region is required")
	}
	if heartbeat.Load < 0 {
		return fmt.Errorf("heartbeat load must be non-negative")
	}
	if heartbeat.Observed.IsZero() {
		return fmt.Errorf("heartbeat observed time is required")
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodes[heartbeat.ID] = heartbeat
	return nil
}

func (t *HealthTracker) Candidates(now time.Time) []Candidate {
	t.mu.RLock()
	defer t.mu.RUnlock()

	candidates := make([]Candidate, 0, len(t.nodes))
	for _, heartbeat := range t.nodes {
		candidates = append(candidates, Candidate{
			ID:      heartbeat.ID,
			Region:  heartbeat.Region,
			Healthy: !heartbeat.Observed.IsZero() && now.Sub(heartbeat.Observed) <= t.ttl,
			Load:    heartbeat.Load,
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates
}

type Scheduler struct{}

func NewScheduler() Scheduler {
	return Scheduler{}
}

func (s Scheduler) Pick(candidates []Candidate) (Candidate, error) {
	ranked, err := s.Rank(candidates)
	if err != nil {
		return Candidate{}, err
	}
	return ranked[0], nil
}

func (Scheduler) Rank(candidates []Candidate) ([]Candidate, error) {
	healthy := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID == "" {
			return nil, fmt.Errorf("candidate id is required")
		}
		if candidate.Healthy {
			healthy = append(healthy, candidate)
		}
	}
	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy edge candidate available")
	}
	sort.SliceStable(healthy, func(i, j int) bool {
		if healthy[i].Load == healthy[j].Load {
			return healthy[i].ID < healthy[j].ID
		}
		return healthy[i].Load < healthy[j].Load
	})
	return healthy, nil
}
