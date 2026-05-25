package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"anixops-sd-wan/internal/domain"
)

func (s *Service) LocalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleLocalHealth)
	mux.HandleFunc("/v1/snapshot", s.handleLocalSnapshot)
	mux.HandleFunc("/v1/telemetry", s.handleLocalTelemetry)
	mux.HandleFunc("/v1/config", s.handleLocalConfig)
	return mux
}

func (s *Service) RunLocalAPI(ctx context.Context, addr string) error {
	if addr == "" {
		return fmt.Errorf("local api address is required")
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           s.LocalHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown local api: %w", err)
		}
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Service) handleLocalHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeLocalJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"running": s.Snapshot().Running,
	})
}

func (s *Service) handleLocalSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeLocalJSON(w, http.StatusOK, s.Snapshot())
}

func (s *Service) handleLocalTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeLocalJSON(w, http.StatusOK, s.TelemetryReport())
}

func (s *Service) handleLocalConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeLocalJSON(w, http.StatusOK, s.currentLocalConfig())
	case http.MethodPost:
		var bundle domain.ConfigBundle
		if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
			writeLocalError(w, http.StatusBadRequest, fmt.Errorf("decode config bundle: %w", err))
			return
		}
		if err := s.ApplyConfig(bundle); err != nil {
			writeLocalError(w, http.StatusBadRequest, err)
			return
		}
		writeLocalJSON(w, http.StatusOK, s.Snapshot())
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeLocalJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeLocalError(w http.ResponseWriter, status int, err error) {
	writeLocalJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Service) currentLocalConfig() domain.ConfigBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return domain.ConfigBundle{
		ID:       "current",
		TenantID: s.snapshot.TenantID,
		TargetID: s.snapshot.DeviceID,
		Version:  s.snapshot.ConfigVersion,
		Values: map[string]string{
			"transport": s.snapshot.Protocol.String(),
		},
	}
}
