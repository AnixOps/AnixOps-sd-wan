package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/cert"
	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/store"
	"anixops-sd-wan/internal/telemetry"
)

type Server struct {
	info       buildinfo.Info
	startedAt  time.Time
	store      store.Repository
	authority  *cert.Authority
	signer     *configsign.ConfigSigner
	signerMu   sync.RWMutex
	signerAt   time.Time
	signerPut  ConfigSignerPersistFunc
	crlPub     cert.RevocationListPublisher
	authz      auth.Authorizer
	sessions   auth.SessionManager
	passwords  *auth.PasswordAuthenticator
	oidc       *auth.OIDCAuthenticator
	classifier *policy.Classifier
}

type ConfigSignerPersistFunc func(*configsign.ConfigSigner) error

func NewServer(info buildinfo.Info) *Server {
	return NewServerWithStore(info, store.NewMemory())
}

func NewServerWithStore(info buildinfo.Info, repository store.Repository) *Server {
	authority, err := cert.NewAuthority("anixops-control-ca", time.Now().UTC())
	if err != nil {
		panic(fmt.Sprintf("create control ca: %v", err))
	}
	return NewServerWithStoreAndAuthority(info, repository, authority)
}

func NewServerWithStoreAndAuthority(info buildinfo.Info, repository store.Repository, authority *cert.Authority) *Server {
	return NewServerWithDependencies(info, repository, authority, nil)
}

func NewServerWithDependencies(info buildinfo.Info, repository store.Repository, authority *cert.Authority, sessions auth.SessionManager) *Server {
	return NewServerWithDependenciesAndSigner(info, repository, authority, sessions, nil)
}

func NewServerWithDependenciesAndSigner(info buildinfo.Info, repository store.Repository, authority *cert.Authority, sessions auth.SessionManager, signer *configsign.ConfigSigner) *Server {
	return NewServerWithDependenciesAndSignerPersist(info, repository, authority, sessions, signer, nil)
}

func NewServerWithDependenciesAndSignerPersist(info buildinfo.Info, repository store.Repository, authority *cert.Authority, sessions auth.SessionManager, signer *configsign.ConfigSigner, signerPut ConfigSignerPersistFunc) *Server {
	if repository == nil {
		repository = store.NewMemory()
	}
	if authority == nil {
		var err error
		authority, err = cert.NewAuthority("anixops-control-ca", time.Now().UTC())
		if err != nil {
			panic(fmt.Sprintf("create control ca: %v", err))
		}
	}
	if signer == nil {
		var err error
		signer, err = configsign.NewConfigSigner()
		if err != nil {
			panic(fmt.Sprintf("create config signer: %v", err))
		}
	}
	if sessions == nil {
		sessions = auth.NewSessionStore()
	}
	now := time.Now().UTC()
	return &Server{
		info:      info,
		startedAt: now,
		store:     repository,
		authority: authority,
		signer:    signer,
		signerAt:  now,
		signerPut: signerPut,
		authz:     auth.NewAuthorizer(),
		sessions:  sessions,
	}
}

func (s *Server) ConfigSigningPublicKey() []byte {
	s.signerMu.RLock()
	defer s.signerMu.RUnlock()
	return s.signer.PublicKey()
}

func (s *Server) ConfigSigningKey() (configsign.SigningPublicKey, error) {
	s.signerMu.RLock()
	defer s.signerMu.RUnlock()
	return configsign.NewSigningPublicKey(s.signer.PublicKey(), s.signerAt)
}

func (s *Server) RotateConfigSigningKey() (configsign.SigningPublicKey, error) {
	signer, err := configsign.NewConfigSigner()
	if err != nil {
		return configsign.SigningPublicKey{}, err
	}
	rotatedAt := time.Now().UTC()
	if s.signerPut != nil {
		if err := s.signerPut(signer); err != nil {
			return configsign.SigningPublicKey{}, fmt.Errorf("persist config signing key: %w", err)
		}
	}
	s.signerMu.Lock()
	s.signer = signer
	s.signerAt = rotatedAt
	s.signerMu.Unlock()
	return configsign.NewSigningPublicKey(signer.PublicKey(), rotatedAt)
}

func (s *Server) SetRevocationListPublisher(publisher cert.RevocationListPublisher) {
	s.crlPub = publisher
}

func (s *Server) SetPasswordAuthenticator(authenticator *auth.PasswordAuthenticator) {
	s.passwords = authenticator
}

func (s *Server) SetOIDCAuthenticator(authenticator *auth.OIDCAuthenticator) {
	s.oidc = authenticator
}

func (s *Server) SetTrafficClassifier(classifier *policy.Classifier) {
	s.classifier = classifier
}

func (s *Server) ManagementTLSConfig(requireClientCert bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !requireClientCert {
		return cfg, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(s.authority.CAPEM()) {
		return nil, fmt.Errorf("append control ca certificate")
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

func (s *Server) IssueSession(subject auth.Subject, ttl time.Duration, now time.Time) (auth.Session, error) {
	return s.sessions.Issue(subject, ttl, now)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/console", s.handleConsole)
	mux.HandleFunc("/v1/login", s.handlePasswordLogin)
	mux.HandleFunc("/v1/oidc-login", s.handleOIDCLogin)
	mux.HandleFunc("/v1/sessions", s.handleSessions)
	mux.HandleFunc("/v1/config-signing-key/approval-request", s.handleConfigSigningKeyApprovalRequest)
	mux.HandleFunc("/v1/config-signing-key", s.handleConfigSigningKey)
	mux.HandleFunc("/v1/tenants", s.handleTenants)
	mux.HandleFunc("/v1/tenants/", s.handleTenantScoped)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"service":    s.info.Name,
		"started_at": s.startedAt,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, s.info)
}

func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(controlConsoleHTML()))
}

func controlConsoleHTML() string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AnixOps Control</title>
  <style>
    :root { color-scheme: light; --ink:#1c2430; --muted:#5a6677; --line:#cad3df; --fill:#f4f7fb; --panel:#fff; --accent:#126b67; --warn:#a44c14; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; color: var(--ink); background: var(--fill); }
    header { background: #18313d; color: #fff; padding: 1rem clamp(1rem, 3vw, 2rem); }
    main { width: min(1240px, 100%); margin: 0 auto; padding: 1rem; }
    h1 { font-size: 1.35rem; margin: 0; letter-spacing: 0; }
    h2 { font-size: 1rem; margin: 0 0 .75rem; }
    h3 { font-size: .9rem; margin: 0 0 .5rem; color: var(--muted); }
    .bar { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .75rem; background: var(--panel); border-bottom: 1px solid var(--line); padding: .85rem clamp(1rem, 3vw, 2rem); }
    .grid { display: grid; grid-template-columns: 1.1fr .9fr; gap: 1rem; align-items: start; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: .85rem; }
    .stack { display: grid; gap: 1rem; }
    .row { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .6rem; }
    label { display: grid; gap: .25rem; font-size: .78rem; color: var(--muted); }
    input, textarea, select, button { width: 100%; font: inherit; border-radius: 4px; border: 1px solid var(--line); }
    input, textarea, select { min-height: 2.25rem; padding: .45rem .55rem; background: #fff; color: var(--ink); }
    textarea { min-height: 6rem; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
    button { min-height: 2.25rem; padding: .45rem .65rem; border-color: #0d5f5b; background: var(--accent); color: #fff; cursor: pointer; }
    button.secondary { background: #2f4d62; border-color: #2f4d62; }
    button.warn { background: var(--warn); border-color: var(--warn); }
    .actions { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .5rem; }
    .forms { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
    pre { min-height: 24rem; max-height: 64rem; overflow: auto; margin: 0; padding: .75rem; background: #111820; color: #e7edf5; border-radius: 6px; font-size: .8rem; line-height: 1.45; }
    .status { min-height: 1.8rem; color: var(--muted); font-size: .84rem; }
    @media (max-width: 840px) { .bar, .grid, .forms, .row, .actions { grid-template-columns: 1fr; } pre { min-height: 18rem; } }
  </style>
</head>
<body>
  <header><h1>AnixOps Control</h1></header>
  <section class="bar" aria-label="Request context">
    <label>Tenant ID<input id="tenantId" value="tenant-a" autocomplete="off"></label>
    <label>Actor ID<input id="actorId" value="admin-a" autocomplete="off"></label>
    <label>Roles<input id="roles" value="admin" autocomplete="off"></label>
    <label>Bearer token<input id="bearer" type="password" autocomplete="off"></label>
  </section>
  <main data-console-app>
    <div class="grid">
      <div class="stack">
        <section class="panel">
          <h2>Read</h2>
          <div class="actions">
            <button data-get="/healthz">Health</button>
            <button data-get="/version">Version</button>
            <button data-tenant-get="inventory">Inventory</button>
            <button data-tenant-get="audit">Audit</button>
            <button data-tenant-get="policies" class="secondary">Policies</button>
            <button data-tenant-get="configs" class="secondary">Configs</button>
            <button data-tenant-get="signed-configs" class="secondary">Signed Configs</button>
            <button data-tenant-get="telemetry" class="secondary">Telemetry</button>
            <button data-tenant-get="certificates" class="secondary">Certificates</button>
            <button data-tenant-get="certificate-revocations" class="secondary">Revocations</button>
            <button data-tenant-get="certificate-revocation-list" class="secondary">CRL</button>
          </div>
          <form id="auditSearchForm" data-audit-search>
            <h3>Audit Search</h3>
            <div class="row"><label>Action<input name="action" value="node.retire"></label><label>Actor<input name="actor" value="admin-a"></label></div>
            <div class="row"><label>Object type<input name="object_type" value="node"></label><label>Object ID<input name="object_id" value="edge-a"></label></div>
            <div class="row"><label>Since<input name="since" placeholder="2026-01-01T00:00:00Z"></label><label>Until<input name="until" placeholder="2026-01-02T00:00:00Z"></label></div>
            <label>Limit<input name="limit" value="50"></label>
            <button class="secondary">Search Audit</button>
          </form>
        </section>
        <section class="panel">
          <h2>Write</h2>
          <div class="forms">
            <form id="createTenantForm" data-post="/v1/tenants">
              <h3>Tenant</h3>
              <div class="row"><label>ID<input name="id" value="tenant-a"></label><label>Name<input name="name" value="Tenant A"></label></div>
              <button>Create Tenant</button>
            </form>
            <form id="createDeviceForm" data-tenant-post="devices">
              <h3>Device</h3>
              <div class="row"><label>ID<input name="id" value="agent-a"></label><label>Name<input name="name" value="Agent A"></label></div>
              <div class="row"><label>Kind<input name="kind" value="client"></label><label>Platform<input name="platform" value="linux/amd64"></label></div>
              <button>Create Device</button>
            </form>
            <form id="createNodeForm" data-tenant-post="nodes">
              <h3>Node</h3>
              <div class="row"><label>ID<input name="id" value="edge-a"></label><label>Role<input name="role" value="overseas-edge"></label></div>
              <div class="row"><label>Region<input name="region" value="hk"></label><label>Endpoint<input name="endpoint" value="edge.example.com:443"></label></div>
              <button>Create Node</button>
            </form>
            <form id="retireNodeForm" data-tenant-post="node-retirements">
              <h3>Retire Node</h3>
              <label>Node ID<input name="node_id" value="edge-a"></label>
              <button class="warn">Retire Node</button>
            </form>
            <form id="createPolicyForm" data-tenant-post="policies">
              <h3>Policy</h3>
              <div class="row"><label>ID<input name="id" value="ai-openai"></label><label>Priority<input name="priority" value="100" data-number></label></div>
              <div class="row"><label>Domain suffix<input name="domain_suffix" value="openai.com"></label><label>Class<input name="class" value="ai"></label></div>
              <label>Egress node<input name="egress_node_id" value="jp-egress"></label>
              <button>Create Policy</button>
            </form>
          </div>
        </section>
        <section class="panel">
          <h2>Config</h2>
          <form id="createConfigForm" data-tenant-post="configs">
            <div class="row"><label>ID<input name="id" value="cfg-1"></label><label>Target ID<input name="target_id" value="agent-a"></label></div>
            <div class="row"><label>Version<input name="version" value="v1"></label><label>Values JSON<textarea name="values">{"transport":"hysteria2"}</textarea></label></div>
            <button>Create Config</button>
          </form>
          <form id="configWatchForm" data-watch>
            <div class="row"><label>Target ID<input name="target_id" value="agent-a"></label><label>Since version<input name="since_version" value="v0"></label></div>
            <div class="row"><label>Timeout ms<input name="timeout_ms" value="5000" data-number></label><label>Envelope<select name="signed"><option value="false">unsigned</option><option value="true">signed</option></select></label></div>
            <button class="secondary">Watch Config</button>
          </form>
        </section>
        <section class="panel">
          <h2>Certificates</h2>
          <div class="forms">
            <form id="issueCertificateForm" data-tenant-post="certificates">
              <h3>Issue</h3>
              <div class="row"><label>Device ID<input name="device_id" value="agent-a"></label><label>Role<input name="role" value="agent"></label></div>
              <label>TTL hours<input name="ttl_hours" value="24" data-number></label>
              <button>Issue Certificate</button>
            </form>
            <form id="certificateStatusForm" data-certificate-status>
              <h3>Status</h3>
              <label>Serial<input name="serial" autocomplete="off"></label>
              <button class="secondary">Check Status</button>
            </form>
            <form id="certificateOCSPForm">
              <h3>OCSP</h3>
              <label>OCSP request base64<textarea name="request_b64" placeholder="Base64 DER OCSP request"></textarea></label>
              <button class="secondary">Post OCSP Request</button>
            </form>
            <form id="rotateCertificateForm" data-tenant-post="certificate-rotations">
              <h3>Rotate</h3>
              <div class="row"><label>Serial<input name="serial" autocomplete="off"></label><label>TTL hours<input name="ttl_hours" value="24" data-number></label></div>
              <button class="secondary">Rotate Certificate</button>
            </form>
            <form id="revokeCertificateForm" data-tenant-post="certificate-revocations">
              <h3>Revoke</h3>
              <label>Serial<input name="serial" autocomplete="off"></label>
              <button class="warn">Revoke Certificate</button>
            </form>
          </div>
        </section>
      </div>
      <aside class="stack">
        <section class="panel">
          <h2>Output</h2>
          <div id="status" class="status"></div>
          <pre id="output">{}</pre>
        </section>
        <section class="panel">
          <h2>Session</h2>
          <form id="loginForm" data-login>
            <div class="row"><label>Subject ID<input name="subject_id" value="admin-a"></label><label>Password<input name="password" type="password"></label></div>
            <button>Login</button>
          </form>
          <form id="oidcLoginForm" data-oidc-login>
            <h3>OIDC</h3>
            <label>ID token<textarea name="id_token"></textarea></label>
            <button class="secondary">OIDC Login</button>
          </form>
          <button id="signingKeyApprovalRequest" class="secondary">Export Signing Key Approval Request</button>
          <button id="rotateSigningKey" class="warn">Rotate Signing Key</button>
        </section>
      </aside>
    </div>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const out = $('output');
    const status = $('status');
    const ctx = () => ({ tenant: $('tenantId').value.trim(), actor: $('actorId').value.trim(), roles: $('roles').value.trim(), bearer: $('bearer').value.trim() });
    function headers() {
      const c = ctx();
      const h = { 'Content-Type': 'application/json' };
      if (c.bearer) h.Authorization = 'Bearer ' + c.bearer;
      else { h['X-Tenant-ID'] = c.tenant; h['X-Actor-ID'] = c.actor; h['X-Roles'] = c.roles; }
      return h;
    }
    function tenantPath(resource) { return '/v1/tenants/' + encodeURIComponent(ctx().tenant) + '/' + resource; }
    function show(value) { out.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); }
    async function request(method, path, body) {
      status.textContent = method + ' ' + path;
      const res = await fetch(path, { method, headers: headers(), body: body ? JSON.stringify(body) : undefined });
      if (res.status === 204) { show({ status: 204 }); return; }
      const text = await res.text();
      let data = text;
      try { data = text ? JSON.parse(text) : {}; } catch (_) {}
      show(data);
      status.textContent = res.status + ' ' + method + ' ' + path;
    }
    async function requestBinary(method, path, body, contentType) {
      status.textContent = method + ' ' + path;
      const h = headers();
      h['Content-Type'] = contentType;
      const res = await fetch(path, { method, headers: h, body });
      const data = new Uint8Array(await res.arrayBuffer());
      show({ status: res.status, content_type: res.headers.get('Content-Type'), length: data.length, hex_prefix: Array.from(data.slice(0, 32)).map((b) => b.toString(16).padStart(2, '0')).join(' ') });
      status.textContent = res.status + ' ' + method + ' ' + path;
    }
    function formBody(form) {
      const data = {};
      new FormData(form).forEach((value, key) => {
        const field = form.elements[key];
        if (key === 'values') data[key] = JSON.parse(value || '{}');
        else if (field && field.hasAttribute('data-number')) data[key] = Number(value);
        else data[key] = value;
      });
      return data;
    }
    document.querySelectorAll('[data-get]').forEach((b) => b.addEventListener('click', () => request('GET', b.dataset.get)));
    document.querySelectorAll('[data-tenant-get]').forEach((b) => b.addEventListener('click', () => request('GET', tenantPath(b.dataset.tenantGet))));
    $('auditSearchForm').addEventListener('submit', (event) => {
      event.preventDefault();
      const body = formBody(event.currentTarget);
      const params = new URLSearchParams();
      Object.keys(body).forEach((key) => {
        if (body[key] !== '') params.set(key, body[key]);
      });
      const query = params.toString();
      request('GET', tenantPath('audit') + (query ? '?' + query : '')).catch((err) => show({ error: err.message }));
    });
    document.querySelectorAll('form[data-post], form[data-tenant-post]').forEach((form) => form.addEventListener('submit', (event) => {
      event.preventDefault();
      const path = form.dataset.post || tenantPath(form.dataset.tenantPost);
      request('POST', path, formBody(form)).catch((err) => show({ error: err.message }));
    }));
    $('configWatchForm').addEventListener('submit', (event) => {
      event.preventDefault();
      const body = formBody(event.currentTarget);
      const endpoint = body.signed === 'true' ? 'signed-config-watch' : 'config-watch';
      const params = new URLSearchParams({ target_id: body.target_id, since_version: body.since_version, timeout_ms: String(body.timeout_ms || 5000) });
      request('GET', tenantPath(endpoint) + '?' + params.toString()).catch((err) => show({ error: err.message }));
    });
    $('certificateStatusForm').addEventListener('submit', (event) => {
      event.preventDefault();
      const body = formBody(event.currentTarget);
      const params = new URLSearchParams({ serial: body.serial || '' });
      request('GET', tenantPath('certificate-status') + '?' + params.toString()).catch((err) => show({ error: err.message }));
    });
    $('certificateOCSPForm').addEventListener('submit', (event) => {
      event.preventDefault();
      const body = formBody(event.currentTarget);
      const raw = (body.request_b64 || '').replace(/\s+/g, '');
      if (!raw) { show({ error: 'OCSP request base64 is required' }); return; }
      let bytes;
      try {
        const bin = atob(raw);
        bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      } catch (err) {
        show({ error: err.message || String(err) });
        return;
      }
      requestBinary('POST', tenantPath('certificate-ocsp'), bytes, 'application/ocsp-request').catch((err) => show({ error: err.message }));
    });
    $('loginForm').addEventListener('submit', (event) => {
      event.preventDefault();
      const body = formBody(event.currentTarget);
      request('POST', '/v1/login', { tenant_id: ctx().tenant, subject_id: body.subject_id, password: body.password, ttl_hours: 8 }).catch((err) => show({ error: err.message }));
    });
    $('oidcLoginForm').addEventListener('submit', (event) => {
      event.preventDefault();
      const body = formBody(event.currentTarget);
      request('POST', '/v1/oidc-login', { id_token: body.id_token, ttl_hours: 8 }).catch((err) => show({ error: err.message }));
    });
    $('signingKeyApprovalRequest').addEventListener('click', () => request('GET', '/v1/config-signing-key/approval-request?source=console'));
    $('rotateSigningKey').addEventListener('click', () => request('POST', '/v1/config-signing-key'));
  </script>
</body>
</html>`
}

func (s *Server) handleConfigSigningKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.authorizeOwnTenant(w, r, auth.ActionConfigRead) {
			return
		}
		key, err := s.ConfigSigningKey()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, key)
	case http.MethodPost:
		subject, ok := s.authorizeOwnTenantSubject(w, r, auth.ActionManage)
		if !ok {
			return
		}
		key, err := s.RotateConfigSigningKey()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.recordAuditEvent(r.Context(), subject, "config_signing_key.rotate", "config_signing_key", key.SHA256FingerprintHex, "rotated config signing key"); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, key)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConfigSigningKeyApprovalRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	subject, ok := s.authorizeOwnTenantSubject(w, r, auth.ActionManage)
	if !ok {
		return
	}
	key, err := s.ConfigSigningKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	request, err := configsign.NewSigningKeyApprovalRequest(key, subject.ID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	request.Source = strings.TrimSpace(r.URL.Query().Get("source"))
	if request.Source == "" {
		request.Source = "control-api"
	}
	request.Reason = strings.TrimSpace(r.URL.Query().Get("reason"))
	if err := s.recordAuditEvent(r.Context(), subject, "config_signing_key.approval_request.export", "config_signing_key", request.SHA256FingerprintHex, fmt.Sprintf("exported signing key approval request source=%s reason=%s", request.Source, request.Reason)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var tenant domain.Tenant
	if err := decodeJSON(r, &tenant); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorize(w, r, tenant.ID, auth.ActionManage) {
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}
	created, err := s.store.CreateTenant(r.Context(), tenant)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "tenant.create", "tenant", created.ID, "created tenant through control API"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

type sessionIssueRequest struct {
	TTLHours int `json:"ttl_hours"`
}

type passwordLoginRequest struct {
	TenantID  string `json:"tenant_id"`
	SubjectID string `json:"subject_id"`
	Password  string `json:"password"`
	TTLHours  int    `json:"ttl_hours"`
}

type oidcLoginRequest struct {
	IDToken  string `json:"id_token"`
	TTLHours int    `json:"ttl_hours"`
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request passwordLoginRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	subject, ok, err := s.passwords.Authenticate(request.TenantID, request.SubjectID, request.Password)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid password credentials"))
		return
	}
	if request.TTLHours <= 0 {
		request.TTLHours = 8
	}
	if request.TTLHours > 24 {
		request.TTLHours = 24
	}
	session, err := s.sessions.Issue(subject, time.Duration(request.TTLHours)*time.Hour, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "auth.login", "subject", subject.ID, "password login issued bearer session"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request oidcLoginRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	subject, ok, err := s.oidc.AuthenticateIDToken(request.IDToken, time.Now().UTC())
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid oidc id token"))
		return
	}
	if request.TTLHours <= 0 {
		request.TTLHours = 8
	}
	if request.TTLHours > 24 {
		request.TTLHours = 24
	}
	session, err := s.sessions.Issue(subject, time.Duration(request.TTLHours)*time.Hour, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "auth.login", "subject", subject.ID, "oidc login issued bearer session"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var request sessionIssueRequest
		if err := decodeJSON(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		subject, err := s.subjectFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		allowed, err := s.authz.Allowed(subject, auth.Request{TenantID: subject.TenantID, Action: auth.ActionRead})
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, fmt.Errorf("subject %q is not allowed to create a session for tenant %q", subject.ID, subject.TenantID))
			return
		}
		if request.TTLHours <= 0 {
			request.TTLHours = 8
		}
		if request.TTLHours > 24 {
			request.TTLHours = 24
		}
		session, err := s.sessions.Issue(subject, time.Duration(request.TTLHours)*time.Hour, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.recordAuditEvent(r.Context(), subject, "auth.session.issue", "subject", subject.ID, "issued bearer session"); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, session)
	case http.MethodDelete:
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("bearer session token is required"))
			return
		}
		subject, ok := s.sessions.Authenticate(token, time.Now().UTC())
		if !ok {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("bearer session is invalid or expired"))
			return
		}
		if err := s.recordAuditEvent(r.Context(), subject, "auth.session.revoke", "subject", subject.ID, "revoked bearer session"); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.sessions.Revoke(token)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTenantScoped(w http.ResponseWriter, r *http.Request) {
	tenantID, resource, ok := parseTenantPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	action, ok := actionFor(resource, r.Method)
	if !ok {
		if !knownTenantResource(resource) {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(w, r, tenantID, action) {
		return
	}

	switch resource {
	case "devices":
		s.handleDevices(w, r, tenantID)
	case "nodes":
		s.handleNodes(w, r, tenantID)
	case "node-heartbeats":
		s.handleNodeHeartbeats(w, r, tenantID)
	case "node-retirements":
		s.handleNodeRetirements(w, r, tenantID)
	case "inventory":
		s.handleInventory(w, r, tenantID)
	case "telemetry":
		s.handleTelemetry(w, r, tenantID)
	case "audit":
		s.handleAudit(w, r, tenantID)
	case "policies":
		s.handlePolicies(w, r, tenantID)
	case "policy-decisions":
		s.handlePolicyDecisions(w, r, tenantID)
	case "configs":
		s.handleConfigs(w, r, tenantID)
	case "config-watch":
		s.handleConfigWatch(w, r, tenantID)
	case "signed-configs":
		s.handleSignedConfigs(w, r, tenantID)
	case "signed-config-watch":
		s.handleSignedConfigWatch(w, r, tenantID)
	case "certificates":
		s.handleCertificates(w, r, tenantID)
	case "certificate-revocations":
		s.handleCertificateRevocations(w, r, tenantID)
	case "certificate-revocation-list":
		s.handleCertificateRevocationList(w, r, tenantID)
	case "certificate-status":
		s.handleCertificateStatus(w, r, tenantID)
	case "certificate-ocsp":
		s.handleCertificateOCSP(w, r, tenantID)
	case "certificate-rotations":
		s.handleCertificateRotations(w, r, tenantID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, tenantID string, action auth.Action) bool {
	subject, err := s.subjectFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return false
	}
	allowed, err := s.authz.Allowed(subject, auth.Request{TenantID: tenantID, Action: action})
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return false
	}
	if !allowed {
		if err := s.recordAuthorizationDenied(r.Context(), subject, tenantID, action); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return false
		}
		writeError(w, http.StatusForbidden, fmt.Errorf("subject %q is not allowed to %s tenant %q", subject.ID, action, tenantID))
		return false
	}
	return true
}

func (s *Server) authorizeOwnTenant(w http.ResponseWriter, r *http.Request, action auth.Action) bool {
	_, ok := s.authorizeOwnTenantSubject(w, r, action)
	return ok
}

func (s *Server) authorizeOwnTenantSubject(w http.ResponseWriter, r *http.Request, action auth.Action) (auth.Subject, bool) {
	subject, err := s.subjectFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return auth.Subject{}, false
	}
	allowed, err := s.authz.Allowed(subject, auth.Request{TenantID: subject.TenantID, Action: action})
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return auth.Subject{}, false
	}
	if !allowed {
		if err := s.recordAuthorizationDenied(r.Context(), subject, subject.TenantID, action); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return auth.Subject{}, false
		}
		writeError(w, http.StatusForbidden, fmt.Errorf("subject %q is not allowed to %s tenant %q", subject.ID, action, subject.TenantID))
		return auth.Subject{}, false
	}
	return subject, true
}

func (s *Server) recordAuthorizationDenied(ctx context.Context, subject auth.Subject, tenantID string, action auth.Action) error {
	_, err := s.store.RecordAuditEvent(ctx, domain.AuditEvent{
		TenantID:   tenantID,
		Actor:      subject.ID,
		Action:     "auth.denied",
		ObjectType: "authorization",
		ObjectID:   string(action),
		Message:    fmt.Sprintf("denied action %s for subject tenant=%s target tenant=%s", action, subject.TenantID, tenantID),
	})
	return err
}

func (s *Server) recordAuditEvent(ctx context.Context, subject auth.Subject, action, objectType, objectID, message string) error {
	_, err := s.store.RecordAuditEvent(ctx, domain.AuditEvent{
		TenantID:   subject.TenantID,
		Actor:      subject.ID,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Message:    message,
	})
	return err
}

func (s *Server) subjectForAudit(w http.ResponseWriter, r *http.Request) (auth.Subject, bool) {
	subject, err := s.subjectFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return auth.Subject{}, false
	}
	return subject, true
}

func (s *Server) subjectFromRequest(r *http.Request) (auth.Subject, error) {
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		if subject, ok := s.sessions.Authenticate(token, time.Now().UTC()); ok {
			return subject, nil
		}
		return auth.Subject{}, fmt.Errorf("bearer session is invalid or expired")
	}
	if subject, ok, err := subjectFromPeerCertificate(r, time.Now().UTC()); err != nil {
		return auth.Subject{}, err
	} else if ok {
		return subject, nil
	}
	return subjectFromHeaders(r)
}

func subjectFromPeerCertificate(r *http.Request, now time.Time) (auth.Subject, bool, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return auth.Subject{}, false, nil
	}
	certificate := r.TLS.PeerCertificates[0]
	if err := verifyPeerCertificateTime(certificate, now); err != nil {
		return auth.Subject{}, true, err
	}
	parts := strings.Split(certificate.Subject.CommonName, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return auth.Subject{}, true, fmt.Errorf("peer certificate common name must be tenant:role:device")
	}
	return auth.Subject{
		ID:       parts[2],
		TenantID: parts[0],
		Roles:    rolesFromCertificateRole(parts[1]),
	}, true, nil
}

func verifyPeerCertificateTime(certificate *x509.Certificate, now time.Time) error {
	if now.Before(certificate.NotBefore) {
		return fmt.Errorf("peer certificate is not valid yet")
	}
	if !now.Before(certificate.NotAfter) {
		return fmt.Errorf("peer certificate is expired")
	}
	return nil
}

func rolesFromCertificateRole(role string) []auth.Role {
	switch auth.Role(role) {
	case auth.RoleAdmin:
		return []auth.Role{auth.RoleAdmin}
	case auth.RoleOperator:
		return []auth.Role{auth.RoleOperator}
	case auth.RoleViewer:
		return []auth.Role{auth.RoleViewer}
	case auth.RoleAgent:
		return []auth.Role{auth.RoleAgent}
	default:
		return []auth.Role{auth.RoleAgent}
	}
}

func subjectFromHeaders(r *http.Request) (auth.Subject, error) {
	subject := auth.Subject{
		ID:       strings.TrimSpace(r.Header.Get("X-Actor-ID")),
		TenantID: strings.TrimSpace(r.Header.Get("X-Tenant-ID")),
	}
	for _, raw := range strings.Split(r.Header.Get("X-Roles"), ",") {
		role := strings.TrimSpace(raw)
		if role == "" {
			continue
		}
		subject.Roles = append(subject.Roles, auth.Role(role))
	}
	if subject.ID == "" {
		return auth.Subject{}, fmt.Errorf("X-Actor-ID header is required")
	}
	if subject.TenantID == "" {
		return auth.Subject{}, fmt.Errorf("X-Tenant-ID header is required")
	}
	if len(subject.Roles) == 0 {
		return auth.Subject{}, fmt.Errorf("X-Roles header is required")
	}
	return subject, nil
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func actionFor(resource, method string) (auth.Action, bool) {
	switch resource {
	case "devices", "nodes":
		if method == http.MethodPost {
			return auth.ActionManage, true
		}
	case "node-heartbeats":
		if method == http.MethodPost {
			return auth.ActionTelemetryWrite, true
		}
	case "node-retirements":
		if method == http.MethodPost {
			return auth.ActionManage, true
		}
	case "inventory":
		if method == http.MethodGet {
			return auth.ActionRead, true
		}
	case "telemetry":
		switch method {
		case http.MethodGet:
			return auth.ActionRead, true
		case http.MethodPost:
			return auth.ActionTelemetryWrite, true
		}
	case "audit":
		if method == http.MethodGet {
			return auth.ActionAuditRead, true
		}
	case "policies":
		switch method {
		case http.MethodGet:
			return auth.ActionRead, true
		case http.MethodPost:
			return auth.ActionPolicyEdit, true
		}
	case "policy-decisions":
		if method == http.MethodPost {
			return auth.ActionRead, true
		}
	case "configs":
		switch method {
		case http.MethodGet:
			return auth.ActionConfigRead, true
		case http.MethodPost:
			return auth.ActionManage, true
		}
	case "config-watch":
		if method == http.MethodGet {
			return auth.ActionConfigRead, true
		}
	case "signed-configs":
		if method == http.MethodGet {
			return auth.ActionConfigRead, true
		}
	case "signed-config-watch":
		if method == http.MethodGet {
			return auth.ActionConfigRead, true
		}
	case "certificates":
		switch method {
		case http.MethodGet:
			return auth.ActionRead, true
		case http.MethodPost:
			return auth.ActionCertManage, true
		}
	case "certificate-revocations":
		switch method {
		case http.MethodGet:
			return auth.ActionRead, true
		case http.MethodPost:
			return auth.ActionCertManage, true
		}
	case "certificate-revocation-list":
		if method == http.MethodGet {
			return auth.ActionRead, true
		}
	case "certificate-status":
		if method == http.MethodGet {
			return auth.ActionRead, true
		}
	case "certificate-ocsp":
		if method == http.MethodPost {
			return auth.ActionRead, true
		}
	case "certificate-rotations":
		if method == http.MethodPost {
			return auth.ActionCertManage, true
		}
	}
	return "", false
}

func knownTenantResource(resource string) bool {
	switch resource {
	case "devices", "nodes", "node-heartbeats", "node-retirements", "inventory", "telemetry", "audit", "policies", "policy-decisions", "configs", "config-watch", "signed-configs", "signed-config-watch", "certificates", "certificate-revocations", "certificate-revocation-list", "certificate-status", "certificate-ocsp", "certificate-rotations":
		return true
	default:
		return false
	}
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}

	var device domain.Device
	if err := decodeJSON(r, &device); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	device.TenantID = tenantID
	created, err := s.store.RegisterDevice(r.Context(), device)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "device.register", "device", created.ID, "registered device through control API"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}

	var node domain.Node
	if err := decodeJSON(r, &node); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	node.TenantID = tenantID
	created, err := s.store.RegisterNode(r.Context(), node)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "node.register", "node", created.ID, "registered node through control API"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleNodeHeartbeats(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}

	var heartbeat domain.NodeHeartbeat
	if err := decodeJSON(r, &heartbeat); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	heartbeat.TenantID = tenantID
	updated, err := s.store.RecordNodeHeartbeat(r.Context(), heartbeat)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "node.heartbeat", "node", updated.ID, "recorded node heartbeat through control API"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

type nodeRetireRequest struct {
	NodeID string `json:"node_id"`
}

func (s *Server) handleNodeRetirements(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}

	var request nodeRetireRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodeID := strings.TrimSpace(request.NodeID)
	retired, err := s.store.RetireNode(r.Context(), tenantID, nodeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "node.retire", "node", retired.ID, "retired node through control API"); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, retired)
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	inventory, err := s.store.Inventory(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request, tenantID string) {
	switch r.Method {
	case http.MethodGet:
		reports, err := s.store.Telemetry(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, reports)
	case http.MethodPost:
		var report telemetry.Report
		if err := decodeJSON(r, &report); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		report.TenantID = tenantID
		created, err := s.store.RecordTelemetry(r.Context(), report)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	events, err := s.store.AuditEvents(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	events, err = filterAuditEvents(events, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func filterAuditEvents(events []domain.AuditEvent, r *http.Request) ([]domain.AuditEvent, error) {
	query := r.URL.Query()
	action := strings.TrimSpace(query.Get("action"))
	actor := strings.TrimSpace(query.Get("actor"))
	objectType := strings.TrimSpace(query.Get("object_type"))
	objectID := strings.TrimSpace(query.Get("object_id"))
	since, err := parseOptionalAuditTime(query.Get("since"), "since")
	if err != nil {
		return nil, err
	}
	until, err := parseOptionalAuditTime(query.Get("until"), "until")
	if err != nil {
		return nil, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return nil, fmt.Errorf("audit since must be before or equal to until")
	}
	limit, err := parseOptionalAuditLimit(query.Get("limit"))
	if err != nil {
		return nil, err
	}
	filtered := make([]domain.AuditEvent, 0, len(events))
	for _, event := range events {
		if action != "" && event.Action != action {
			continue
		}
		if actor != "" && event.Actor != actor {
			continue
		}
		if objectType != "" && event.ObjectType != objectType {
			continue
		}
		if objectID != "" && event.ObjectID != objectID {
			continue
		}
		if !since.IsZero() && event.CreatedAt.Before(since) {
			continue
		}
		if !until.IsZero() && event.CreatedAt.After(until) {
			continue
		}
		filtered = append(filtered, event)
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered, nil
}

func parseOptionalAuditTime(raw, name string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("audit %s must be RFC3339 timestamp: %w", name, err)
	}
	return parsed, nil
}

func parseOptionalAuditLimit(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return 0, fmt.Errorf("audit limit must be a positive integer")
	}
	return limit, nil
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request, tenantID string) {
	switch r.Method {
	case http.MethodGet:
		rules, err := s.store.PolicyRules(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, rules)
	case http.MethodPost:
		subject, ok := s.subjectForAudit(w, r)
		if !ok {
			return
		}
		var rule policy.Rule
		if err := decodeJSON(r, &rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		rule.TenantID = tenantID
		created, err := s.store.UpsertPolicyRule(r.Context(), rule)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.recordAuditEvent(r.Context(), subject, "policy.upsert", "policy_rule", created.ID, "upserted policy rule through control API"); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePolicyDecisions(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var request policy.Request
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	request.TenantID = tenantID
	if s.classifier != nil {
		request.Class = s.classifier.Classify(request)
	}
	decision, err := s.store.EvaluatePolicy(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) handleConfigs(w http.ResponseWriter, r *http.Request, tenantID string) {
	switch r.Method {
	case http.MethodGet:
		configs, err := s.store.Configs(r.Context(), tenantID)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, configs)
	case http.MethodPost:
		subject, ok := s.subjectForAudit(w, r)
		if !ok {
			return
		}
		var bundle domain.ConfigBundle
		if err := decodeJSON(r, &bundle); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		bundle.TenantID = tenantID
		created, err := s.store.UpsertConfig(r.Context(), bundle)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.recordAuditEvent(r.Context(), subject, "config.upsert", "config_bundle", created.ID, "upserted config bundle through control API"); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConfigWatch(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	if targetID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("target_id is required"))
		return
	}
	sinceVersion := strings.TrimSpace(r.URL.Query().Get("since_version"))
	timeout := configWatchTimeout(r)
	ctx, cancel := contextWithTimeout(r, timeout)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		bundle, changed, err := s.changedConfig(ctx, tenantID, targetID, sinceVersion)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if changed {
			writeJSON(w, http.StatusOK, bundle)
			return
		}
		select {
		case <-ctx.Done():
			w.WriteHeader(http.StatusNoContent)
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) changedConfig(ctx context.Context, tenantID, targetID, sinceVersion string) (domain.ConfigBundle, bool, error) {
	configs, err := s.store.Configs(ctx, tenantID)
	if err != nil {
		return domain.ConfigBundle{}, false, err
	}
	bundle, ok := selectTargetConfig(configs, targetID)
	if !ok {
		return domain.ConfigBundle{}, false, nil
	}
	if sinceVersion != "" && bundle.Version == sinceVersion {
		return domain.ConfigBundle{}, false, nil
	}
	return bundle, true, nil
}

func (s *Server) handleSignedConfigs(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	configs, err := s.store.Configs(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	signed := make([]configsign.SignedBundle, 0, len(configs))
	s.signerMu.RLock()
	defer s.signerMu.RUnlock()
	for _, bundle := range configs {
		envelope, err := s.signer.Sign(bundle, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		signed = append(signed, envelope)
	}
	writeJSON(w, http.StatusOK, signed)
}

func (s *Server) handleSignedConfigWatch(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	if targetID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("target_id is required"))
		return
	}
	sinceVersion := strings.TrimSpace(r.URL.Query().Get("since_version"))
	timeout := configWatchTimeout(r)
	ctx, cancel := contextWithTimeout(r, timeout)
	defer cancel()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		bundle, changed, err := s.changedConfig(ctx, tenantID, targetID, sinceVersion)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if changed {
			signed, err := s.signConfigBundle(bundle)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, signed)
			return
		}
		select {
		case <-ctx.Done():
			w.WriteHeader(http.StatusNoContent)
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) signConfigBundle(bundle domain.ConfigBundle) (configsign.SignedBundle, error) {
	s.signerMu.RLock()
	defer s.signerMu.RUnlock()
	return s.signer.Sign(bundle, time.Now().UTC())
}

func configWatchTimeout(r *http.Request) time.Duration {
	const defaultTimeout = 25 * time.Second
	const maxTimeout = 30 * time.Second
	raw := strings.TrimSpace(r.URL.Query().Get("timeout_ms"))
	if raw == "" {
		return defaultTimeout
	}
	millis, err := strconv.Atoi(raw)
	if err != nil || millis <= 0 {
		return defaultTimeout
	}
	timeout := time.Duration(millis) * time.Millisecond
	if timeout > maxTimeout {
		return maxTimeout
	}
	return timeout
}

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

func selectTargetConfig(configs []domain.ConfigBundle, targetID string) (domain.ConfigBundle, bool) {
	var selected domain.ConfigBundle
	found := false
	for _, candidate := range configs {
		if candidate.TargetID != targetID {
			continue
		}
		if !found || candidate.CreatedAt.After(selected.CreatedAt) || candidate.Version > selected.Version {
			selected = candidate
			found = true
		}
	}
	return selected, found
}

type certificateIssueRequest struct {
	DeviceID string `json:"device_id"`
	Role     string `json:"role"`
	TTLHours int    `json:"ttl_hours"`
}

type certificateRevokeRequest struct {
	Serial string `json:"serial"`
}

type certificateRotateRequest struct {
	Serial   string `json:"serial"`
	TTLHours int    `json:"ttl_hours"`
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request, tenantID string) {
	switch r.Method {
	case http.MethodGet:
		if _, err := s.store.Inventory(r.Context(), tenantID); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, s.authority.RecordsByTenant(tenantID))
	case http.MethodPost:
		if _, err := s.store.Inventory(r.Context(), tenantID); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		subject, ok := s.subjectForAudit(w, r)
		if !ok {
			return
		}
		var request certificateIssueRequest
		if err := decodeJSON(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if request.TTLHours <= 0 {
			request.TTLHours = 24
		}
		issued, err := s.authority.Issue(cert.Identity{
			TenantID: tenantID,
			DeviceID: request.DeviceID,
			Role:     request.Role,
		}, time.Duration(request.TTLHours)*time.Hour, time.Now().UTC())
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.recordAuditEvent(r.Context(), subject, "certificate.issue", "certificate", issued.Record.Serial, fmt.Sprintf("issued certificate for device=%s role=%s", issued.Record.DeviceID, issued.Record.Role)); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, issued)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificateRevocations(w http.ResponseWriter, r *http.Request, tenantID string) {
	switch r.Method {
	case http.MethodGet:
		if _, err := s.store.Inventory(r.Context(), tenantID); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, s.authority.RevokedRecordsByTenant(tenantID))
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var request certificateRevokeRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}
	existing, exists := s.authority.Record(request.Serial)
	if !exists {
		writeError(w, http.StatusBadRequest, fmt.Errorf("certificate %q not found", request.Serial))
		return
	}
	if existing.TenantID != tenantID {
		writeError(w, http.StatusForbidden, fmt.Errorf("certificate does not belong to tenant %q", tenantID))
		return
	}
	record, err := s.authority.Revoke(request.Serial, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.publishRevocationList(r, tenantID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "certificate.revoke", "certificate", record.Serial, fmt.Sprintf("revoked certificate for device=%s role=%s", record.DeviceID, record.Role)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) handleCertificateRevocationList(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.store.Inventory(r.Context(), tenantID); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	list, err := s.authority.RevocationListByTenant(tenantID, time.Now().UTC(), 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCertificateStatus(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.store.Inventory(r.Context(), tenantID); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	responder, err := cert.NewStatusResponder(s.authority, cert.DefaultStatusMaxAge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	status, err := responder.Respond(cert.StatusRequest{
		TenantID: tenantID,
		Serial:   serial,
	}, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleCertificateOCSP(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := s.store.Inventory(r.Context(), tenantID); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	responder, err := cert.NewStatusResponder(s.authority, cert.DefaultStatusMaxAge)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	responder.ServeOCSPHTTP(tenantID, w, r)
}

func (s *Server) handleCertificateRotations(w http.ResponseWriter, r *http.Request, tenantID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var request certificateRotateRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	subject, ok := s.subjectForAudit(w, r)
	if !ok {
		return
	}
	existing, exists := s.authority.Record(request.Serial)
	if !exists {
		writeError(w, http.StatusBadRequest, fmt.Errorf("certificate %q not found", request.Serial))
		return
	}
	if existing.TenantID != tenantID {
		writeError(w, http.StatusForbidden, fmt.Errorf("certificate does not belong to tenant %q", tenantID))
		return
	}
	if request.TTLHours <= 0 {
		request.TTLHours = 24
	}
	issued, err := s.authority.Rotate(request.Serial, time.Duration(request.TTLHours)*time.Hour, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.publishRevocationList(r, tenantID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.recordAuditEvent(r.Context(), subject, "certificate.rotate", "certificate", issued.Record.Serial, fmt.Sprintf("rotated certificate from serial=%s for device=%s role=%s", request.Serial, issued.Record.DeviceID, issued.Record.Role)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, issued)
}

func (s *Server) publishRevocationList(r *http.Request, tenantID string) error {
	if s.crlPub == nil {
		return nil
	}
	list, err := s.authority.RevocationListByTenant(tenantID, time.Now().UTC(), 24*time.Hour)
	if err != nil {
		return err
	}
	_, err = s.crlPub.PublishRevocationList(r.Context(), list)
	return err
}

func parseTenantPath(path string) (tenantID, resource string, ok bool) {
	rest := strings.TrimPrefix(path, "/v1/tenants/")
	if rest == path {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func decodeJSON(r *http.Request, value interface{}) error {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
