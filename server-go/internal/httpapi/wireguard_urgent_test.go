// wireguard_urgent_test.go — endpoint del flag urgente por peer (#1441):
// auth admin, validación de clave y cuerpo, y round-trip de persistencia.
//
// El adapter demo NO implementa el flag (el endpoint responde 501), así que
// los casos de escritura usan un stub que embebe *adapters.Demo y añade el
// setter/lector, igual que el Live real los añade sobre el Snapshotter.
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/adapters"
	"github.com/gnacho/netpulse/server-go/internal/apitoken"
	"github.com/gnacho/netpulse/server-go/internal/auth"
	"github.com/gnacho/netpulse/server-go/internal/channelplan"
	"github.com/gnacho/netpulse/server-go/internal/config"
	"github.com/gnacho/netpulse/server-go/internal/configbackup"
	"github.com/gnacho/netpulse/server-go/internal/db"
	"github.com/gnacho/netpulse/server-go/internal/httpapi"
	"github.com/gnacho/netpulse/server-go/internal/orchestr"
	"github.com/gnacho/netpulse/server-go/internal/sse"
)

// wgUrgentAdapter: demo + el flag urgente en memoria (lo que en producción
// hace Live con la tabla kv).
type wgUrgentAdapter struct {
	*adapters.Demo
	mu     sync.Mutex
	urgent map[string]bool
}

func (a *wgUrgentAdapter) SetWireGuardPeerUrgent(key string, urgent bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.urgent == nil {
		a.urgent = map[string]bool{}
	}
	if urgent {
		a.urgent[key] = true
	} else {
		delete(a.urgent, key)
	}
	return nil
}

func (a *wgUrgentAdapter) WireGuardUrgentPeers() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.urgent))
	for k := range a.urgent {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// makeWGUrgentServer: réplica de makeTestServer con el adapter del flag.
func makeWGUrgentServer(t *testing.T) *testServer {
	t.Helper()
	auth.SetTrustProxy(true)
	t.Cleanup(func() { auth.SetTrustProxy(false) })
	dataDir := t.TempDir()
	cfg, err := config.Load(map[string]string{
		"AUTH_USER": "admin", "AUTH_PASS": "test123456",
		"DEMO_MODE": "0", "DATA_DIR": dataDir, "NODE_ENV": "test",
	}, dataDir)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	d, err := db.Open(dataDir)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	secret, err := auth.EnsureSessionSecret(d, cfg)
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if err := auth.EnsureUsers(d, cfg); err != nil {
		t.Fatalf("users: %v", err)
	}
	if err := apitoken.EnsureSchema(d); err != nil {
		t.Fatalf("api_tokens schema: %v", err)
	}
	configBackup, err := configbackup.NewStore(d)
	if err != nil {
		t.Fatalf("config backup store: %v", err)
	}
	handler := httpapi.NewHandler(httpapi.Deps{
		Config: cfg, DB: d,
		Adapter:      &wgUrgentAdapter{Demo: adapters.NewDemo()},
		Hub:          sse.NewHub(d, cfg.MaxSSEClients, func() any { return nil }),
		Secret:       secret,
		Started:      time.Now(),
		TokenStore:   apitoken.NewStore(d, secret),
		ConfigBackup: configBackup,
		Orchestr:     orchestr.New(d),
		Agents:       adapters.NewAgentRegistry(0),
		ChannelPlan:  channelplan.NewStore(d.DB),
	})
	srv := httptest.NewServer(handler)
	ts := &testServer{Server: srv, db: d, secret: secret}
	t.Cleanup(func() {
		srv.Close()
		d.Close()
	})
	return ts
}

// wgPeerKey: identificador url-safe con la forma que acepta el endpoint
// (8-64 chars). Sintético a propósito: una pubkey real dispara el escáner.
const wgPeerKey = "test-peer-urgent-key"

func putUrgent(t *testing.T, base, key, body, cookie string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("PUT", base+"/api/wireguard/peers/"+key+"/urgent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", "session="+cookie)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT urgent: %v", err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func urgentKeys(t *testing.T, base, cookie string) []string {
	t.Helper()
	req, _ := http.NewRequest("GET", base+"/api/wireguard/urgent", nil)
	req.Header.Set("Cookie", "session="+cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET urgent: %v", err)
	}
	defer res.Body.Close()
	var body struct {
		Peers []string `json:"peers"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Peers
}

func TestWireGuardPeerUrgentRequiresAdminSession(t *testing.T) {
	ts := makeWGUrgentServer(t)
	// Sin sesión → 401.
	if got, _ := putUrgent(t, ts.URL, wgPeerKey, `{"urgent":true}`, ""); got != http.StatusUnauthorized {
		t.Errorf("sin sesión: %d, want 401", got)
	}
	// Sesión de rol user → 403.
	_, adminCookie, _ := loginCookie(t, ts.URL, "admin", "test123456")
	userCookie := createUserAndLogin(t, ts.URL, adminCookie, "viewer", "clave12345", "user")
	if got, _ := putUrgent(t, ts.URL, wgPeerKey, `{"urgent":true}`, userCookie); got != http.StatusForbidden {
		t.Errorf("rol user: %d, want 403", got)
	}
}

func TestWireGuardPeerUrgentValidatesInput(t *testing.T) {
	ts := makeWGUrgentServer(t)
	_, cookie, _ := loginCookie(t, ts.URL, "admin", "test123456")

	cases := []struct {
		name, key, body string
		wantStatus      int
	}{
		{"clave con +", "abc+def", `{"urgent":true}`, http.StatusBadRequest},
		// '/' no llega al handler: la ruta no casa (por eso la API expone la
		// pubkey en base64url).
		{"clave con /", "abc/def", `{"urgent":true}`, http.StatusNotFound},
		{"clave demasiado corta", "abc", `{"urgent":true}`, http.StatusBadRequest},
		{"sin urgent", wgPeerKey, `{}`, http.StatusBadRequest},
		{"urgent no booleano", wgPeerKey, `{"urgent":"si"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		got, _ := putUrgent(t, ts.URL, c.key, c.body, cookie)
		if got != c.wantStatus {
			t.Errorf("%s: %d, want %d", c.name, got, c.wantStatus)
		}
	}
}

func TestWireGuardPeerUrgentRoundTrip(t *testing.T) {
	ts := makeWGUrgentServer(t)
	_, cookie, _ := loginCookie(t, ts.URL, "admin", "test123456")

	if keys := urgentKeys(t, ts.URL, cookie); len(keys) != 0 {
		t.Fatalf("arranque con urgentes: %v", keys)
	}
	got, body := putUrgent(t, ts.URL, wgPeerKey, `{"urgent":true}`, cookie)
	if got != http.StatusOK {
		t.Fatalf("marcar: %d (%v)", got, body)
	}
	if body["urgent"] != true || body["key"] != wgPeerKey {
		t.Errorf("respuesta: %v", body)
	}
	if keys := urgentKeys(t, ts.URL, cookie); len(keys) != 1 || keys[0] != wgPeerKey {
		t.Errorf("lectura tras marcar: %v, want [%s]", keys, wgPeerKey)
	}
	// Idempotente: marcar dos veces no duplica.
	if got, _ := putUrgent(t, ts.URL, wgPeerKey, `{"urgent":true}`, cookie); got != http.StatusOK {
		t.Fatalf("marcar de nuevo: %d", got)
	}
	if keys := urgentKeys(t, ts.URL, cookie); len(keys) != 1 {
		t.Errorf("lectura tras re-marcar: %v, want 1 entrada", keys)
	}
	// Desmarcar lo quita.
	if got, _ := putUrgent(t, ts.URL, wgPeerKey, `{"urgent":false}`, cookie); got != http.StatusOK {
		t.Fatalf("desmarcar: %d", got)
	}
	if keys := urgentKeys(t, ts.URL, cookie); len(keys) != 0 {
		t.Errorf("lectura tras desmarcar: %v, want vacío", keys)
	}
}

// El adapter demo (el de /api/overview del modo demo) NO soporta el flag: el
// endpoint lo dice con 501 en vez de fingir que guardó.
func TestWireGuardPeerUrgentNotSupportedInDemoAdapter(t *testing.T) {
	ts := makeTestServer(t)
	_, cookie, _ := loginCookie(t, ts.URL, "admin", "test123456")
	if got, _ := putUrgent(t, ts.URL, wgPeerKey, `{"urgent":true}`, cookie); got != http.StatusNotImplemented {
		t.Errorf("adapter demo: %d, want 501", got)
	}
	if keys := urgentKeys(t, ts.URL, cookie); len(keys) != 0 {
		t.Errorf("adapter demo no debe listar urgentes: %v", keys)
	}
}
