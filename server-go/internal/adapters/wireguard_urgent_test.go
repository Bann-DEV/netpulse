// wireguard_urgent_test.go — #1441: flag urgente por peer WireGuard
// (clave estable, persistencia en kv y Urgent en las alertas de transición).
package adapters

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/alerts"
	"github.com/gnacho/netpulse/server-go/internal/db"
)

// realPubkey: una pubkey WireGuard de 32 bytes en base64 estándar (44 chars,
// con '=' final). La de los fixtures reales del repo también vale.
func realPubkey(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestWGPeerKeyIsURLSafeAndStable(t *testing.T) {
	pub := realPubkey(1)
	key := WGPeerKey(pub)
	if len(key) != 43 {
		t.Fatalf("key len = %d (%q), want 43 (base64url sin padding)", len(key), key)
	}
	if strings.ContainsAny(key, "+/=") {
		t.Errorf("key %q lleva caracteres que rompen el path", key)
	}
	if again := WGPeerKey(pub); again != key {
		t.Errorf("key no estable: %q != %q", again, key)
	}
	if other := WGPeerKey(realPubkey(2)); other == key {
		t.Errorf("dos pubkeys distintas comparten key %q", key)
	}
	if WGPeerKey("") != "" {
		t.Error("pubkey vacía debería dar key vacía")
	}
	// Pubkey no estándar (no decodifica): se translitera, sin '+' ni '/'.
	if got := WGPeerKey("ab+cd/ef=="); strings.ContainsAny(got, "+/=") || got == "" {
		t.Errorf("transliteración de pubkey rara: %q", got)
	}
}

func TestBuildWGPeerStampsUrgencyByKey(t *testing.T) {
	pub := realPubkey(7)
	key := WGPeerKey(pub)
	descs := map[string]string{}
	peer := buildWGPeer(WGDumpPeer{Pubkey: pub, AllowedIPs: "10.0.0.9/32", HandshakeSec: time.Now().Unix()},
		nil, descs, time.Now().Unix(), 1, map[string]bool{key: true})
	if peer.Key != key {
		t.Fatalf("Key: %q, want %q", peer.Key, key)
	}
	if !peer.Urgent {
		t.Error("el peer marcado por Key debería salir Urgent=true")
	}
	other := buildWGPeer(WGDumpPeer{Pubkey: realPubkey(8), AllowedIPs: "10.0.0.10/32"},
		nil, descs, time.Now().Unix(), 2, map[string]bool{key: true})
	if other.Urgent {
		t.Error("un peer sin marcar no puede salir Urgent=true")
	}
	if other.Key == key {
		t.Error("peers distintos no pueden compartir Key")
	}
}

// newUrgentLive: Live con BD real (tabla kv de db.Open) y engine para VPN.
func newUrgentLive(t *testing.T) (*Live, *db.DB) {
	t.Helper()
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	l := NewLive(nil, d, nil, nil)
	if err := l.engine.SetConfig(map[string]string{alerts.CatVPN: alerts.LevelAll}); err != nil {
		t.Fatalf("SetConfig vpn: %v", err)
	}
	return l, d
}

func TestSetWireGuardPeerUrgentPersistsInKV(t *testing.T) {
	l, d := newUrgentLive(t)
	key := WGPeerKey(realPubkey(3))
	if err := l.SetWireGuardPeerUrgent(key, true); err != nil {
		t.Fatalf("SetWireGuardPeerUrgent(true): %v", err)
	}
	if !l.WireGuardPeerUrgent(key) {
		t.Error("el peer debería quedar marcado en memoria")
	}
	if got := l.WireGuardUrgentPeers(); len(got) != 1 || got[0] != key {
		t.Errorf("WireGuardUrgentPeers = %v, want [%s]", got, key)
	}
	var raw string
	if err := d.QueryRow("SELECT value FROM kv WHERE key = ?", wgUrgentKey).Scan(&raw); err != nil {
		t.Fatalf("kv: %v", err)
	}
	if !strings.Contains(raw, key) {
		t.Errorf("kv %q no contiene la clave %q", raw, key)
	}
	// Reinicio: un Live nuevo sobre la misma BD recupera el flag.
	reloaded := NewLive(nil, d, nil, nil)
	if !reloaded.WireGuardPeerUrgent(key) {
		t.Error("el flag no sobrevive a un reinicio del servidor")
	}
	// Desmarcar lo quita de memoria y del kv.
	if err := reloaded.SetWireGuardPeerUrgent(key, false); err != nil {
		t.Fatalf("SetWireGuardPeerUrgent(false): %v", err)
	}
	if reloaded.WireGuardPeerUrgent(key) {
		t.Error("el peer debería quedar desmarcado")
	}
	if got := reloaded.WireGuardUrgentPeers(); len(got) != 0 {
		t.Errorf("WireGuardUrgentPeers = %v, want vacío", got)
	}
	// Y un tercer arranque no lo resucita.
	if NewLive(nil, d, nil, nil).WireGuardPeerUrgent(key) {
		t.Error("el flag desmarcado no debe reaparecer tras reiniciar")
	}
}

func TestSetWireGuardPeerUrgentRejectsInvalidKey(t *testing.T) {
	l, _ := newUrgentLive(t)
	for _, key := range []string{"", "con espacio", "a/b", strings.Repeat("x", 65)} {
		if err := l.SetWireGuardPeerUrgent(key, true); err == nil {
			t.Errorf("clave %q aceptada, debería rechazarse", key)
		}
	}
}

// Corrupto/no lista: el arranque no se rompe y no hay urgentes.
func TestLoadWGUrgentIgnoresGarbage(t *testing.T) {
	_, d := newUrgentLive(t)
	if _, err := d.Exec(`INSERT INTO kv (key, value) VALUES (?, ?)`, wgUrgentKey, `{"no":"es una lista"}`); err != nil {
		t.Fatalf("seed kv: %v", err)
	}
	reloaded := NewLive(nil, d, nil, nil)
	if got := reloaded.WireGuardUrgentPeers(); len(got) != 0 {
		t.Errorf("kv corrupto no debe producir urgentes: %v", got)
	}
}

// dropOnePeer: un ciclo de caída para un peer concreto y su alerta (el engine
// deduplica por categoría+título+router durante 5 min, así que un test de dos
// peers necesita dos Live separados, igual que dos incidentes reales).
func dropOnePeer(t *testing.T, peer WGPeer) AlertEvent {
	t.Helper()
	l, _ := newUrgentLive(t)
	l.wgActive = map[string]bool{peer.ID: true}
	l.wgActiveSince = map[string]time.Time{peer.ID: time.Now().Add(-2 * time.Hour)}
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{peer}}, "gw")
	for _, ev := range l.engine.List() {
		if ev.Type == alerts.TypeWireguardDisconnect {
			return ev
		}
	}
	t.Fatalf("sin alerta de caída para %s", peer.Name)
	return AlertEvent{}
}

// La alerta de caída de un peer urgente sale con Urgent=true; la de uno
// normal sigue en false. Categoría e ID no cambian (#1348/#1441).
func TestWireGuardDisconnectUrgencyFollowsFlag(t *testing.T) {
	urgent := WGPeer{ID: "site-a", Key: WGPeerKey(realPubkey(11)), Name: "Site A", Active: false}
	l, _ := newUrgentLive(t)
	if err := l.SetWireGuardPeerUrgent(urgent.Key, true); err != nil {
		t.Fatalf("marcar urgente: %v", err)
	}
	l.wgActive = map[string]bool{urgent.ID: true}
	l.wgActiveSince = map[string]time.Time{urgent.ID: time.Now().Add(-2 * time.Hour)}
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{urgent}}, "gw")

	byPeer := map[string]AlertEvent{}
	for _, ev := range l.engine.List() {
		if ev.Type == alerts.TypeWireguardDisconnect {
			byPeer[ev.Vars["peer"]] = ev
		}
	}
	site, ok := byPeer["Site A"]
	if !ok {
		t.Fatalf("sin alerta de caída para Site A: %v", byPeer)
	}
	if !site.Urgent {
		t.Error("la caída de un peer urgente debe salir Urgent=true")
	}
	if site.Category != alerts.CatVPN {
		t.Errorf("categoría: %q, want %q", site.Category, alerts.CatVPN)
	}
	if !strings.HasPrefix(site.ID, "alert-wg-down-") {
		t.Errorf("ID: %q, want prefijo alert-wg-down-", site.ID)
	}

	laptop := dropOnePeer(t, WGPeer{ID: "laptop", Key: WGPeerKey(realPubkey(12)), Name: "Laptop", Active: false})
	if laptop.Urgent {
		t.Error("la caída de un peer normal debe seguir en Urgent=false")
	}
	if laptop.Category != alerts.CatVPN {
		t.Errorf("categoría del peer normal: %q, want %q", laptop.Category, alerts.CatVPN)
	}
}

// El handshake de un peer urgente también avisa; el de uno normal, no.
func TestWireGuardHandshakeUrgencyFollowsFlag(t *testing.T) {
	l, _ := newUrgentLive(t)
	urgentKey := WGPeerKey(realPubkey(21))
	if err := l.SetWireGuardPeerUrgent(urgentKey, true); err != nil {
		t.Fatalf("marcar urgente: %v", err)
	}
	l.wgActive = map[string]bool{"otro": true}
	l.wgActiveSince = map[string]time.Time{"otro": time.Now()}
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "site-a", Key: urgentKey, Name: "Site A", Active: true},
		{ID: "otro", Key: WGPeerKey(realPubkey(22)), Name: "Otro", Active: true},
	}}, "gw")

	handshakes := map[string]bool{}
	for _, ev := range l.engine.List() {
		if ev.Type == alerts.TypeWireguardHandshake {
			handshakes[ev.Vars["peer"]] = ev.Urgent
		}
	}
	if u, ok := handshakes["Site A"]; !ok || !u {
		t.Errorf("handshake de Site A: urgente=%v (presente=%v), want true", u, ok)
	}
}

// Los 4 enlaces WG de la semántica son los mismos 4 nodos que dibuja el mapa:
// urgentes activos primero, después los activos normales (#1441).
func TestTopoSemanticsWGLinksUrgentFirst(t *testing.T) {
	wg := WireGuardStats{Peers: []WGPeer{
		{ID: "a", Active: true},
		{ID: "b", Active: true},
		{ID: "c", Active: true},
		{ID: "site-to-site", Active: true, Urgent: true},
		{ID: "quinta", Active: true},
		{ID: "caido", Active: false},
		{ID: "caido-urgente", Active: false, Urgent: true},
	}}
	sem := BuildTopoSemantics([]Router{{ID: "gw", Name: "GW", RoleBadge: "Principal"}}, nil, wg, nil, "", nil, nil, nil)
	got := []string{}
	for _, l := range sem.Links {
		if l.Kind == "wg" {
			got = append(got, l.From)
		}
	}
	want := []string{"peer-site-to-site", "peer-a", "peer-b", "peer-c"}
	if len(got) != len(want) {
		t.Fatalf("enlaces wg: %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("enlaces wg: %v, want %v", got, want)
		}
	}
}
