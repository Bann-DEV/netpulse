// wireguard_connect_test.go - connects de túneles iniciados por la unidad
// local y flaps (#1443).
package adapters

import (
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/alerts"
)

func wgHandshakes(l *Live, peer string) []alerts.AlertEvent {
	out := []alerts.AlertEvent{}
	for _, ev := range l.engine.List() {
		if ev.Type == alerts.TypeWireguardHandshake && (peer == "" || ev.Vars["peer"] == peer) {
			out = append(out, ev)
		}
	}
	return out
}

// El escenario reportado: el túnel lo inicia la unidad local. El ciclo
// previo no tenía NINGÚN peer activo (túnel caído), así que con el guarda
// viejo len(wgActive)>0 el connect se perdía para siempre.
func TestWireGuardLocalInitiatedConnectNotLost(t *testing.T) {
	l := wgAlertLive(t)
	key := WGPeerKey(realPubkey(31))

	// Ciclo 1 (post-boot): el túnel está caído; el peer aparece en el dump
	// pero inactivo. Warmup: nada suena.
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "site-a", Key: key, Name: "Site A", Active: false},
	}}, "gw")
	if got := wgHandshakes(l, "Site A"); len(got) != 0 {
		t.Fatalf("warmup: 0 handshakes, hay %d", len(got))
	}

	// Ciclo 2: la unidad local inicia el túnel; el handshake aparece en el
	// dump. El connect DEBE sonar aunque el ciclo previo no tuviera activos.
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "site-a", Key: key, Name: "Site A", Active: true},
	}}, "gw")
	if got := wgHandshakes(l, "Site A"); len(got) != 1 {
		t.Fatalf("connect del túnel local: 1 handshake, hay %d", len(got))
	}
}

// Flaps repetidos: cada reconexión emite SU connect. Con el dedup de 5 min
// (mismo título "WireGuard handshake") los flaps rápidos se tragaban. Los
// ciclos van separados unos ms para que los IDs (timestamp) no colisionen:
// en producción los flaps están separados por segundos como mínimo.
func TestWireGuardFlapsEachEmitConnect(t *testing.T) {
	l := wgAlertLive(t)
	key := WGPeerKey(realPubkey(32))
	peer := WGPeer{ID: "site-b", Key: key, Name: "Site B", Active: false}

	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{peer}}, "gw") // warmup: túnel caído
	peer.Active = true
	time.Sleep(5 * time.Millisecond)
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{peer}}, "gw") // connect 1
	peer.Active = false
	time.Sleep(5 * time.Millisecond)
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{peer}}, "gw") // disconnect
	peer.Active = true
	time.Sleep(5 * time.Millisecond)
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{peer}}, "gw") // connect 2 (reconexión)

	if got := wgHandshakes(l, "Site B"); len(got) != 2 {
		t.Fatalf("dos flaps: 2 handshakes, hay %d", len(got))
	}
	if got := wgDisconnects(l); len(got) != 1 {
		t.Fatalf("un disconnect, hay %d", len(got))
	}
}

// El tracker se indexa por Key estable: si el ID derivado del dump cambia
// ("peer-0" pasa a ser "peer-1" al reordenarse los peers), NO debe emitirse
// un disconnect+connect fantasma para el mismo peer. La única activación del
// peer quedó consumida por el warmup: el total de eventos debe ser cero.
func TestWireGuardTrackerKeyedByStableKey(t *testing.T) {
	l := wgAlertLive(t)
	key := WGPeerKey(realPubkey(33))

	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "peer-0", Key: key, Name: "Site C", Active: true},
	}}, "gw") // warmup: activación consumida sin connect
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "peer-0", Key: key, Name: "Site C", Active: true},
	}}, "gw") // estable, sin eventos
	// Reorden del dump: mismo peer (misma Key), distinto índice de ID.
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "peer-1", Key: key, Name: "Site C", Active: true},
	}}, "gw")

	if got := wgHandshakes(l, "Site C"); len(got) != 0 {
		t.Fatalf("sin connects por cambio de ID: 0, hay %d", len(got))
	}
	if got := wgDisconnects(l); len(got) != 0 {
		t.Fatalf("sin disconnects por cambio de ID: 0, hay %d", len(got))
	}
}

// Tras un reinicio (wgPrimed a false) con los túneles ya activos, el warmup
// sigue sin emitir connects: no hay tormenta de alertas en el arranque.
func TestWireGuardBootWarmupStillSkipsConnects(t *testing.T) {
	l := wgAlertLive(t)
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "site-d", Key: WGPeerKey(realPubkey(34)), Name: "Site D", Active: true},
	}}, "gw")
	if got := wgHandshakes(l, ""); len(got) != 0 {
		t.Fatalf("warmup post-boot: 0 handshakes, hay %d", len(got))
	}
	if !l.wgPrimed {
		t.Error("wgPrimed debe quedar true tras el primer ciclo")
	}
}
