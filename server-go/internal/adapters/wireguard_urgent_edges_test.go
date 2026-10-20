// wireguard_urgent_edges_test.go - aristas del flag urgente (#1445).
package adapters

import (
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/alerts"
)

type notifySpy struct{ got []alerts.AlertEvent }

func (n *notifySpy) Notify(ev alerts.AlertEvent) { n.got = append(n.got, ev) }

// 1) Coalescing: dos urgentes cayendo en el MISMO ciclo producen DOS
// alertas y DOS notificaciones. Antes (#1443 era Emit con dedup de 5 min)
// la segunda caída se tragaba: el operador no se enteraba del segundo peer.
func TestWireGuardUrgentSimultaneousDropsAllNotify(t *testing.T) {
	spy := &notifySpy{}
	l := wgAlertLive(t)
	l.engine.SetNotifier(spy)
	ka, kb := WGPeerKey(realPubkey(41)), WGPeerKey(realPubkey(42))
	if err := l.SetWireGuardPeerUrgent(ka, true); err != nil {
		t.Fatalf("urgente A: %v", err)
	}
	if err := l.SetWireGuardPeerUrgent(kb, true); err != nil {
		t.Fatalf("urgente B: %v", err)
	}
	l.wgActive = map[string]bool{ka: true, kb: true}
	l.wgActiveSince = map[string]time.Time{ka: time.Now().Add(-time.Hour), kb: time.Now().Add(-time.Hour)}
	l.wgPrimed = true

	// Ambos caen en el mismo ciclo: el dump los sigue listando, inactivos.
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{
		{ID: "a", Key: ka, Name: "Site A", Active: false},
		{ID: "b", Key: kb, Name: "Site B", Active: false},
	}}, "gw")

	if got := wgDisconnects(l); len(got) != 2 {
		t.Fatalf("alertas de caída: 2, hay %d", len(got))
	}
	urgentNotifies := 0
	for _, ev := range spy.got {
		if ev.Type == alerts.TypeWireguardDisconnect && ev.Urgent {
			urgentNotifies++
		}
	}
	if urgentNotifies != 2 {
		t.Fatalf("notificaciones urgentes: 2, hay %d (coalescing)", urgentNotifies)
	}
}

// 2) Clave urgente huérfana: el flag sobrevive ausencias sueltas (dump
// parcial #714) y se recoge tras wgUrgentPruneMisses sondeos seguidos.
func TestWireGuardUrgentPruneAfterMisses(t *testing.T) {
	l := wgAlertLive(t)
	ka := WGPeerKey(realPubkey(43))
	if err := l.SetWireGuardPeerUrgent(ka, true); err != nil {
		t.Fatalf("urgente: %v", err)
	}
	other := WGPeer{ID: "x", Key: WGPeerKey(realPubkey(44)), Name: "X", Active: true}

	// Dump sin el peer A: dos sondeos no bastan.
	l.pruneWGUrgent([]WGPeer{other})
	l.pruneWGUrgent([]WGPeer{other})
	if !l.WireGuardPeerUrgent(ka) {
		t.Fatal("el flag no debe recogerse con 2 ausencias")
	}
	// Tercera ausencia consecutiva: se recoge.
	l.pruneWGUrgent([]WGPeer{other})
	if l.WireGuardPeerUrgent(ka) {
		t.Fatal("tras 3 ausencias seguidas el flag huérfano se recoge")
	}
	if got := l.WireGuardUrgentPeers(); len(got) != 0 {
		t.Fatalf("diagnóstico sin claves huérfanas: %v", got)
	}
}

// 2b) Un dump vacío NO cuenta ausencias: sin peers no hay evidencia.
func TestWireGuardUrgentPruneSkipsEmptyDump(t *testing.T) {
	l := wgAlertLive(t)
	ka := WGPeerKey(realPubkey(45))
	if err := l.SetWireGuardPeerUrgent(ka, true); err != nil {
		t.Fatalf("urgente: %v", err)
	}
	for i := 0; i < 10; i++ {
		l.pruneWGUrgent(nil)
	}
	if !l.WireGuardPeerUrgent(ka) {
		t.Fatal("dump vacío no debe recoger flags")
	}
}

// 2c) Si el peer reaparece, el contador de ausencias se reinicia.
func TestWireGuardUrgentPruneMissCounterResets(t *testing.T) {
	l := wgAlertLive(t)
	ka := WGPeerKey(realPubkey(46))
	if err := l.SetWireGuardPeerUrgent(ka, true); err != nil {
		t.Fatalf("urgente: %v", err)
	}
	other := WGPeer{ID: "x", Key: WGPeerKey(realPubkey(47)), Name: "X", Active: true}
	l.pruneWGUrgent([]WGPeer{other})
	l.pruneWGUrgent([]WGPeer{other})
	l.pruneWGUrgent([]WGPeer{ // reaparece: reinicio
		other, {ID: "a", Key: ka, Name: "A", Active: true},
	})
	l.pruneWGUrgent([]WGPeer{other})
	l.pruneWGUrgent([]WGPeer{other})
	if !l.WireGuardPeerUrgent(ka) {
		t.Fatal("la reaparición reinicia el contador: con 2 ausencias nuevas no se recoge")
	}
}

// 3) Peer urgente que DESAPARECE del dump en el ciclo de su caída: la
// alerta de caída conserva Urgent=true (respaldo del conjunto persistido).
func TestWireGuardUrgentDropAbsentFromDumpStaysUrgent(t *testing.T) {
	l := wgAlertLive(t)
	ka := WGPeerKey(realPubkey(48))
	if err := l.SetWireGuardPeerUrgent(ka, true); err != nil {
		t.Fatalf("urgente: %v", err)
	}
	l.wgActive = map[string]bool{ka: true}
	l.wgActiveSince = map[string]time.Time{ka: time.Now().Add(-time.Hour)}
	l.wgPrimed = true

	// El dump ya NO lista al peer (el router lo borró al caer).
	l.applyWireGuardTransitions(&WireGuardStats{Peers: []WGPeer{}}, "gw")

	got := wgDisconnects(l)
	if len(got) != 1 {
		t.Fatalf("caída: 1 alerta, hay %d", len(got))
	}
	if !got[0].Urgent {
		t.Error("la caída de un peer urgente ausente del dump sigue siendo Urgent=true")
	}
}
