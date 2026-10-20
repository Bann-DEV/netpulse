// health_vpn_test.go - componente VPN de la nota de salud (#1442).
package adapters

import (
	"strings"
	"testing"
)

// La interfaz caída (interfaces descubiertas pero ninguna responde, quirk
// #714) resta y aparece en el breakdown.
func TestComputeHealthWireGuardInterfaceDown(t *testing.T) {
	h := computeHealth(nil, nil, &WireGuardStats{Interface: "wg0", Status: "inactive"})
	if h.Score != 90 {
		t.Fatalf("score: %d, want 90 (-10 interfaz caída)", h.Score)
	}
	found := false
	for _, d := range h.Breakdown {
		if d.Label == "WireGuard caído" && d.Delta == -10 {
			found = true
		}
	}
	if !found {
		t.Fatalf("breakdown sin 'WireGuard caído -10': %+v", h.Breakdown)
	}
}

// Sin interfaces WireGuard en el router (Interface vacío con estado
// "inactive", quirk #714) NO penaliza: no hay VPN que vigilar.
func TestComputeHealthNoWireGuardNoPenalty(t *testing.T) {
	h := computeHealth(nil, nil, &WireGuardStats{Interface: "", Status: "inactive"})
	if h.Score != 100 {
		t.Fatalf("score: %d, want 100 (sin WG no hay penalización)", h.Score)
	}
	if len(h.Breakdown) != 0 {
		t.Fatalf("breakdown vacío: %+v", h.Breakdown)
	}
}

// Un peer urgente caído resta acotado y sale en el breakdown con su nombre.
func TestComputeHealthUrgentPeerDown(t *testing.T) {
	wg := &WireGuardStats{
		Interface: "wg0", Status: "active",
		Peers: []WGPeer{
			{ID: "a", Name: "Site A", Active: true},
			{ID: "b", Name: "Site B", Active: false, Urgent: true},
		},
	}
	h := computeHealth(nil, nil, wg)
	if h.Score != 94 {
		t.Fatalf("score: %d, want 94 (-6 un peer urgente caído)", h.Score)
	}
	found := false
	for _, d := range h.Breakdown {
		if strings.Contains(d.Label, "Site B") && d.Delta == -6 {
			found = true
		}
	}
	if !found {
		t.Fatalf("breakdown sin 'Site B -6': %+v", h.Breakdown)
	}
}

// Varios urgentes caídos: el subtotal queda acotado (máx -12) para que un
// enjambre de peers no domine la nota.
func TestComputeHealthUrgentPeersCapped(t *testing.T) {
	wg := &WireGuardStats{
		Interface: "wg0", Status: "active",
		Peers: []WGPeer{
			{ID: "a", Name: "A", Active: false, Urgent: true},
			{ID: "b", Name: "B", Active: false, Urgent: true},
			{ID: "c", Name: "C", Active: false, Urgent: true},
			{ID: "d", Name: "D", Active: false, Urgent: true},
		},
	}
	h := computeHealth(nil, nil, wg)
	if h.Score != 88 {
		t.Fatalf("score: %d, want 88 (-12 acotado pese a 4 urgentes)", h.Score)
	}
}

// Con la interfaz caída no se cuentan los peers urgentes: están caídos por
// ella, no por sí mismos (sin doble penalización).
func TestComputeHealthInterfaceDownSkipsPeers(t *testing.T) {
	wg := &WireGuardStats{
		Interface: "wg0", Status: "inactive",
		Peers: []WGPeer{{ID: "b", Name: "Site B", Active: false, Urgent: true}},
	}
	h := computeHealth(nil, nil, wg)
	if h.Score != 90 {
		t.Fatalf("score: %d, want 90 (solo la interfaz, sin doble penalización)", h.Score)
	}
}

// Los peers normales (no urgentes) caídos no tocan la nota.
func TestComputeHealthNormalPeerDownIgnored(t *testing.T) {
	wg := &WireGuardStats{
		Interface: "wg0", Status: "active",
		Peers: []WGPeer{{ID: "b", Name: "Laptop", Active: false}},
	}
	h := computeHealth(nil, nil, wg)
	if h.Score != 100 {
		t.Fatalf("score: %d, want 100 (peer normal caído no penaliza)", h.Score)
	}
}
