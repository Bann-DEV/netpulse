// topology_child_speed_test.go - velocidad del enlace desde la boca del hijo
// (#1429).
package adapters

import "testing"

// El caso de crowedavid: enlace FDB sw1↔ap1 sin velocidad en el lado del
// padre (la boca del switch no reporta o no casa); el HIJO (OpenWrt) sabe la
// velocidad negociada de su propia boca de uplink (childPort de la evidencia
// FDB).
func TestFillUplinkSpeedsFromChild(t *testing.T) {
	polled := map[string]*routerPolled{
		"ap1": {ports: []EthPort{
			{ID: "lan1", Up: true, Speed: "1 Gbps"},
			{ID: "wan", Up: true, Speed: "1 Gbps"},
		}},
		"ap2": {ports: []EthPort{
			{ID: "lan1", Up: true, Speed: "2.5 Gbps"},
		}},
	}
	evidence := map[string]topoParent{
		"ap1": {parent: "sw1", port: "1/0/5", childPort: "wan"},
		"ap2": {parent: "sw1", port: "1/0/7", childPort: "lan1"},
	}
	links := []TopoLink{
		{From: "sw1", To: "ap1", Kind: "uplink", Port: "1/0/5"}, // el padre no aportó velocidad
		{From: "sw1", To: "ap2", Kind: "uplink", Port: "1/0/7"},
	}
	fillUplinkSpeedsFromChild(polled, evidence, links)
	if links[0].SpeedMbps != 1000 {
		t.Fatalf("sw1-ap1 desde la boca del hijo (wan 1G): %d, want 1000", links[0].SpeedMbps)
	}
	if links[1].SpeedMbps != 2500 {
		t.Fatalf("sw1-ap2 desde la boca del hijo (lan1 2.5G): %d, want 2500", links[1].SpeedMbps)
	}
}

// El lado del padre manda cuando ambos extremos reportan (son el mismo
// cable; el dato del lado que sondea el enlace es el directo).
func TestFillUplinkSpeedsFromChildKeepsParent(t *testing.T) {
	polled := map[string]*routerPolled{
		"ap1": {ports: []EthPort{{ID: "wan", Up: true, Speed: "100 Mbps"}}},
	}
	evidence := map[string]topoParent{"ap1": {parent: "sw1", port: "1/0/5", childPort: "wan"}}
	links := []TopoLink{{From: "sw1", To: "ap1", Kind: "uplink", Port: "1/0/5", SpeedMbps: 1000}}
	fillUplinkSpeedsFromChild(polled, evidence, links)
	if links[0].SpeedMbps != 1000 {
		t.Fatalf("el lado del padre no se pisa: %d, want 1000", links[0].SpeedMbps)
	}
}

// Sin childPort en la evidencia (uplink resuelto por otro camino) no hay
// nada que mirar en el hijo: la "—" honesta se respeta.
func TestFillUplinkSpeedsFromChildNoEvidence(t *testing.T) {
	polled := map[string]*routerPolled{
		"ap1": {ports: []EthPort{{ID: "wan", Up: true, Speed: "1 Gbps"}}},
	}
	links := []TopoLink{{From: "sw1", To: "ap1", Kind: "uplink", Port: "1/0/5"}}
	fillUplinkSpeedsFromChild(polled, nil, links)
	if links[0].SpeedMbps != 0 {
		t.Fatalf("sin evidencia no se inventa: %d, want 0", links[0].SpeedMbps)
	}
}

// Boca del hijo caída (Down): no afirma velocidad sobre un puerto que no
// está levantado, aunque la tabla guarde un valor.
func TestFillUplinkSpeedsFromChildDownPort(t *testing.T) {
	polled := map[string]*routerPolled{
		"ap1": {ports: []EthPort{{ID: "wan", Up: false, Speed: "1 Gbps"}}},
	}
	evidence := map[string]topoParent{"ap1": {parent: "sw1", port: "1/0/5", childPort: "wan"}}
	links := []TopoLink{{From: "sw1", To: "ap1", Kind: "uplink", Port: "1/0/5"}}
	fillUplinkSpeedsFromChild(polled, evidence, links)
	if links[0].SpeedMbps != 0 {
		t.Fatalf("boca del hijo caída: %d, want 0", links[0].SpeedMbps)
	}
}
