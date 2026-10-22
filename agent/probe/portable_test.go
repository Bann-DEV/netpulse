// portable_test.go — parsers portables del phase 1.5 (#1500): meminfo,
// timezone, ruta default y la WAN por uplink runtime en equipos sin layout.
// Fixtures reales recortados de un GT-BE98 Pro (Asuswrt/Merlin) y un
// DS1821+ (DSM) donde aplica.
package probe

import "testing"

func TestParseMeminfoMem(t *testing.T) {
	m := parseMeminfoFieldsKB(`MemTotal:       32841568 kB
MemFree:         9959988 kB
MemAvailable:   24142564 kB
Buffers:          512128 kB
Cached:         12582912 kB
`)
	if m.total != 32841568 || m.avail != 24142564 || m.free != 9959988 || m.buffered != 512128 || m.cached != 12582912 {
		t.Fatalf("campos meminfo: %+v", m)
	}
	// Kernel sin MemAvailable: aproxima con MemFree.
	m = parseMeminfoFieldsKB("MemTotal: 1000 kB\nMemFree: 400 kB\n")
	if m.total != 1000 || m.avail != 400 {
		t.Fatalf("fallback MemFree: %+v", m)
	}
	if m := parseMeminfoFieldsKB("basura\n"); m.total != 0 {
		t.Fatalf("basura debía dar 0, dio %+v", m)
	}
}

func TestParseTimezoneLocaltime(t *testing.T) {
	cases := map[string]string{
		"/usr/share/zoneinfo/Asia/Shanghai":     "Asia/Shanghai",
		"/rom/usr/share/zoneinfo/Asia/Shanghai": "Asia/Shanghai",
		"/usr/share/zoneinfo/Europe/Madrid":     "Europe/Madrid",
		"/etc/localtime":                        "",
		"":                                      "",
	}
	for link, want := range cases {
		if got := parseTimezoneLocaltime(link); got != want {
			t.Fatalf("parseTimezoneLocaltime(%q) = %q, want %q", link, got, want)
		}
	}
}

func TestParseDefaultRouteIface(t *testing.T) {
	out := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0102A8C0	0003	0	0	10	00000000	0	0	0
br0	00000000	00000000	0001	0	0	20	00000000	0	0	0
eth1	0002A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`
	if got := parseDefaultRouteIface(out); got != "eth0" {
		t.Fatalf("default route = %q, want eth0 (métrica mínima)", got)
	}
	if got := parseDefaultRouteIface("basura\n"); got != "" {
		t.Fatalf("basura debía dar vacío, dio %q", got)
	}
}

// Sin layout y con uplink runtime físico: la WAN es esa boca aunque exista
// eth1 (la heurística ciega del #847 no debe pisar al runtime).
func TestBuildEthPortsUplinkFisicoSinLayout(t *testing.T) {
	states := ParsePortStates("eth0 up 1000\neth1 up 1000\neth4 up 1000\n")
	ifaces := map[string]IfRate{"eth0": {}, "eth1": {}, "eth4": {}}
	ports := BuildEthPorts(nil, states, nil, ifaces, "eth4")
	if len(ports) != 3 {
		t.Fatalf("bocas: %+v", ports)
	}
	if ports[0].ID != "wan" || ports[0].Iface != "eth4" {
		t.Fatalf("WAN debía ser eth4: %+v", ports[0])
	}
}

// Sin layout y con uplink sobre bridge: la WAN es el miembro con vecino
// LLDP aunque otro cargue más rx (tráfico local puenteado).
func TestBuildEthPortsUplinkBridgeMiembroMaxRx(t *testing.T) {
	states := ParsePortStates("eth0 up 1000\neth1 up 1000\neth3 up 1000\nbr0 up 1000\n")
	members := map[string]bool{"eth0": true, "eth1": true, "eth3": true}
	ifaces := map[string]IfRate{
		"eth0": {IfCounters: IfCounters{Rx: 188583580}},
		"eth1": {IfCounters: IfCounters{Rx: 40756909}},
		"eth3": {IfCounters: IfCounters{Rx: 619101463}},
	}
	// Uplink bridge ya resuelto por bridgeMemberUplink en probeFDB: aquí se
	// comprueba que BuildEthPorts acepta el miembro físico como uplink.
	ports := BuildEthPorts(nil, states, members, ifaces, "eth0")
	if len(ports) != 3 || ports[0].ID != "wan" || ports[0].Iface != "eth0" {
		t.Fatalf("WAN debía ser eth0: %+v", ports)
	}
}

// bridgeMemberUplink: LLDP gana sobre rx, y los empates se resuelven por
// nombre ordenado (sin baile entre sondeos, review de #1500).
func TestBridgeMemberUplinkPrefiereLldp(t *testing.T) {
	states := ParsePortStates("eth0 up 1000\neth1 up 1000\neth3 up 1000\nbr0 up 1000\n")
	members := map[string]bool{"eth0": true, "eth1": true, "eth3": true}
	ifaces := map[string]IfRate{
		"eth0": {IfCounters: IfCounters{Rx: 188583580}},
		"eth3": {IfCounters: IfCounters{Rx: 619101463}},
	}
	if got := bridgeMemberUplink(members, map[string]bool{"eth0": true}, states, ifaces); got != "eth0" {
		t.Fatalf("con vecino LLDP debía ganar eth0, dio %q", got)
	}
	if got := bridgeMemberUplink(members, nil, states, ifaces); got != "eth3" {
		t.Fatalf("sin LLDP debía ganar el de más rx (eth3), dio %q", got)
	}
	// Empate de rx con dos miembros LLDP: gana el primero en orden de nombre.
	tie := map[string]IfRate{
		"eth1": {IfCounters: IfCounters{Rx: 500}},
		"eth0": {IfCounters: IfCounters{Rx: 500}},
	}
	if got := bridgeMemberUplink(members, map[string]bool{"eth0": true, "eth1": true}, states, tie); got != "eth0" {
		t.Fatalf("empate LLDP debía ganar eth0 (orden de nombre), dio %q", got)
	}
	if got := bridgeMemberUplink(map[string]bool{}, nil, states, ifaces); got != "" {
		t.Fatalf("sin miembros cualificados debía dar vacío, dio %q", got)
	}
}

// Sin uplink runtime se conserva la heurística clásica (eth1).
func TestBuildEthPortsSinUplinkMantieneHeuristica(t *testing.T) {
	states := ParsePortStates("eth0 up 1000\neth1 up 1000\n")
	ifaces := map[string]IfRate{"eth0": {}, "eth1": {}}
	ports := BuildEthPorts(nil, states, nil, ifaces, "")
	if len(ports) != 2 || ports[0].ID != "wan" || ports[0].Iface != "eth1" {
		t.Fatalf("sin uplink la WAN heurística es eth1: %+v", ports)
	}
}
