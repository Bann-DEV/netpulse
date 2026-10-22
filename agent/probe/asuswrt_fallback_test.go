// asuswrt_fallback_test.go — fallbacks portables del #1481 (fase 1):
// uptime por /proc/uptime, clientes/radios por `iw` (nl80211) y vecinos
// LLDP en texto plano. Los fixtures son capturas REALES recortadas de un
// ASUS GT-BE98 Pro (Asuswrt, kernel 4.19, lldpd 0.9.8, iw sobre nl80211).
package probe

import (
	"context"
	"testing"
)

const uptimeProcFixture = "70273.29 269277.55\n"

// iwDevFixture: `iw dev` real recortado a dos phys (uno 2.4 GHz con una
// interfaz AP, uno 5 GHz con otra) para exercising el agrupado por phy.
const iwDevFixture = `phy#3
	Interface wl3.1
		ifindex 32
		wdev 0x300000002
		addr 9a:7c:61:8f:37:e9
		ssid VB
		type AP
		channel 3 (2422 MHz), width: 20 MHz, center1: 2422 MHz
phy#0
	Interface wl0
		ifindex 24
		wdev 0x1
		addr 10:7c:61:8f:37:ec
		ssid D321F96D28F481AF28FEB9152F1B213A
		type AP
		channel 48 (5240 MHz), width: 160 MHz, center1: 5250 MHz
`

// iwStationFixture: salida combinada de CmdIwStationDump con el ==DEV==
// arriba y dos estaciones en wl3.1 + una en wl0 (captura real recortada).
const iwStationFixture = "==DEV==\n" + iwDevFixture +
	`==IF==wl3.1
Station 24:9e:7d:0a:c3:1a (on wl3.1)
	inactive time:	1000 ms
	rx bytes:	1889632
	rx packets:	6810
	tx bytes:	10787545
	tx packets:	40873
	tx failed:	23
	signal:  	-56 [-62] dBm
	signal avg:	-54 [-61] dBm
	tx bitrate:	65.0 MBit/s MCS 6 short GI
	rx bitrate:	72.2 MBit/s MCS 7 short GI
Station ec:0b:ae:f6:db:0a (on wl3.1)
	inactive time:	1000 ms
	rx bytes:	3177417
	tx bytes:	49829241
	signal:  	-65 [-64] dBm
	signal avg:	-65 [-64] dBm
	tx bitrate:	54.0 MBit/s
	rx bitrate:	54.0 MBit/s
==IF==wl0
Station 1c:5e:e6:38:36:7c (on wl0)
	inactive time:	4000 ms
	rx bytes:	1040745835
	tx bytes:	80697335
	signal:  	-42 [-41] dBm
	signal avg:	-42 [-41] dBm
	tx bitrate:	108.3 MBit/s MCS 7
	rx bitrate:	114.7 MBit/s MCS 7
`

// lldpTextFixture: `lldpcli show neighbors` real recortado (lldpd 0.9.8):
// un vecino con chassis mac + sysname + mgmt + caps y otro con chassis
// "local" y port id por mac.
const lldpTextFixture = `-------------------------------------------------------------------------------
LLDP neighbors:
-------------------------------------------------------------------------------
Interface:    eth0, via: LLDP, RID: 2, Time: 0 day, 10:10:04
  Chassis:
    ChassisID:    mac 08:bd:43:75:50:cd
    SysName:      XS708T
    SysDescr:     XS708T 8-Port 10-Gigabit Copper Smart Managed Pro Switch
    MgmtIP:       192.168.2.6
    Capability:   Bridge, on
    Capability:   Router, off
  Port:
    PortID:       local xg2
    PortDescr:    xg2
    TTL:          120
-------------------------------------------------------------------------------
Interface:    eth3, via: LLDP, RID: 1, Time: 0 day, 10:10:11
  Chassis:
    ChassisID:    local EVANGELION-X
  Port:
    PortID:       mac b0:6e:bf:82:9e:69
    TTL:          3601
-------------------------------------------------------------------------------
`

func TestParseUptimeSecPortatil(t *testing.T) {
	if got := ParseUptimeSec(uptimeProcFixture); got != 70273.29 {
		t.Fatalf("uptime = %v, want 70273.29", got)
	}
	for _, bad := range []string{"", "\n", "basura\n", "-3 0\n"} {
		if got := ParseUptimeSec(bad); got != 0 {
			t.Fatalf("ParseUptimeSec(%q) = %v, want 0", bad, got)
		}
	}
}

func TestParseIwWirelessAsuswrt(t *testing.T) {
	clients, radios := ParseIwWireless(iwStationFixture)
	if len(clients) != 3 {
		t.Fatalf("clientes = %d, want 3: %+v", len(clients), clients)
	}
	c := clients["24:9E:7D:0A:C3:1A"]
	if c.SignalDbm != -56 || c.Band != "2.4 GHz" || c.RxBytes != 1889632 || c.TxBytes != 10787545 {
		t.Fatalf("estación wl3.1 mal parseada: %+v", c)
	}
	if c := clients["1C:5E:E6:38:36:7C"]; c.Band != "5 GHz" || c.SignalDbm != -42 {
		t.Fatalf("estación wl0 mal parseada: %+v", c)
	}
	if len(radios) != 2 {
		t.Fatalf("radios = %d, want 2: %+v", len(radios), radios)
	}
	r24, r5 := radios[0], radios[1]
	if r24.Name != "2.4 GHz" || r24.Channel != 3 || r24.WidthMhz != 20 || r24.Clients != 2 || r24.BSSID != "9A:7C:61:8F:37:E9" {
		t.Fatalf("radio 2.4 GHz mal agrupada: %+v", r24)
	}
	if r5.Name != "5 GHz" || r5.Channel != 48 || r5.WidthMhz != 160 || r5.Clients != 1 {
		t.Fatalf("radio 5 GHz mal agrupada: %+v", r5)
	}
}

func TestParseLldpNeighborsTextAsuswrt(t *testing.T) {
	nbs := ParseLldpNeighborsText(lldpTextFixture)
	if len(nbs) != 2 {
		t.Fatalf("vecinos = %d, want 2: %+v", len(nbs), nbs)
	}
	n := nbs[0]
	if n.Port != "eth0" || n.ChassisMac != "08:BD:43:75:50:CD" || n.Chassis != "XS708T" ||
		n.Mgmt != "192.168.2.6" || n.PortDesc != "xg2" {
		t.Fatalf("vecino 1 mal parseado: %+v", n)
	}
	if len(n.Caps) != 1 || n.Caps[0] != "Bridge" {
		t.Fatalf("caps solo deben contar las 'on': %+v", n.Caps)
	}
	m := nbs[1]
	if m.Port != "eth3" || m.Chassis != "EVANGELION-X" || m.ChassisMac != "" || m.PortDesc != "b0:6e:bf:82:9e:69" {
		t.Fatalf("vecino 2 mal parseado: %+v", m)
	}
}

// TestProberFallbacksAsuswrt: sin ubus, sin iwinfo y sin JSON LLDP, el
// prober completo levanta uptime, clientes/radios y vecinos por los
// fallbacks portables del #1481.
func TestProberFallbacksAsuswrt(t *testing.T) {
	run := fakeRunner{outs: map[string]string{
		CmdProcUptime:        uptimeProcFixture,
		CmdProcStat:          "cpu  4705 356 584 3699 23 0 23 0 0 0\n",
		CmdNetDev:            "  eth0: 1000000 0 0 0 0 0 0 0 500000 0\n",
		CmdBridgeMAC:         "10:7c:61:8f:37:e8\n",
		CmdPortStates:        "eth0 up 1000\neth1 up 1000\n",
		CmdIwStationDump:     iwStationFixture,
		CmdLldpCheck:         "/usr/sbin/lldpcli\n",
		CmdLldpNeighbors:     "", // lldpd sin JSON o salida vacía
		CmdLldpNeighborsText: lldpTextFixture,
	}}
	p := NewProber(run, Options{GwPingTarget: "192.168.2.1", ScanInterval: ScanDisabled})

	pl := p.Build(context.Background(), "gt-be98-pro", "3.0.19")
	if pl.Data.System == nil || pl.Data.System.SysInfo == nil || pl.Data.System.SysInfo.Uptime != 70273.29 {
		t.Fatalf("uptime por /proc/uptime no llegó: %+v", pl.Data.System)
	}
	if pl.Data.Wireless == nil || len(pl.Data.Wireless.Clients) != 3 || len(pl.Data.Wireless.Radios) != 2 {
		t.Fatalf("wireless por iw no llegó: %+v", pl.Data.Wireless)
	}
	if pl.Data.Lldp == nil || !pl.Data.Lldp.Available || len(pl.Data.Lldp.Neighbors) != 2 {
		t.Fatalf("lldp en texto no llegó: %+v", pl.Data.Lldp)
	}
}
