// wl_test.go — ParseWlWireless con la salida real capturada de un RT-AX92U
// con Merlin (dhd: nl80211 ciego, wl lo sabe todo).
package probe

import "testing"

const wlFixture = `==IF== wl1.1
04:d9:f5:27:76:04
a
target channel	48
CHSPEC 48/80 (0xe32a)
STA 48:B0:2D:03:B6:78 -73
STA 00:41:0E:80:51:25 -52
STA 38:B8:00:0A:24:37 -75
==IF== wl0.1
04:d9:f5:27:76:01
b
target channel	3
CHSPEC 11 (0x100b)
`

func TestParseWlWireless(t *testing.T) {
	clients, radios := ParseWlWireless(wlFixture)
	if len(clients) != 3 {
		t.Fatalf("clientes: %d, want 3", len(clients))
	}
	tv, ok := clients["38:B8:00:0A:24:37"]
	if !ok || tv.Band != "5 GHz" || tv.SignalDbm != -75 {
		t.Fatalf("TV: %+v", tv)
	}
	if len(radios) != 2 {
		t.Fatalf("radios: %d, want 2", len(radios))
	}
	if radios[0].Name != "5 GHz" || radios[0].Channel != 48 || radios[0].WidthMhz != 80 || radios[0].BSSID != "04:D9:F5:27:76:04" || radios[0].Clients != 3 {
		t.Fatalf("radio 5G: %+v", radios[0])
	}
	if radios[1].Name != "2.4 GHz" || radios[1].Channel != 3 || radios[1].WidthMhz != 20 || radios[1].BSSID != "04:D9:F5:27:76:01" {
		t.Fatalf("radio 2.4G: %+v", radios[1])
	}
}

func TestParseWlWirelessGarbage(t *testing.T) {
	// rssi no numérico (estación yendo en este mismo instante): el cliente
	// se omite en vez de inventar señal; la radio igualmente se emite.
	out := `==IF== wl0.1
04:d9:f5:27:76:01
b
target channel	3
STA AA:BB:CC:DD:EE:FF 
`
	clients, radios := ParseWlWireless(out)
	if len(clients) != 0 {
		t.Fatalf("clientes: %+v, want ninguno", clients)
	}
	if len(radios) != 1 || radios[0].Name != "2.4 GHz" || radios[0].Clients != 0 {
		t.Fatalf("radios: %+v", radios)
	}
}

func TestWlWidthMhz(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"48/80 (0xe32a)", 80},
		{"11/40", 40},
		{"36/160 (0x1a2b)", 160},
		{"11 (0x100b)", 20},
		{"", 0},
		{"foo", 0},
	}
	for _, c := range cases {
		if got := wlWidthMhz(c.in); got != c.want {
			t.Fatalf("wlWidthMhz(%q)=%d, want %d", c.in, got, c.want)
		}
	}
}

func TestWlBandFromChannelFallback(t *testing.T) {
	if b := wlBand("ax", 3); b != "2.4 GHz" {
		t.Fatalf("canal 3: %q", b)
	}
	if b := wlBand("ax", 149); b != "5 GHz" {
		t.Fatalf("canal 149: %q", b)
	}
	if b := wlBand("", 0); b != "" {
		t.Fatalf("sin datos: %q, want vacío", b)
	}
}
