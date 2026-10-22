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
