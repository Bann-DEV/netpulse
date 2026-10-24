// netgearVitals_test.go — parsers de los vitales Netgear FastPath con
// muestras reales capturadas de un XS708T (firmware 7.0.0.24).
package snmp

import "testing"

func TestParseNetgearCpuUtil(t *testing.T) {
	vals := []string{
		"    5 Sec (  0.19%)   60 Sec (  0.16%)  300 Sec (  0.15%) ",
		"    5 Sec (  0.00%)   60 Sec (  0.18%)  300 Sec (  0.23%) ",
		"    5 Sec (  5.75%)   60 Sec (  5.39%)  300 Sec (  5.38%) ",
		"    5 Sec (  1.34%)   60 Sec (  0.22%)  300 Sec (  0.44%) ",
	}
	cpu, ok := ParseNetgearCpuUtil(vals)
	if !ok {
		t.Fatal("ok = false, want true con strings válidos")
	}
	// 0.19+0.00+5.75+1.34 = 7.28 → redondeo 7.
	if cpu != 7 {
		t.Fatalf("cpu = %d, want 7 (suma de la ventana de 5s)", cpu)
	}
}

func TestParseNetgearCpuUtilGarbage(t *testing.T) {
	if cpu, ok := ParseNetgearCpuUtil([]string{"firmware nuevo sin formato", ""}); ok || cpu != 0 {
		t.Fatalf("formato inparseable debe dar (0,false), tuve (%d,%v)", cpu, ok)
	}
}

func TestParseNetgearCpuUtilCapsAt100(t *testing.T) {
	vals := []string{"5 Sec ( 60.0%)", "5 Sec ( 55.0%)"}
	cpu, ok := ParseNetgearCpuUtil(vals)
	if !ok || cpu != 100 {
		t.Fatalf("cpu = %d/%v, want 100 techado", cpu, ok)
	}
}

func TestParseNetgearTemps(t *testing.T) {
	// XS708T: dos sensores, 48 y 56 °C; el punto caliente manda.
	temp, ok := ParseNetgearTemps([]int{48, 56})
	if !ok || temp != 56 {
		t.Fatalf("temp = %d/%v, want 56 (máximo de sensores)", temp, ok)
	}
	if _, ok := ParseNetgearTemps(nil); ok {
		t.Fatal("sin sensores ok debe ser false")
	}
}

func TestParseNetgearRam(t *testing.T) {
	// GS728TXP live reading: ~233 MB pool, ~50 MB free → ~79% used.
	if used, ok := ParseNetgearRam(50968, 238968); !ok || used != 79 {
		t.Fatalf("GS728TXP used = %d/%v, want 79", used, ok)
	}
	// XS708T live reading: ~486 MB pool, ~325 MB free → ~33% used.
	if used, ok := ParseNetgearRam(332580, 497656); !ok || used != 33 {
		t.Fatalf("XS708T used = %d/%v, want 33", used, ok)
	}
	// All free → 0% used.
	if used, ok := ParseNetgearRam(238968, 238968); !ok || used != 0 {
		t.Fatalf("all-free used = %d/%v, want 0", used, ok)
	}
	// Fully used (free 0) → 100%.
	if used, ok := ParseNetgearRam(0, 238968); !ok || used != 100 {
		t.Fatalf("fully-used used = %d/%v, want 100", used, ok)
	}
	// free > available (transient between the two gets) clamps to 0.
	if used, ok := ParseNetgearRam(300000, 238968); !ok || used != 0 {
		t.Fatalf("free>avail used = %d/%v, want 0", used, ok)
	}
	// Guards: no total, or negative free → not ok (RAM stays null).
	if _, ok := ParseNetgearRam(10, 0); ok {
		t.Fatal("avail<=0 must be not-ok")
	}
	if _, ok := ParseNetgearRam(-1, 238968); ok {
		t.Fatal("free<0 must be not-ok")
	}
}
