package adapters

import (
	"errors"
	"strings"
	"testing"
)

// TestFirmwareCompare cubre la comparación pura (issues #241 y #1412): con
// versiones parseables compara componente a componente; si no, cae al
// Contains insensible a mayúsculas (resultado fwAmbiguous).
func TestFirmwareCompare(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		target    string
		want      int
	}{
		{"sin target", "OpenWrt 23.05.5", "", fwMatch},
		{"target solo espacios", "OpenWrt 23.05.5", "   ", fwMatch},
		{"coincide exacto", "23.05.5", "23.05.5", fwMatch},
		{"coincide dentro de descripción", "OpenWrt 25.12.5 r33051-abc", "25.12.5", fwMatch},
		{"target más nuevo", "OpenWrt 25.12.5 r33051-abc", "25.12.6", fwNewer},
		{"target más viejo (downgrade)", "OpenWrt 25.12.5 r33051-abc", "25.12.4", fwOlder},
		{"salto de major", "OpenWrt 23.05.5 r20134-abc", "24.10.1", fwNewer},
		{"minor con patch", "OpenWrt 24.10.0", "24.10.1", fwNewer},
		{"target con major y minor", "OpenWrt 25.12.5", "25.13", fwNewer},
		{"instalado vacío", "", "24.10.1", fwAmbiguous},
		{"target con espacios alrededor", "OpenWrt 23.05.5", " 23.05.5 ", fwMatch},
		{"target no parseable legacy", "OpenWrt 23.05.5", "snapshot", fwAmbiguous},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firmwareCompare(c.installed, c.target); got != c.want {
				t.Fatalf("firmwareCompare(%q, %q) = %d, esperaba %d", c.installed, c.target, got, c.want)
			}
		})
	}
}

// boardWithDesc construye un BoardInfo con la descripción de firmware dada.
func boardWithDesc(desc string) *BoardInfo {
	b := &BoardInfo{}
	b.Release.Description = desc
	return b
}

// TestBuildRouterFirmwareTarget cubre la integración en buildRouter: flag
// FirmwareOutdated, FirmwareTarget, penalización de salud y alerta CatSystem.
func TestBuildRouterFirmwareTarget(t *testing.T) {
	// Target no coincide → flag, health -5 y alerta no urgente.
	l := NewLive(nil, nil, []RouterConfig{
		{ID: "r1", Host: "192.168.8.1", IsGateway: true},
	}, nil)
	p := &routerPolled{
		cfg:   RouterConfig{ID: "r1", Name: "Salón", Host: "192.168.8.2", FirmwareTarget: "25.12.5"},
		board: boardWithDesc("OpenWrt 23.05.5 r20134-abc"),
	}
	r := l.buildRouter(p, nil)
	if !r.FirmwareOutdated {
		t.Fatalf("FirmwareOutdated debería ser true: %+v", r)
	}
	if r.FirmwareTarget != "25.12.5" {
		t.Fatalf("FirmwareTarget=%q, esperaba 25.12.5", r.FirmwareTarget)
	}
	if r.Firmware != "OpenWrt 23.05.5 r20134-abc" {
		t.Fatalf("Firmware=%q", r.Firmware)
	}
	if r.Health != 95 {
		t.Fatalf("Health=%d, esperaba 95 (100-5)", r.Health)
	}
	list := l.AlertsEngine().List()
	if len(list) != 1 {
		t.Fatalf("alertas=%d, esperaba 1", len(list))
	}
	ev := list[0]
	if ev.Category != "system" || ev.Urgent || ev.Severity != "warn" || ev.RouterID != "r1" {
		t.Fatalf("alerta mal formada: %+v", ev)
	}
	if ev.Title != "Firmware outdated" {
		t.Fatalf("Title=%q", ev.Title)
	}
	if !strings.Contains(ev.Description, "25.12.5") || !strings.Contains(ev.Description, "23.05.5") {
		t.Fatalf("Description=%q", ev.Description)
	}

	// Target coincide → sin flag, health intacto, sin alerta nueva.
	l2 := NewLive(nil, nil, []RouterConfig{{ID: "g", Host: "192.168.8.1", IsGateway: true}}, nil)
	p2 := &routerPolled{
		cfg:   RouterConfig{ID: "r2", Name: "Estudio", Host: "192.168.8.3", FirmwareTarget: "23.05.5"},
		board: boardWithDesc("OpenWrt 23.05.5 r20134-abc"),
	}
	r2 := l2.buildRouter(p2, nil)
	if r2.FirmwareOutdated {
		t.Fatalf("FirmwareOutdated no debería marcarse: %+v", r2)
	}
	if r2.FirmwareTarget != "23.05.5" {
		t.Fatalf("FirmwareTarget=%q", r2.FirmwareTarget)
	}
	if r2.Health != 100 {
		t.Fatalf("Health=%d, esperaba 100", r2.Health)
	}
	if n := len(l2.AlertsEngine().List()); n != 0 {
		t.Fatalf("alertas=%d, esperaba 0", n)
	}

	// Sin target → sin flag y sin alerta.
	l3 := NewLive(nil, nil, []RouterConfig{{ID: "g", Host: "192.168.8.1", IsGateway: true}}, nil)
	p3 := &routerPolled{
		cfg:   RouterConfig{ID: "r3", Name: "Patio", Host: "192.168.8.4"},
		board: boardWithDesc("OpenWrt 23.05.5"),
	}
	r3 := l3.buildRouter(p3, nil)
	if r3.FirmwareOutdated || r3.FirmwareTarget != "" {
		t.Fatalf("sin target no debería marcar nada: %+v", r3)
	}
	if n := len(l3.AlertsEngine().List()); n != 0 {
		t.Fatalf("alertas=%d, esperaba 0", n)
	}
}

// TestBuildRouterFirmwareDowngrade (#1412): un target MÁS VIEJO que lo
// instalado alerta con wording propio, NO marca FirmwareOutdated y NO
// penaliza la salud.
func TestBuildRouterFirmwareDowngrade(t *testing.T) {
	l := NewLive(nil, nil, []RouterConfig{{ID: "g", Host: "192.168.8.1", IsGateway: true}}, nil)
	p := &routerPolled{
		cfg:   RouterConfig{ID: "r5", Name: "Salón", Host: "192.168.8.2", FirmwareTarget: "25.12.4"},
		board: boardWithDesc("OpenWrt 25.12.5 r33051-abc"),
	}
	r := l.buildRouter(p, nil)
	if r.FirmwareOutdated {
		t.Fatalf("downgrade no debe marcar FirmwareOutdated: %+v", r)
	}
	if r.Health != 100 {
		t.Fatalf("Health=%d, esperaba 100 (el downgrade no penaliza como desactualizado)", r.Health)
	}
	list := l.AlertsEngine().List()
	if len(list) != 1 {
		t.Fatalf("alertas=%d, esperaba 1", len(list))
	}
	ev := list[0]
	if ev.Title != "Firmware downgrade target" || ev.Type != "firmware-downgrade-target" {
		t.Fatalf("alerta de downgrade mal formada: %+v", ev)
	}
	if !strings.Contains(ev.Description, "25.12.4") || !strings.Contains(ev.Description, "25.12.5") {
		t.Fatalf("Description=%q", ev.Description)
	}
}

// TestBuildRouterFirmwareOncePerUnit (#1411): la alerta de firmware es UN
// episodio por unidad. Re-sondar la misma condición no re-firea; cambiar la
// versión o el target actualiza la misma alerta; al coincidir se resuelve.
func TestBuildRouterFirmwareOncePerUnit(t *testing.T) {
	l := NewLive(nil, nil, []RouterConfig{{ID: "g", Host: "192.168.8.1", IsGateway: true}}, nil)
	p := &routerPolled{
		cfg:   RouterConfig{ID: "r6", Name: "Salón", Host: "192.168.8.2", FirmwareTarget: "25.12.6"},
		board: boardWithDesc("OpenWrt 25.12.5 r33051-abc"),
	}
	l.buildRouter(p, nil)
	l.buildRouter(p, nil) // mismo ciclo: sin re-fire
	list := l.AlertsEngine().List()
	if len(list) != 1 {
		t.Fatalf("alertas=%d tras re-sondar, esperaba 1 (episodio único)", len(list))
	}
	if list[0].ID != "alert-firmware-r6" {
		t.Fatalf("ID=%q, esperaba ID estable alert-firmware-r6", list[0].ID)
	}
	// Cambia el target: misma alerta actualizada en sitio, no una copia.
	p.cfg.FirmwareTarget = "25.13.0"
	l.buildRouter(p, nil)
	list = l.AlertsEngine().List()
	if len(list) != 1 || !strings.Contains(list[0].Description, "25.13.0") {
		t.Fatalf("tras cambio de target: %d alertas, %+v", len(list), list)
	}
	// Cambia la versión instalada: episodio nuevo en la misma alerta.
	p.board = boardWithDesc("OpenWrt 25.12.7 r33051-abc")
	l.buildRouter(p, nil)
	list = l.AlertsEngine().List()
	if len(list) != 1 || !strings.Contains(list[0].Description, "25.12.7") {
		t.Fatalf("tras cambio de versión: %d alertas, %+v", len(list), list)
	}
	// El firmware alcanza el target: la alerta se resuelve y sale del feed.
	p.cfg.FirmwareTarget = "25.12.7"
	l.buildRouter(p, nil)
	if n := len(l.AlertsEngine().List()); n != 0 {
		t.Fatalf("alertas=%d tras resolver, esperaba 0", n)
	}
	// Reincidencia (mismatch otra vez): el mismo ID vuelve a alertar.
	p.cfg.FirmwareTarget = "25.12.8"
	l.buildRouter(p, nil)
	list = l.AlertsEngine().List()
	if len(list) != 1 || list[0].ID != "alert-firmware-r6" {
		t.Fatalf("reincidencia: %d alertas, %+v", len(list), list)
	}
}

// TestBuildRouterFirmwareSinBoard: target sin board (sin firmware leído) no
// debe marcar outdated ni emitir (evita falsos positivos en sondeo parcial).
func TestBuildRouterFirmwareSinBoard(t *testing.T) {
	l := NewLive(nil, nil, []RouterConfig{{ID: "g", Host: "192.168.8.1", IsGateway: true}}, nil)
	p := &routerPolled{
		cfg: RouterConfig{ID: "r4", Name: "Salón", Host: "192.168.8.2", FirmwareTarget: "25.12.5"},
	}
	r := l.buildRouter(p, nil)
	if r.FirmwareOutdated {
		t.Fatalf("sin board no debería marcar outdated: %+v", r)
	}
	if r.FirmwareTarget != "25.12.5" {
		t.Fatalf("FirmwareTarget debería reflejar el config aun sin board: %+v", r)
	}
	if n := len(l.AlertsEngine().List()); n != 0 {
		t.Fatalf("alertas=%d, esperaba 0", n)
	}
}

// Issue #257: un gateway detectado pero SIN acceso SSH (la clave del server
// no está autorizada) NO se muestra como "offline": status "unreachable" +
// accessMissing true (config issue, no power issue). Un fallo de conexión
// real (refused/timeout) sigue siendo "offline".
func TestBuildRouterAccessMissing(t *testing.T) {
	l := NewLive(nil, nil, []RouterConfig{{ID: "gw", Host: "192.168.8.1", IsGateway: true}}, nil)
	cfg := RouterConfig{ID: "gw", Host: "192.168.8.1", IsGateway: true}
	l.mu.Lock()
	l.lastErr["gw"] = errors.New("ssh 192.168.8.1: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]")
	l.mu.Unlock()
	r := l.offlineRouter(cfg)
	if r.Status != "unreachable" || !r.AccessMissing {
		t.Fatalf("sin acceso: status=%q accessMissing=%v", r.Status, r.AccessMissing)
	}
	l.mu.Lock()
	l.lastErr["gw"] = errors.New("ssh 192.168.8.1: dial tcp 192.168.8.1:22: connect: connection refused")
	l.mu.Unlock()
	r = l.offlineRouter(cfg)
	if r.Status != "offline" || r.AccessMissing {
		t.Fatalf("caído real: status=%q accessMissing=%v", r.Status, r.AccessMissing)
	}
	l.mu.Lock()
	delete(l.lastErr, "gw")
	l.mu.Unlock()
	r = l.offlineRouter(cfg)
	if r.Status != "offline" {
		t.Fatalf("sin dato previo: status=%q", r.Status)
	}
}

func TestIsAccessError(t *testing.T) {
	for _, m := range []string{
		"ssh h: handshake failed: ssh: unable to authenticate, attempted methods [none publickey]",
		"ssh h: handshake failed: ssh: no supported methods remain",
		"ssh h: permission denied (publickey)",
	} {
		if !isAccessError(errors.New(m)) {
			t.Fatalf("debería ser access error: %q", m)
		}
	}
	for _, m := range []string{
		"ssh h: dial tcp h:22: connect: connection refused",
		"ssh h: timeout (5s)",
		"ssh h: Process exited with status 127",
		"",
	} {
		if isAccessError(errors.New(m)) {
			t.Fatalf("no debería ser access error: %q", m)
		}
	}
	if isAccessError(nil) {
		t.Fatal("nil no es access error")
	}
}
