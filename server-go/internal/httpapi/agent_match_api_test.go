package httpapi_test

import (
	"fmt"
	"testing"
	"time"
)

// TestAgentsListResolvesRouterIdByHostname verifica que GET /api/agents
// expone routerId incluso cuando el slug del agente no coincide con el id del
// router (#282).
func TestAgentsListResolvesRouterIdByHostname(t *testing.T) {
	ts := makeAgentTestServer(t)

	// Insertar un router cuyo id autogenerado difiere del slug elegido.
	_, err := ts.db.Exec("INSERT INTO routers (id, name, host, type, is_gateway, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"gl-inet-gl-mt6000", "flint2", "192.168.10.1", "glinet", 1, time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("insert router: %v", err)
	}

	_, token, _ := createAgentToken(t, ts, "flint2")

	// Payload con hostname que casa con el name del router.
	payload := fmt.Sprintf(`{"router":"flint2","ts":%d,"version":"0.1.0","data":{"system":{"sysinfo":{"uptime":100,"load":[0,0,0],"memory":{"total":100,"free":50,"buffered":0,"available":50}},"board":{"hostname":"flint2","model":"GL-MT6000"},"cpu":10,"temp":40},"wireless":{"clients":{}},"dhcp":{"leases":[]},"fdb":{"macs":{}}}}`, time.Now().Unix())
	res := ingest(t, ts, token, "10.0.5.1", payload)
	res.Body.Close()
	if res.StatusCode != 202 {
		t.Fatalf("ingest: %d", res.StatusCode)
	}

	res = get(t, ts.URL, "/api/agents", ts.cookie)
	body := readJSON(t, res)
	agents, _ := body["agents"].([]any)
	var flint2 map[string]any
	for _, a := range agents {
		m, _ := a.(map[string]any)
		if m["slug"] == "flint2" {
			flint2 = m
		}
	}
	if flint2 == nil {
		t.Fatalf("agente no listado: %v", body)
	}
	if flint2["routerId"] != "gl-inet-gl-mt6000" {
		t.Fatalf("routerId esperado gl-inet-gl-mt6000, got %v", flint2["routerId"])
	}
}

// #1334: dos routers con hostname duplicado (APs puente idénticos) se
// resuelven por bridge MAC: la identidad física manda sobre el nombre.
func TestAgentsListResolvesDuplicateHostnameByBridgeMAC(t *testing.T) {
	ts := makeAgentTestServer(t)
	for _, row := range []struct {
		id, host, mac string
	}{
		{"jidu6401", "192.168.1.1", "AA:AA:AA:AA:AA:01"},
		{"jidu6401-2", "192.168.1.2", "AA:AA:AA:AA:AA:02"},
	} {
		if _, err := ts.db.Exec("INSERT INTO routers (id, name, host, type, mac, is_gateway, created_at) VALUES (?, 'Jidu6401', ?, 'openwrt', ?, 0, ?)", row.id, row.host, row.mac, time.Now().UnixMilli()); err != nil {
			t.Fatalf("insert router %s: %v", row.id, err)
		}
	}
	_, token, _ := createAgentToken(t, ts, "ap-agent")
	payload := fmt.Sprintf(`{"router":"ap-agent","ts":%d,"version":"0.1.0","data":{"system":{"sysinfo":{"uptime":100,"load":[0,0,0],"memory":{"total":100,"free":50,"buffered":0,"available":50}},"board":{"hostname":"Jidu6401","model":"Jidu6401"},"bridgeMac":"AA:AA:AA:AA:AA:02","cpu":10,"temp":40},"wireless":{"clients":{}},"dhcp":{"leases":[]},"fdb":{"macs":{}}}}`, time.Now().Unix())
	res := ingest(t, ts, token, "10.0.5.2", payload)
	res.Body.Close()
	if res.StatusCode != 202 {
		t.Fatalf("ingest: %d", res.StatusCode)
	}

	res = get(t, ts.URL, "/api/agents", ts.cookie)
	body := readJSON(t, res)
	agents, _ := body["agents"].([]any)
	for _, item := range agents {
		m, _ := item.(map[string]any)
		if m["slug"] == "ap-agent" {
			if m["routerId"] != "jidu6401-2" {
				t.Fatalf("bridge MAC should select second AP: %v", m)
			}
			return
		}
	}
	t.Fatalf("ap-agent no listado: %v", body)
}
