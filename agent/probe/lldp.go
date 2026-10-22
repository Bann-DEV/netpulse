// lldp.go — vecinos LLDP del equipo (issue #489). El comando y el parser
// viven aquí (patrón Cmd*/Parse* de probe) para que los use TANTO el agente
// local (sección lldp del payload) como el sondeo SSH del server, que hasta
// ahora tenía su propia copia en adapters/lldp.go.
//
// Contrato de disponibilidad (#247/#489):
//   - lldpd NO instalado → LldpData{Available:false} (hint "instala lldpd").
//   - instalado pero la sonda falla esta ronda → Available:true con
//     Neighbors nil (el server conserva el último dato bueno).
//   - instalado y sin vecinos → Available:true con Neighbors [] (vacío
//     honesto: cero vecinos escuchados).
package probe

import (
	"encoding/json"
	"sort"
	"strings"
)

// CmdLldpCheck: ¿está lldpcli instalado? (exit != 0 → no instalado).
// #1481: en Asuswrt el /bin/sh no trae el builtin `command`, así que la
// forma clásica fallaba con lldpcli presente (y el payload salía con
// lldpAvailable=false teniendo vecinos). Cadena de fallbacks portable:
// builtin, which, y rutas absolutas típicas.
const CmdLldpCheck = "command -v lldpcli 2>/dev/null || which lldpcli 2>/dev/null || ls /usr/sbin/lldpcli /usr/bin/lldpcli /opt/sbin/lldpcli 2>/dev/null | head -1"

// CmdLldpNeighbors: vecinos LLDP en JSON (lldpd). Igual que la sonda SSH.
const CmdLldpNeighbors = "lldpcli -f json show neighbors"

// CmdLldpNeighborsText (#1481): vecinos en texto plano, fallback para
// lldpd antiguos sin salida JSON. Mismos campos que el JSON (chassis id,
// sysname, mgmt-ip, capabilities, port id/descr).
const CmdLldpNeighborsText = "lldpcli show neighbors 2>/dev/null || /usr/sbin/lldpcli show neighbors 2>/dev/null || /opt/sbin/lldpcli show neighbors 2>/dev/null"

// CmdLldpdIfaces: binding de lldpd en OpenWrt (UCI). Vacío si no hay UCI
// (Linux genérico) o la opción no existe (lldpd escucha en todas las
// físicas por defecto). Solo se consulta cuando hay 0 vecinos (#1369).
const CmdLldpdIfaces = "uci -q get lldpd.config.interface 2>/dev/null || true"

// HintLldpdBridgeOnly: valor de LldpData.Hint cuando lldpd está instalado,
// reporta 0 vecinos y su binding UCI es SOLO a interfaces bridge (br-*):
// en varios targets (qualcommax nss-dp verificado; DSA probable) los frames
// LLDP nunca suben al listener del bridge master y lldpd no ve a nadie sin
// avisar (#1369). La UI lo traduce a "configura lldpd en puertos físicos".
const HintLldpdBridgeOnly = "lldpd-bridge-only"

// LldpData: sección lldp del payload del agente (#489).
type LldpData struct {
	// Available: false cuando lldpd no está instalado en el equipo.
	Available bool `json:"available"`
	// Neighbors: vecinos anunciados. nil = sonda fallida esta ronda (el
	// server conserva el último dato bueno); [] = cero vecinos honesto.
	// SIN omitempty a propósito: hay que distinguir nil de vacío en el
	// wire format.
	Neighbors []LldpNeighbor `json:"neighbors"`
	// Hint: aviso de configuración subóptima detectada (p. ej.
	// HintLldpdBridgeOnly). Código estable, la UI lo traduce (i18n).
	Hint string `json:"hint,omitempty"`
}

// LldpdBridgeOnly: true si el binding UCI de lldpd (CSV de patrones, p. ej.
// "br-lan" o "lan*,wan") nombra SOLO interfaces bridge. Vacío (sin opción:
// lldpd escucha en todas las físicas) o cualquier patrón físico → false.
func LldpdBridgeOnly(ifaces string) bool {
	any := false
	for _, tok := range strings.Split(ifaces, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		any = true
		if !strings.HasPrefix(tok, "br-") {
			return false
		}
	}
	return any
}

// LldpNeighbor: un vecino LLDP anunciado en un puerto local. Todos los
// campos son opcionales en el anuncio; vacío = no anunciado. Mismos campos
// que adapters.LldpNeighbor (conversión directa por campos idénticos).
type LldpNeighbor struct {
	Port       string   `json:"port"`                 // puerto local que recibe el anuncio ("lan3"…)
	ChassisMac string   `json:"chassisMac,omitempty"` // id del chasis tipo mac (mayúsculas)
	Chassis    string   `json:"chassis,omitempty"`    // nombre del chasis (o id si no hay nombre)
	Mgmt       string   `json:"mgmt,omitempty"`       // primera mgmt-ip anunciada
	Caps       []string `json:"caps,omitempty"`       // capacidades enabled ("Bridge", "Router", "Wlan"…)
	PortDesc   string   `json:"portDesc,omitempty"`   // descripción del puerto remoto
}

// ParseLldpNeighbors parsea `lldpcli -f json show neighbors`:
//
//	{"lldp":{"interface":[{"name","chassis":{<nombre>:{id{type,value},descr,
//	  mgmt-ip,capability[]}},"port":{id{type,value},descr}}]}}
//
// Defensivo: campos ausentes o de tipo inesperado se ignoran (best-effort de
// encoding/json rellena lo compatible); interface también se acepta como
// mapa nombre→objeto (versiones viejas de lldpd). Error solo si la raíz no
// es JSON válido.
func ParseLldpNeighbors(data []byte) ([]LldpNeighbor, error) {
	var root struct {
		Lldp struct {
			Ifaces json.RawMessage `json:"interface"`
		} `json:"lldp"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.Lldp.Ifaces) == 0 || string(root.Lldp.Ifaces) == "null" {
		return []LldpNeighbor{}, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(root.Lldp.Ifaces, &entries); err != nil {
		// Forma mapa: {"lan3": {...}, "lan1": {...}} (lldpd viejo)
		var byName map[string]json.RawMessage
		if err2 := json.Unmarshal(root.Lldp.Ifaces, &byName); err2 != nil {
			// Ni array ni mapa: forma desconocida → sin datos, no error
			return []LldpNeighbor{}, nil
		}
		names := make([]string, 0, len(byName))
		for name := range byName {
			names = append(names, name)
		}
		sort.Strings(names)
		neighbors := make([]LldpNeighbor, 0, len(names))
		for _, name := range names {
			// En la forma mapa el nombre de la interfaz es la CLAVE
			neighbors = append(neighbors, parseLldpEntry(byName[name], name))
		}
		return neighbors, nil
	}
	neighbors := make([]LldpNeighbor, 0, len(entries))
	for _, raw := range entries {
		neighbors = append(neighbors, parseLldpEntry(raw, ""))
	}
	return neighbors, nil
}

// parseLldpEntry parsea una entrada de interface (nunca entra en pánico:
// los Unmarshal secundarios ignoran el error a propósito — best-effort).
// fallbackName es la clave de la forma mapa (lldpd viejo, sin campo "name").
func parseLldpEntry(raw json.RawMessage, fallbackName string) LldpNeighbor {
	var e struct {
		Name    string                     `json:"name"`
		Chassis map[string]json.RawMessage `json:"chassis"`
		Port    json.RawMessage            `json:"port"`
	}
	// Best-effort: un campo de tipo inesperado (chassis como cadena, port
	// como número…) no invalida el resto de la entrada.
	_ = json.Unmarshal(raw, &e)
	// lldpd 1.0.20 (OpenWrt 25.x, #1370): cada entrada del array puede ser
	// un objeto de UNA clave cuyo nombre es la interfaz ({"lan1": {...}}),
	// sin campo "name" dentro. Descender usando la clave como nombre de
	// puerto. Las claves que son campos conocidos no son interfaces.
	if e.Name == "" && e.Chassis == nil {
		var byName map[string]json.RawMessage
		if err := json.Unmarshal(raw, &byName); err == nil && len(byName) == 1 {
			for name, inner := range byName {
				switch name {
				case "name", "chassis", "port", "via", "rid", "age":
				default:
					return parseLldpEntry(inner, name)
				}
			}
		}
	}
	n := LldpNeighbor{Port: e.Name}
	if n.Port == "" {
		n.Port = fallbackName
	}

	// Chassis: mapa nombre→datos (normalmente uno; el primero ordenado)
	keys := make([]string, 0, len(e.Chassis))
	for k := range e.Chassis {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		n.Chassis = keys[0]
		var ch struct {
			ID struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"id"`
			MgmtIP json.RawMessage `json:"mgmt-ip"`
			Caps   []struct {
				Type    string `json:"type"`
				Enabled bool   `json:"enabled"`
			} `json:"capability"`
		}
		_ = json.Unmarshal(e.Chassis[keys[0]], &ch) // best-effort (ver cabecera)
		if ch.ID.Type == "mac" {
			n.ChassisMac = strings.ToUpper(ch.ID.Value)
		}
		if n.Chassis == "" {
			n.Chassis = ch.ID.Value
		}
		n.Mgmt = firstMgmtIP(ch.MgmtIP)
		for _, cap := range ch.Caps {
			if cap.Enabled && cap.Type != "" {
				n.Caps = append(n.Caps, cap.Type)
			}
		}
	}

	// Puerto remoto: descr; si no, el id
	if len(e.Port) > 0 {
		var p struct {
			ID struct {
				Value string `json:"value"`
			} `json:"id"`
			Descr string `json:"descr"`
		}
		if json.Unmarshal(e.Port, &p) == nil {
			n.PortDesc = p.Descr
			if n.PortDesc == "" {
				n.PortDesc = p.ID.Value
			}
		}
	}
	return n
}

// firstMgmtIP: mgmt-ip viene como array (lldpd actual) o string suelto.
func firstMgmtIP(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, ip := range list {
			if ip != "" {
				return ip
			}
		}
		return ""
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single
	}
	return ""
}

// ParseLldpNeighborsText (#1481) parsea el formato texto de `lldpcli show
// neighbors` (lldpd sin salida JSON): bloques separados por reglas que
// empiezan en "Interface: <if>, via: ...", con campos ChassisID (mac o
// local), SysName, SysDescr, MgmtIP, Capability "<tipo>, on|off" y PortID
// (mac o local) / PortDescr. Mismo shape que el parser JSON: PortDesc cae
// al valor del port id y Chassis al id del chasis si no hay SysName. Las
// capacidades solo cuentan cuando van "on", igual que en JSON.
func ParseLldpNeighborsText(out string) []LldpNeighbor {
	neighbors := []LldpNeighbor{}
	var cur *LldpNeighbor
	var chassisID, portID string
	flush := func() {
		if cur == nil {
			return
		}
		if cur.PortDesc == "" {
			cur.PortDesc = portID
		}
		if cur.Chassis == "" {
			cur.Chassis = chassisID
		}
		if cur.Port != "" || cur.ChassisMac != "" || cur.Chassis != "" {
			neighbors = append(neighbors, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "Interface:") {
			flush()
			// "Interface:    eth0, via: LLDP, RID: 2, Time: ..."
			name := strings.TrimPrefix(trim, "Interface:")
			if i := strings.IndexByte(name, ','); i >= 0 {
				name = name[:i]
			}
			cur = &LldpNeighbor{Port: strings.TrimSpace(name)}
			chassisID, portID = "", ""
			continue
		}
		if cur == nil {
			continue
		}
		key, val := trim, ""
		if i := strings.IndexByte(trim, ':'); i >= 0 {
			key, val = trim[:i], strings.TrimSpace(trim[i+1:])
		}
		switch key {
		case "ChassisID":
			// "mac 08:bd:43:75:50:cd" | "local EVANGELION-X"
			if rest, ok := strings.CutPrefix(val, "mac "); ok {
				cur.ChassisMac = strings.ToUpper(strings.TrimSpace(rest))
				chassisID = strings.TrimSpace(rest)
			} else if rest, ok := strings.CutPrefix(val, "local "); ok {
				chassisID = strings.TrimSpace(rest)
			} else {
				chassisID = val
			}
		case "SysName":
			cur.Chassis = val
		case "MgmtIP":
			if cur.Mgmt == "" {
				cur.Mgmt = val
			}
		case "Capability":
			// "Bridge, on" | "Router, off"
			if rest, ok := strings.CutSuffix(val, ", on"); ok && rest != "" {
				cur.Caps = append(cur.Caps, strings.TrimSpace(rest))
			}
		case "PortID":
			if rest, ok := strings.CutPrefix(val, "mac "); ok {
				portID = strings.TrimSpace(rest)
			} else if rest, ok := strings.CutPrefix(val, "local "); ok {
				portID = strings.TrimSpace(rest)
			} else {
				portID = val
			}
		case "PortDescr":
			cur.PortDesc = val
		}
	}
	flush()
	return neighbors
}
