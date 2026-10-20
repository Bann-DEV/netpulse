package adapters

// wireguard_urgent.go — flag "urgente" por peer WireGuard (#1441).
//
// No todos los peers importan igual: un túnel site-to-site o un servidor
// merece aviso cuando se cae; un portátil o un móvil que entra y sale es
// rutina y solo debe quedar en el log. El admin marca peers a mano y la
// decisión se persiste.
//
// Persistencia: UNA clave kv (`wireguard.urgent_peers`) con un JSON de claves
// de peer (WGPeer.Key, la pubkey en base64url). No hace falta tabla nueva: la
// lista es pequeña, se lee entera y el patrón kv ya es el que usan los demás
// ajustes del repo (impostor_allowlist_v1, alerts.impostor_enabled...). Un
// id estable de peer es la pubkey; el ID de WGPeer no vale (sale del device
// que casó por IP del túnel o del índice del dump y cambia entre sondeos).
//
// Live mantiene el conjunto en memoria (como impostorAllow) para que las
// transiciones y el snapshot no consulten la BD en cada vuelta; el setter
// escribe kv y memoria a la vez.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// wgUrgentKey: clave kv con la lista JSON de claves de peer urgentes.
const wgUrgentKey = "wireguard.urgent_peers"

// wgPeerKeyRe valida una clave de peer tal como la genera WGPeerKey
// (base64url sin padding, 43 chars para pubkeys de 32 bytes). El rango de
// longitud deja sitio a las claves transliteradas a mano y a las del demo,
// pero corta cualquier intento de escribir basura en el kv.
var wgPeerKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// WireGuardPeerUrgent dice si una clave de peer está marcada como urgente.
func (l *Live) WireGuardPeerUrgent(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.wgUrgent[key]
}

// SetWireGuardPeerUrgent (#1441) marca o desmarca un peer como urgente.
// Persiste en kv y actualiza la copia en memoria: el siguiente snapshot
// (/api/overview) y la siguiente transición ya ven el flag nuevo, sin
// reiniciar ni esperar a un sondeo. Devuelve error si la clave no tiene la
// forma esperada (la validación de tamaño/caracteres vive aquí, junto al
// almacenamiento, para que el endpoint no pueda guardar cualquier cosa).
func (l *Live) SetWireGuardPeerUrgent(key string, urgent bool) error {
	if !wgPeerKeyRe.MatchString(key) {
		return fmt.Errorf("invalid peer key %q", key)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.wgUrgent == nil {
		l.wgUrgent = map[string]bool{}
	}
	if urgent {
		l.wgUrgent[key] = true
	} else {
		delete(l.wgUrgent, key)
	}
	l.saveWGUrgentLocked()
	return nil
}

// WireGuardUrgentPeers devuelve las claves marcadas, ordenadas. La usa el
// endpoint de lectura y sirve para depurar qué quedó persistido.
func (l *Live) WireGuardUrgentPeers() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.wgUrgent))
	for k := range l.wgUrgent {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// wgUrgentCopyLocked: copia del conjunto para pasarla al adapter sin el mutex
// tomado. Caller holds l.mu.
func (l *Live) wgUrgentCopyLocked() map[string]bool {
	out := make(map[string]bool, len(l.wgUrgent))
	for k := range l.wgUrgent {
		out[k] = true
	}
	return out
}

// loadWGUrgent (#1441) lee la lista persistida al arrancar. Ausente, vacía o
// corrupta → sin peers urgentes (nunca rompe el arranque por un ajuste).
func (l *Live) loadWGUrgent() {
	if l.db == nil {
		return
	}
	var raw string
	if err := l.db.QueryRow("SELECT value FROM kv WHERE key = ?", wgUrgentKey).Scan(&raw); err != nil {
		return
	}
	var list []string
	if json.Unmarshal([]byte(raw), &list) != nil {
		return
	}
	for _, k := range list {
		if wgPeerKeyRe.MatchString(k) {
			l.wgUrgent[k] = true
		}
	}
}

// saveWGUrgentLocked: persiste la lista en kv (lista ordenada para que el
// valor no cambie de forma si no cambia el contenido). Caller holds l.mu.
func (l *Live) saveWGUrgentLocked() {
	if l.db == nil {
		return
	}
	list := make([]string, 0, len(l.wgUrgent))
	for k := range l.wgUrgent {
		list = append(list, k)
	}
	sort.Strings(list)
	raw, err := json.Marshal(list)
	if err != nil {
		return
	}
	_, _ = l.db.Exec(
		"INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		wgUrgentKey, string(raw))
}
