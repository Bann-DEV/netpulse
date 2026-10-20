// wireguard_urgent.go — flag "urgente" por peer WireGuard (#1441).
//
//	PUT /api/wireguard/peers/{key}/urgent  body {"urgent":true|false}
//	GET /api/wireguard/urgent              claves marcadas (diagnóstico)
//
// `key` es el WGPeer.Key que sirve /api/overview (la clave pública en
// base64url): el único identificador del peer que sobrevive a sondeos y
// reinicios. El flag viaja en el propio WGPeer (`urgent`) y decide si sus
// caídas avisan o solo quedan en el log (adapters.applyWireGuardTransitions).
package httpapi

import (
	"net/http"
	"regexp"

	"github.com/gnacho/netpulse/server-go/internal/auth"
)

// wgPeerKeyPathRe: forma aceptada de la clave en el path. Misma regla que el
// almacenamiento del adapter (base64url, 43 chars para una pubkey real); se
// valida AQUÍ antes de tocar el adapter para no pasar basura al kv.
var wgPeerKeyPathRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func (s *server) registerWireGuardUrgentRoutes(mux *http.ServeMux) {
	mux.Handle("PUT /api/wireguard/peers/{key}/urgent", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		if !wgPeerKeyPathRe.MatchString(key) {
			writeError(w, http.StatusBadRequest, "invalid_peer", "invalid WireGuard peer key")
			return
		}
		var body struct {
			Urgent *bool `json:"urgent"`
		}
		if st := readJSONBody(w, r, &body); st != 0 {
			writeBodyError(w, st, "invalid_body", "body JSON inválido")
			return
		}
		if body.Urgent == nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "urgent is required")
			return
		}
		setter, ok := s.adapter.(interface {
			SetWireGuardPeerUrgent(string, bool) error
		})
		if !ok {
			writeError(w, http.StatusNotImplemented, "not_supported", "adapter does not support WireGuard peer urgency")
			return
		}
		if err := setter.SetWireGuardPeerUrgent(key, *body.Urgent); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_peer", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"key": key, "urgent": *body.Urgent})
	})))

	// Diagnóstico: qué peers quedaron marcados en la BD. Sirve para comprobar
	// una persistencia y para entender un aviso que llega (o no llega) sin
	// rebuscar en la tabla kv a mano.
	mux.Handle("GET /api/wireguard/urgent", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reader, ok := s.adapter.(interface{ WireGuardUrgentPeers() []string })
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{"peers": []string{}})
			return
		}
		peers := reader.WireGuardUrgentPeers()
		if peers == nil {
			peers = []string{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
	})))
}
