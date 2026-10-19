// firmware_upload.go — selector de método por unidad e imagen subida desde
// local (#1414). La imagen se guarda en el server y el flujo clásico la sirve
// al agente para su descarga (el agente ya descarga por URL con sha256, sin
// cambios de protocolo).
package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gnacho/netpulse/server-go/internal/auth"
	"github.com/gnacho/netpulse/server-go/internal/firmware"
)

// maxFirmwareUpload: tope de una imagen subida (las de OpenWrt rondan 8-25 MB;
// 100 MB da margen para perfiles con muchos paquetes empaquetados).
const maxFirmwareUpload = 100 << 20

func (s *server) registerFirmwareUploadRoutes(mux *http.ServeMux) {
	if s.firmware == nil {
		return
	}

	// PUT method: método preferido de la tarjeta (auto/owut/url/upload).
	mux.Handle("PUT /api/firmware-upgrades/{routerId}/method", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("routerId")
		var body struct {
			Method string `json:"method"`
		}
		if st := readJSONBody(w, r, &body); st != 0 {
			return
		}
		if !firmware.ValidMethod(body.Method) {
			writeError(w, http.StatusBadRequest, "invalid_method", "method debe ser auto, owut, url o upload")
			return
		}
		if err := firmware.SaveMethod(s.db.DB, id, body.Method); err != nil {
			writeError(w, http.StatusInternalServerError, "firmware_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})))

	// POST image: sube una imagen (multipart, campo "image") y la deja como
	// target del flujo clásico: URL servida por este mismo server (alcanzable
	// por el agente vía NETPULSE_AGENT_URL/PublicURL) + checksum calculado.
	mux.Handle("POST /api/firmware-upgrades/{routerId}/image", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("routerId")
		if err := r.ParseMultipartForm(maxFirmwareUpload); err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "image_too_large", fmt.Sprintf("imagen mayor de %d MB", maxFirmwareUpload>>20))
			return
		}
		f, hdr, err := r.FormFile("image")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "campo multipart 'image' requerido")
			return
		}
		defer f.Close()

		dir := filepath.Join(filepath.Dir(s.db.Path), "firmware-uploads")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			writeError(w, http.StatusInternalServerError, "firmware_error", err.Error())
			return
		}
		dest := filepath.Join(dir, id+".bin")
		tmp := dest + ".tmp"
		df, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "firmware_error", err.Error())
			return
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(df, h), io.LimitReader(f, maxFirmwareUpload+1))
		closeErr := df.Close()
		if copyErr != nil || closeErr != nil {
			os.Remove(tmp)
			writeError(w, http.StatusInternalServerError, "firmware_error", "no se pudo guardar la imagen")
			return
		}
		if n == 0 || n > maxFirmwareUpload {
			os.Remove(tmp)
			writeError(w, http.StatusRequestEntityTooLarge, "image_too_large", "imagen vacía o mayor del tope")
			return
		}
		if err := os.Rename(tmp, dest); err != nil {
			os.Remove(tmp)
			writeError(w, http.StatusInternalServerError, "firmware_error", err.Error())
			return
		}
		sum := hex.EncodeToString(h.Sum(nil))

		// La URL con la que los AGENTES deben alcanzar al server (#1335):
		// la misma cadena de precedencia que el install line.
		imgURL := s.agentBaseURL(r) + "/api/firmware-image/" + id
		t, _ := s.firmware.GetTarget(id)
		if t == nil {
			t = &firmware.Target{RouterID: id}
		}
		t.TargetURL = imgURL
		t.Checksum = sum
		if err := s.firmware.SetTarget(*t); err != nil {
			writeError(w, http.StatusInternalServerError, "firmware_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "checksum": sum, "size": n, "name": hdr.Filename, "url": imgURL,
		})
	})))

	// GET image: sirve la imagen subida. Sin auth de admin a propósito: el
	// AGENTE la descarga con su transporte pinned (mismo caso que
	// GET /api/agents/{slug}/binary, #1367) y no puede añadir cabeceras.
	// La imagen tampoco es secreta (es la que el admin subió para flashear).
	mux.HandleFunc("GET /api/firmware-image/{routerId}", s.handleFirmwareImage)
}

// handleFirmwareImage sirve la imagen subida de un router. El id se sanea:
// solo nombre base (sin separadores ni puntos dobles) dentro del directorio
// de uploads.
func (s *server) handleFirmwareImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("routerId")
	if id == "" || strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if s.db == nil {
		writeError(w, http.StatusServiceUnavailable, "no_db")
		return
	}
	path := filepath.Join(filepath.Dir(s.db.Path), "firmware-uploads", id+".bin")
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	http.ServeFile(w, r, path)
}
