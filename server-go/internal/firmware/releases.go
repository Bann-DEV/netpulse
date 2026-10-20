// releases.go - disponibilidad real de releases OpenWrt (#1444).
//
// La alerta de firmware desactualizado se dispara cuando el target
// configurado difiere del instalado (#1412), pero nada comprobaba que ese
// target existiera de verdad: un target inventado se convertía en alerta
// permanente. Este módulo consulta periódicamente el índice oficial
// (downloads.openwrt.org/releases/, la misma fuente que ya usa el resolver
// de imágenes) y guarda la lista en kv; el sondeo sólo alerta "outdated"
// cuando el target figura en ella. Un target desconocido es un aviso de
// configuración distinto (firmware-target-unknown), no una alerta de
// firmware. La periodicidad es configurable (default: una vez al día).
package firmware

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	releasesKey         = "firmware.releases.v1"
	releasesIntervalKey = "firmware.releases.intervalHours"

	DefaultReleasesIntervalHours = 24
	minReleasesIntervalHours     = 1
	maxReleasesIntervalHours     = 168

	// releasesURL: índice HTML de releases oficiales (mismo host que el
	// resolver de imágenes, DefaultImageBase). No es ASU: el servicio ASU
	// no es necesario para saber QUÉ versiones existen.
	releasesPath = "/releases/"
)

// ReleasesState es la lista cacheada de versiones publicadas.
type ReleasesState struct {
	// Ts es el instante (segundos unix) de la última consulta exitosa.
	Ts int64 `json:"ts"`
	// Versions son las versiones ordenadas de más nueva a más vieja.
	Versions []string `json:"versions"`
}

var releaseDirRe = regexp.MustCompile(`<a href="([0-9]+\.[0-9]+(\.[0-9]+)?(-rc[0-9]+)?)/"`)

// ParseReleasesIndex extrae las versiones del índice HTML de
// downloads.openwrt.org/releases/ (enlaces a directorios "X.Y.Z/").
// Descarta entradas ajenas (snapshots, fa.html, ../). Ordena de más nueva
// a más vieja. Pure: testeable sin red.
func ParseReleasesIndex(html string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range releaseDirRe.FindAllStringSubmatch(html, -1) {
		v := m[1]
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return releaseVersionLess(out[j], out[i]) })
	return out
}

// releaseVersionLess compara "X.Y.Z" / "X.Y.Z-rcN" (a < b). Las rc de una
// versión ordenan ANTES del final de esa versión. Formatos raros no
// parseables ordenan al final (menos que todo lo demás).
func releaseVersionLess(a, b string) bool {
	pa, ra, oka := splitReleaseVersion(a)
	pb, rb, okb := splitReleaseVersion(b)
	if oka != okb {
		return !oka // no parseable → al final
	}
	if !oka {
		return a < b
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	if ra != rb {
		// sin rc (0) es posterior a cualquier rc
		if ra == 0 {
			return false
		}
		if rb == 0 {
			return true
		}
		return ra < rb
	}
	return false
}

func splitReleaseVersion(v string) ([3]int, int, bool) {
	var out [3]int
	rc := 0
	base := v
	if i := strings.Index(v, "-rc"); i >= 0 {
		if n, err := strconv.Atoi(v[i+3:]); err == nil {
			rc = n
			base = v[:i]
		}
	}
	parts := strings.Split(base, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, 0, false
	}
	for i := 0; i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return out, 0, false
		}
		out[i] = n
	}
	return out, rc, true
}

// FetchReleases descarga y parsea el índice de releases. base sigue el
// contrato de ImageResolver.BaseURL (sin barra final).
func FetchReleases(ctx context.Context, client *http.Client, base string) ([]string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	url := strings.TrimRight(base, "/") + releasesPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("releases index: HTTP %d", resp.StatusCode)
	}
	buf := new(strings.Builder)
	tmp := make([]byte, 8192)
	for {
		n, err := resp.Body.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			break
		}
	}
	versions := ParseReleasesIndex(buf.String())
	if len(versions) == 0 {
		return nil, fmt.Errorf("releases index: no version entries parsed")
	}
	return versions, nil
}

// LoadReleases lee la lista cacheada de kv. ok=false si nunca se guardó.
func LoadReleases(db *sql.DB) (ReleasesState, bool) {
	var st ReleasesState
	if db == nil {
		return st, false
	}
	var raw string
	if err := db.QueryRow("SELECT value FROM kv WHERE key = ?", releasesKey).Scan(&raw); err != nil {
		return st, false
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil || len(st.Versions) == 0 {
		return ReleasesState{}, false
	}
	return st, true
}

// SaveReleases persiste la lista cacheada en kv.
func SaveReleases(db *sql.DB, st ReleasesState) error {
	if db == nil {
		return nil
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		"INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		releasesKey, string(raw))
	return err
}

// ReleasesIntervalHours devuelve la cadencia configurada del chequeo
// (default una vez al día). Valores corruptos o fuera de rango devuelven el
// default.
func ReleasesIntervalHours(db *sql.DB) int {
	if db == nil {
		return DefaultReleasesIntervalHours
	}
	var raw string
	if err := db.QueryRow("SELECT value FROM kv WHERE key = ?", releasesIntervalKey).Scan(&raw); err != nil {
		return DefaultReleasesIntervalHours
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minReleasesIntervalHours || n > maxReleasesIntervalHours {
		return DefaultReleasesIntervalHours
	}
	return n
}

// SetReleasesIntervalHours valida y persiste la cadencia (horas).
func SetReleasesIntervalHours(db *sql.DB, h int) error {
	if h < minReleasesIntervalHours || h > maxReleasesIntervalHours {
		return fmt.Errorf("intervalHours debe estar entre %d y %d", minReleasesIntervalHours, maxReleasesIntervalHours)
	}
	if db == nil {
		return nil
	}
	_, err := db.Exec(
		"INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
		releasesIntervalKey, strconv.Itoa(h))
	return err
}

// ReleasesRefresher es el daemon que mantiene la lista al día: tick corto
// (como los demás schedulers) y refresco cuando la caché supera la
// cadencia configurada. El sink publica la lista en el adapter (para el
// gating de la alerta) sin depender de la API.
type ReleasesRefresher struct {
	db     *sql.DB
	client *http.Client
	base   string

	mu     sync.Mutex
	sink   func([]string, int64)
	flying bool // single-flight del refresco

	stop chan struct{}
	wg   sync.WaitGroup

	now  func() time.Time
	logf func(format string, args ...any)
}

// NewReleasesRefresher construye el daemon. base sigue el contrato de
// ImageResolver.BaseURL.
func NewReleasesRefresher(db *sql.DB, base string) *ReleasesRefresher {
	return &ReleasesRefresher{
		db:     db,
		client: &http.Client{Timeout: 15 * time.Second},
		base:   base,
		stop:   make(chan struct{}),
		now:    time.Now,
		logf:   func(f string, a ...any) { log.Printf("[firmware] "+f, a...) },
	}
}

// SetSink fija el publicador de la lista en el adapter (lo llama tras cada
// refresco exitoso y al arrancar si ya hay caché).
func (r *ReleasesRefresher) SetSink(fn func([]string, int64)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sink = fn
}

func (r *ReleasesRefresher) emitSink(v []string, ts int64) {
	r.mu.Lock()
	fn := r.sink
	r.mu.Unlock()
	if fn != nil {
		fn(v, ts)
	}
}

const releasesTick = 30 * time.Second

// Start lanza el bucle periódico (daemon; no retorna hasta Stop).
func (r *ReleasesRefresher) Start() {
	r.wg.Add(1)
	defer r.wg.Done()
	// Al arrancar, publica la caché existente: el gating funciona desde el
	// primer ciclo aunque el refresco todavía no haya tocado.
	if st, ok := LoadReleases(r.db); ok {
		r.emitSink(st.Versions, st.Ts)
	}
	ticker := time.NewTicker(releasesTick)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-ticker.C:
			r.tick()
		}
	}
}

// Stop detiene el bucle y espera al tick en curso.
func (r *ReleasesRefresher) Stop() {
	close(r.stop)
	r.wg.Wait()
}

func (r *ReleasesRefresher) tick() {
	interval := time.Duration(ReleasesIntervalHours(r.db)) * time.Hour
	if st, ok := LoadReleases(r.db); ok {
		if r.now().Sub(time.Unix(st.Ts, 0)) < interval {
			return // caché fresca
		}
	}
	if err := r.RunNow(context.Background()); err != nil {
		r.logf("releases: refresco falló: %v", err)
	}
}

// RunNow fuerza un refresco (endpoint "comprobar ahora" y arranque). Es
// single-flight: una segunda llamada durante un refresco en curso espera
// pacíficamente sin lanzar otra descarga.
func (r *ReleasesRefresher) RunNow(ctx context.Context) error {
	r.mu.Lock()
	if r.flying {
		r.mu.Unlock()
		return nil
	}
	r.flying = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.flying = false
		r.mu.Unlock()
	}()

	versions, err := FetchReleases(ctx, r.client, r.base)
	if err != nil {
		return err
	}
	st := ReleasesState{Ts: r.now().Unix(), Versions: versions}
	if err := SaveReleases(r.db, st); err != nil {
		return err
	}
	r.emitSink(versions, st.Ts)
	return nil
}
