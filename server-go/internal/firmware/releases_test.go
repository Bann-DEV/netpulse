// releases_test.go - disponibilidad de releases OpenWrt (#1444).
package firmware

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/db"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d.DB
}

func TestParseReleasesIndex(t *testing.T) {
	html := `<!DOCTYPE html><html><body>
<a href="../">../</a>
<a href="21.02.7/">21.02.7/</a>
<a href="24.10.0/">24.10.0/</a>
<a href="23.05.5/">23.05.5/</a>
<a href="24.10.1/">24.10.1/</a>
<a href="25.12.0-rc1/">25.12.0-rc1/</a>
<a href="snapshots/">snapshots/</a>
<a href="fa.html">Free software</a>
</body></html>`
	got := ParseReleasesIndex(html)
	want := []string{"25.12.0-rc1", "24.10.1", "24.10.0", "23.05.5", "21.02.7"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parse: %v, want %v", got, want)
	}
}

func TestParseReleasesIndexRCOrdersBeforeFinal(t *testing.T) {
	got := ParseReleasesIndex(`<a href="24.10.0/">24.10.0/</a><a href="24.10.0-rc3/">24.10.0-rc3/</a>`)
	if len(got) != 2 || got[0] != "24.10.0" || got[1] != "24.10.0-rc3" {
		t.Fatalf("orden rc: %v", got)
	}
}

func TestParseReleasesIndexEmpty(t *testing.T) {
	if got := ParseReleasesIndex("<html>nada</html>"); len(got) != 0 {
		t.Fatalf("sin entradas: %v", got)
	}
}

func TestFetchReleasesOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<a href="24.10.1/">24.10.1/</a><a href="23.05.5/">23.05.5/</a>`)
	}))
	defer srv.Close()
	got, err := FetchReleases(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 2 || got[0] != "24.10.1" {
		t.Fatalf("versions: %v", got)
	}
}

func TestFetchReleasesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	if _, err := FetchReleases(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("debe fallar con HTTP != 200")
	}
}

func TestFetchReleasesEmptyParseFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "<html>vacio</html>")
	}))
	defer srv.Close()
	if _, err := FetchReleases(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Fatal("índice sin versiones debe fallar (no pisar la caché buena)")
	}
}

func TestReleasesIntervalDefaultAndSet(t *testing.T) {
	if got := ReleasesIntervalHours(nil); got != DefaultReleasesIntervalHours {
		t.Fatalf("default: %d", got)
	}
	if err := SetReleasesIntervalHours(nil, 0); err == nil {
		t.Fatal("rango inválido debe dar error")
	}
	if err := SetReleasesIntervalHours(nil, 24); err != nil {
		t.Fatalf("set nil-db: %v", err)
	}
}

func TestReleasesRefresherPublishesCacheOnStart(t *testing.T) {
	db := testDB(t)
	if err := SaveReleases(db, ReleasesState{Ts: time.Now().Unix(), Versions: []string{"24.10.1"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<a href="24.10.1/">24.10.1/</a><a href="24.10.0/">24.10.0/</a>`)
	}))
	defer srv.Close()
	r := NewReleasesRefresher(db, srv.URL)
	got := make(chan []string, 1)
	r.SetSink(func(v []string, _ int64) { got <- v })
	if st, ok := LoadReleases(db); ok {
		r.emitSink(st.Versions, st.Ts)
	}
	v := <-got
	if len(v) != 1 || v[0] != "24.10.1" {
		t.Fatalf("caché publicada al arranque: %v", v)
	}
}

func TestReleasesRefresherRunNowSingleFlight(t *testing.T) {
	db := testDB(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		fmt.Fprint(w, `<a href="24.10.1/">24.10.1/</a>`)
	}))
	defer srv.Close()
	r := NewReleasesRefresher(db, srv.URL)
	if err := r.RunNow(context.Background()); err != nil {
		t.Fatalf("runnow: %v", err)
	}
	if calls != 1 {
		t.Fatalf("llamadas HTTP: %d, want 1", calls)
	}
	st, ok := LoadReleases(db)
	if !ok || len(st.Versions) != 1 || st.Versions[0] != "24.10.1" {
		t.Fatalf("caché guardada: %+v (ok=%v)", st, ok)
	}
	// Caché fresca: un tick no dispara otra descarga.
	r.tick()
	if calls != 1 {
		t.Fatalf("tick con caché fresca no debe descargar: %d llamadas", calls)
	}
}

func TestReleasesRefresherTickRefreshesStaleCache(t *testing.T) {
	db := testDB(t)
	if err := SaveReleases(db, ReleasesState{Ts: time.Now().Add(-48 * time.Hour).Unix(), Versions: []string{"23.05.5"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		fmt.Fprint(w, `<a href="24.10.1/">24.10.1/</a>`)
	}))
	defer srv.Close()
	r := NewReleasesRefresher(db, srv.URL)
	r.tick()
	if calls != 1 {
		t.Fatalf("caché vieja debe refrescarse: %d llamadas", calls)
	}
	st, _ := LoadReleases(db)
	if st.Versions[0] != "24.10.1" {
		t.Fatalf("versiones tras refresco: %v", st.Versions)
	}
}
