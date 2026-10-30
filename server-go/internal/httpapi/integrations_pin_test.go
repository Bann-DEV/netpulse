package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/reinstall"
	"github.com/gnacho/netpulse/server-go/internal/rintegration"
)

func acceptAny(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func TestPusherPinEnv(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(acceptAny))
	defer tlsSrv.Close()
	sum := sha256.Sum256(tlsSrv.Certificate().RawSubjectPublicKeyInfo)
	want := hex.EncodeToString(sum[:])

	if got := pusherPinEnv(tlsSrv.URL); got[envServerFP] != want {
		t.Fatalf("https pin = %q, want %q", got[envServerFP], want)
	}

	plain := httptest.NewServer(http.HandlerFunc(acceptAny))
	defer plain.Close()
	if got := pusherPinEnv(plain.URL); got != nil {
		t.Fatalf("http must not carry a pin, got %v", got)
	}

	// Sin handshake no hay pin: se omite la variable en lugar de inventarla.
	if got := pusherPinEnv("https://127.0.0.1:1"); got != nil {
		t.Fatalf("unreachable https must not carry a pin, got %v", got)
	}
}

func TestPusherEnvCarriesServerPin(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(acceptAny))
	defer tlsSrv.Close()
	plain := httptest.NewServer(http.HandlerFunc(acceptAny))
	defer plain.Close()

	var s *server // pusherEnv no toca estado del servidor.
	row := rintegration.Row{Slug: "salon", Host: "192.0.2.10", Username: "admin", IntervalS: 30}

	env := s.pusherEnv(rintegration.Vendor{ID: "asuswrt", Mode: "local"}, row, "pw", tlsSrv.URL, "tok")
	if env[envServerFP] == "" {
		t.Fatalf("https server URL must ship %s, env=%v", envServerFP, env)
	}
	if env["NETPULSE_SERVER"] != tlsSrv.URL || env["NETPULSE_TOKEN"] != "tok" || env["NETPULSE_SLUG"] != "salon" {
		t.Fatalf("unexpected env: %v", env)
	}

	// En modo ssh el pusher corre en el router: el host del vendor cambia, el
	// pin del server NO (es la misma URL pública la que va a verificar).
	sshEnv := s.pusherEnv(rintegration.Vendor{ID: "asuswrt", Mode: "ssh"}, row, "pw", tlsSrv.URL, "tok")
	if sshEnv[envServerFP] != env[envServerFP] {
		t.Fatalf("ssh env pin = %q, want %q", sshEnv[envServerFP], env[envServerFP])
	}
	if sshEnv["ASUSWRT_HOST"] != "127.0.0.1" {
		t.Fatalf("ssh env host = %q, want 127.0.0.1", sshEnv["ASUSWRT_HOST"])
	}

	httpEnv := s.pusherEnv(rintegration.Vendor{ID: "asuswrt", Mode: "local"}, row, "pw", plain.URL, "tok")
	if _, present := httpEnv[envServerFP]; present {
		t.Fatalf("http server must not ship a pin: %v", httpEnv)
	}
}

// stubServerFP sustituye el derivado del pin y lo devuelve al terminar.
func stubServerFP(t *testing.T, fp string, err error) {
	t.Helper()
	orig := serverFPWithError
	serverFPWithError = func(string) (string, error) { return fp, err }
	t.Cleanup(func() { serverFPWithError = orig })
}

// Un https sin pin derivable no puede escribirse: el pusher se negaría a
// arrancar y el alta mentiría con un 201.
func TestRequirePusherPinRejectsUndiaableHttps(t *testing.T) {
	cause := errors.New("dial tcp 203.0.113.10:443: connect: connection refused")
	stubServerFP(t, "", cause)

	err := requirePusherPin("https://netpulse.example:3443")
	if err == nil {
		t.Fatal("https sin pin derivable debe rechazar el alta")
	}
	for _, want := range []string{"cannot derive the server fingerprint", cause.Error(), "NETPULSE_AGENT_URL", envServerFP} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("el mensaje debe contener %q; es: %q", want, err)
		}
	}

	// El mismo fallo sin causa concreta (handshake que no presenta cert) sigue
	// siendo un rechazo, no un env incompleto.
	stubServerFP(t, "", nil)
	if err := requirePusherPin("https://netpulse.example:3443"); err == nil {
		t.Fatal("un https sin cert también debe rechazarse")
	}
}

func TestRequirePusherPinAllowsWhatCanStart(t *testing.T) {
	stubServerFP(t, "aabb", nil)
	if err := requirePusherPin("https://netpulse.example:3443"); err != nil {
		t.Fatalf("con pin derivable no hay que rechazar: %v", err)
	}

	// http: no hay nada que verificar, así que la ausencia de pin es el estado
	// correcto, no un error.
	if err := requirePusherPin("http://192.168.1.5:3000"); err != nil {
		t.Fatalf("http no necesita pin: %v", err)
	}

	// Sin stub: un TLS real del todo debe dar el pin por sí solo.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(acceptAny))
	defer tlsSrv.Close()
	restore := serverFPWithError
	serverFPWithError = reinstall.ServerFPWithError
	t.Cleanup(func() { serverFPWithError = restore })
	if err := requirePusherPin(tlsSrv.URL); err != nil {
		t.Fatalf("pin derivable de un TLS real: %v", err)
	}
}
