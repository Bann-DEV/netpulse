// integrations_pin.go — el pin SPKI del propio server en el entorno de los
// pushers externos.
//
// Un NetPulse que sirve su certificado generado es válido para 127.0.0.1, así
// que la verificación x509 por nombre contra una dirección de LAN nunca pasa:
// un pusher que no pinee nada no puede ingestar, ni siquiera con token válido
// (#8 en gnacho/netpulse-integrations). El agente nativo resuelve esto con
// pinning de SPKI; `reinstall.ServerFP` (#851/#870) ya hace ese TLS dial con
// caché por host para el env del agente, y aquí se reutiliza para el de los
// pushers en lugar de duplicar el cálculo.
//
// Con la URL en http no hace falta ninguna variable. Con https, si el pin no se
// puede derivar el alta se rechaza en vez de escribir un env imposible: desde #13
// el pusher se niega a arrancar sin pin, así que escribirlo a medias produce un
// 201 seguido de un state=error que culpa a la variable ausente y no al fallo de
// red que lo causó. Ver requirePusherPin.
package httpapi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gnacho/netpulse/server-go/internal/reinstall"
)

// envServerFP es la variable que leen los pushers externos
// (netpulse-integrations/internal/pusher), con el mismo nombre que usa el
// agente nativo.
const envServerFP = "NETPULSE_SERVER_FP"

// serverFPWithError es la puerta inyectable del derivado: los tests de
// requirePusherPin necesitan un fallo de dial a voluntad, no una red que se
// caiga.
var serverFPWithError = reinstall.ServerFPWithError

// pusherPinEnv devuelve la entrada de pin para serverURL, o nil si no aplica.
func pusherPinEnv(serverURL string) map[string]string {
	fp, _ := serverFPWithError(serverURL)
	if fp == "" {
		return nil
	}
	return map[string]string{envServerFP: fp}
}

// requirePusherPin rechaza un alta cuyo env no podría arrancar. Desde #13 en
// netpulse-integrations, un pusher con NETPULSE_SERVER en https y sin pin se
// niega a levantar: si aquí el derivado falla (hairpin NAT, firewall, el server
// que no alcanza su propia URL pública, un certificado a medio renovar), escribir
// el env sin la variable da un 201 y un state=error al segundo siguiente, con un
// log que acusa a la variable que falta y no a la red. La URL http sí puede
// quedarse sin pin: no hay nada que verificar.
func requirePusherPin(serverURL string) error {
	if !strings.HasPrefix(strings.ToLower(serverURL), "https://") {
		return nil
	}
	fp, err := serverFPWithError(serverURL)
	if fp != "" {
		return nil
	}
	if err == nil {
		err = errors.New("the TLS peer presented no certificate")
	}
	return fmt.Errorf("cannot derive the server fingerprint: %w. "+
		"Check NETPULSE_AGENT_URL or set %s explicitly", err, envServerFP)
}
