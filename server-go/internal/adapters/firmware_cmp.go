// Comparación firmware vs target configurado (issue #1412). Parsea la versión
// de release de ambos lados y compara componente a componente; si alguno no
// tiene formato parseable, cae al Contains insensible a mayúsculas de #241.
package adapters

import (
	"regexp"
	"strconv"
	"strings"
)

// Resultados de la comparación firmware/target.
const (
	// fwMatch: target contenido o igual a lo instalado, sin alerta.
	fwMatch = iota
	// fwNewer: el target es más nuevo que lo instalado (firmware
	// desactualizado; el aviso clásico de "hay firmware más reciente").
	fwNewer
	// fwOlder: el target es MÁS VIEJO que lo instalado. No es "desactualizado":
	// apunta a un downgrade, casi siempre un target mal configurado.
	fwOlder
	// fwAmbiguous: no se pudieron parsear versiones y el Contains no casa.
	// Se alerta como desactualizado (semántica previa a #1412) porque no hay
	// base para decidir otra cosa.
	fwAmbiguous
)

var releaseVersionRe = regexp.MustCompile(`\d+(?:\.\d+)+`)

// parseReleaseVersion extrae la primera versión con puntos del string
// ("OpenWrt 25.12.5 r33051-f5dae5ece4" -> "25.12.5"; "25.12.6" -> "25.12.6").
// Vacío si no hay ninguna.
func parseReleaseVersion(s string) string {
	return releaseVersionRe.FindString(s)
}

// compareReleaseVersions compara dos versiones punto a punto numéricamente:
// -1 si a < b, 0 si iguales (en los componentes presentes), 1 si a > b.
// "25.12" vs "25.12.6": los componentes que faltan cuentan como 0, así que
// "25.12" == "25.12.0" < "25.12.6".
func compareReleaseVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, bi := 0, 0
		if i < len(as) {
			ai, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bi, _ = strconv.Atoi(bs[i])
		}
		if ai != bi {
			if ai < bi {
				return -1
			}
			return 1
		}
	}
	return 0
}

// firmwareCompare decide la relación entre el firmware instalado y el target
// configurado (issue #1412). Target vacío -> fwMatch (no hay comprobación).
func firmwareCompare(installed, target string) int {
	target = strings.TrimSpace(target)
	if target == "" {
		return fwMatch
	}
	iv := parseReleaseVersion(installed)
	tv := parseReleaseVersion(target)
	if iv != "" && tv != "" {
		switch compareReleaseVersions(tv, iv) {
		case 1:
			return fwNewer
		case -1:
			return fwOlder
		}
		return fwMatch
	}
	// Sin versiones parseables: Contains insensible a mayúsculas del TARGET
	// COMPLETO (#241), no del fragmento parseado.
	if strings.Contains(strings.ToLower(strings.TrimSpace(installed)), strings.ToLower(target)) {
		return fwMatch
	}
	return fwAmbiguous
}
