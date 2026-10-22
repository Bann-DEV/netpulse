// portable.go — sondas portables sin ubus (#1481 phase 1.5): lecturas de
// /proc y /etc que funcionan en cualquier Linux (Asuswrt, Merlin, DSM).
package probe

import (
	"os"
	"strconv"
	"strings"
)

// meminfoKB: campos de /proc/meminfo en kB que necesita el fallback portable
// (#1481 phase 1.5). Sin ubus, el server aplica su fórmula clásica
// (total-free-buffered-cached) con estos campos: misma semántica de "uso"
// que en unidades con ubus, donde Used es la suma de RSS (#513). Rellenar
// Used con total-available incluiría la caché de ficheros y dispararía el
// porcentaje muy por encima del uso real de procesos.
type meminfoKB struct {
	total, free, buffered, cached, avail int64
}

// parseMeminfoFieldsKB extrae los campos de /proc/meminfo. Sin
// MemAvailable (kernels viejos) aproxima con MemFree.
func parseMeminfoFieldsKB(data string) meminfoKB {
	var m meminfoKB
	haveAvail := false
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			m.total = n
		case "MemFree:":
			m.free = n
		case "Buffers:":
			m.buffered = n
		case "Cached:":
			m.cached = n
		case "MemAvailable:":
			m.avail, haveAvail = n, true
		}
	}
	if !haveAvail {
		m.avail = m.free
	}
	return m
}

// readMeminfoFieldsKB lee /proc/meminfo del propio host (el agente corre EN
// el equipo; fuera de Linux la lectura falla y devuelve cero).
func readMeminfoFieldsKB() meminfoKB {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return meminfoKB{}
	}
	return parseMeminfoFieldsKB(string(data))
}
