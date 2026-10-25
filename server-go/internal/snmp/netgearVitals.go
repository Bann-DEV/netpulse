// netgearVitals.go — vitales (CPU y temperatura) de switches Netgear
// FastPath (XS708T, GS728TXP/S3300 y familia) vía su MIB privada
// (NETGEAR enterprise 4526, ng700smartswitch = 4526.11):
//
//   - agentSwitchCpuProcessPercentageUtilization
//     1.3.6.1.4.1.4526.11.1.1.4.8.1.3.<idx>: STRING por proceso con tres
//     ventanas, "    5 Sec (  0.19%)   60 Sec (  0.16%)  300 Sec (  0.15%)".
//     El total del equipo es la suma por proceso (no hay tarea idle en la
//     tabla ni escalar de total).
//   - boxServicesTempSensorTemperature
//     1.3.6.1.4.1.4526.11.43.1.8.1.5.<idx>: Integer32 en °C por sensor; con
//     varios sensores se reporta el máximo (el punto caliente).
//   - agentSwitchCpuProcessMemFree / MemAvailable (KBytes scalars):
//     1.3.6.1.4.1.4526.11.1.1.4.1.0 and …4.2.0. There is no "MemTotal" scalar,
//     but MemAvailable is the device's usable total pool (≈ physical RAM minus
//     kernel reservations: 233 MB on a 256 MB GS728TXP, 486 MB on a 512 MB
//     XS708T), so usage is derived as used% = (MemAvailable − MemFree) /
//     MemAvailable.
package snmp

import (
	"regexp"
	"strconv"

	g "github.com/gosnmp/gosnmp"
)

const (
	// OidNetgearCpuUtil: per-process utilization column (5/60/300s string).
	OidNetgearCpuUtil = ".1.3.6.1.4.1.4526.11.1.1.4.8.1.3"
	// OidNetgearTempSensor: per-sensor temperature column (°C).
	OidNetgearTempSensor = ".1.3.6.1.4.1.4526.11.43.1.8.1.5"
	// OidNetgearMemFree / OidNetgearMemAvailable: KBytes scalars. MemAvailable
	// is the usable total pool, MemFree the currently-free part (see header).
	OidNetgearMemFree      = ".1.3.6.1.4.1.4526.11.1.1.4.1.0"
	OidNetgearMemAvailable = ".1.3.6.1.4.1.4526.11.1.1.4.2.0"
)

// cpuUtilRe casa la primera ventana ("5 Sec (  0.19%)") del string por
// proceso; es la misma que pinta el panel web del switch como instantánea.
var cpuUtilRe = regexp.MustCompile(`5\s+Sec\s*\(\s*([0-9]+(?:\.[0-9]+)?)\s*%\)`)

// ParseNetgearCpuUtil suma la utilización de 5s de cada proceso: sin tarea
// idle en la tabla, la suma es el total del equipo. Strings inparseables se
// ignoran (firmwares que cambian el formato no deben romper el sondeo).
func ParseNetgearCpuUtil(vals []string) (cpu int, ok bool) {
	total := 0.0
	seen := 0
	for _, v := range vals {
		m := cpuUtilRe.FindStringSubmatch(v)
		if m == nil {
			continue
		}
		f, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		total += f
		seen++
	}
	if seen == 0 {
		return 0, false
	}
	pct := int(total + 0.5)
	if pct > 100 {
		pct = 100
	}
	return pct, true
}

// ParseNetgearTemps devuelve el máximo de los sensores (punto caliente):
// con dos sensores (CPU y chasis) el que manda para alertas es el mayor.
func ParseNetgearTemps(vals []int) (temp int, ok bool) {
	max := 0
	for _, v := range vals {
		if v > max {
			max = v
		}
		ok = true
	}
	return max, ok
}

// ParseNetgearRam derives the used-memory percentage from the two KBytes
// scalars: MemAvailable is the usable total pool and MemFree the currently
// free part, so used% = (available - free) / available. Guards against a
// missing/zero total and free>available (transient between the two gets).
func ParseNetgearRam(freeKB, availKB int) (used int, ok bool) {
	if availKB <= 0 || freeKB < 0 {
		return 0, false
	}
	usedF := float64(availKB-freeKB) / float64(availKB) * 100.0
	if usedF < 0 {
		usedF = 0
	}
	used = int(usedF + 0.5)
	if used > 100 {
		used = 100
	}
	return used, true
}

// netgearKbFromPDU reads an integer KBytes value from a numeric PDU. Unlike
// mikrotikTempFromPDU it applies no temperature range cap (memory values are
// large); NoSuchObject/NoSuchInstance or a non-numeric type → ok=false.
func netgearKbFromPDU(v g.SnmpPDU) (int, bool) {
	if v.Type == g.NoSuchObject || v.Type == g.NoSuchInstance {
		return 0, false
	}
	switch v.Type {
	case g.Gauge32, g.Integer, g.Counter32, g.Counter64:
	default:
		return 0, false
	}
	bi := g.ToBigInt(v.Value)
	if bi == nil || !bi.IsInt64() {
		return 0, false
	}
	n := bi.Int64()
	if n < 0 {
		return 0, false
	}
	return int(n), true
}

// PollNetgearVitals lee CPU y temperatura del agente FastPath. Un switch sin
// estos árboles (otra familia) devuelve ok=false en ambos y el caller
// conserva sus vitales a null, como hoy. memTotalMb/memUsedMb are the memory
// pool in MiB (from MemAvailable/MemFree KBytes) so the detail can render a
// real "X MB used of Y MB" instead of the frontend's static demo total.
func PollNetgearVitals(s *g.GoSNMP) (cpu int, okCpu bool, temp int, okTemp bool, ram int, okRam bool, memTotalMb int, memUsedMb int) {
	if s == nil {
		return 0, false, 0, false, 0, false, 0, 0
	}
	if pdus, err := walkSafe(s, OidNetgearCpuUtil); err == nil {
		vals := make([]string, 0, len(pdus))
		for _, p := range pdus {
			vals = append(vals, stringVal(p))
		}
		cpu, okCpu = ParseNetgearCpuUtil(vals)
	}
	if pdus, err := walkSafe(s, OidNetgearTempSensor); err == nil {
		vals := make([]int, 0, len(pdus))
		for _, p := range pdus {
			// mikrotikTempFromPDU es el conversor genérico PDU numérica→int
			// del paquete (tipos + NoSuchObject); el nombre viene de su
			// primer usuario, no de su alcance.
			if v, ok := mikrotikTempFromPDU(p); ok {
				vals = append(vals, v)
			}
		}
		temp, okTemp = ParseNetgearTemps(vals)
	}
	// Memory: two KBytes scalars in one GET. Missing/free>available → ok=false
	// and the caller leaves RAM null (the #441 SNMP nulled-vitals contract).
	if res, err := s.Get([]string{OidNetgearMemFree, OidNetgearMemAvailable}); err == nil {
		free, avail, haveFree, haveAvail := 0, 0, false, false
		for _, p := range res.Variables {
			switch p.Name {
			case OidNetgearMemFree:
				if v, ok := netgearKbFromPDU(p); ok {
					free, haveFree = v, true
				}
			case OidNetgearMemAvailable:
				if v, ok := netgearKbFromPDU(p); ok {
					avail, haveAvail = v, true
				}
			}
		}
		if haveFree && haveAvail {
			ram, okRam = ParseNetgearRam(free, avail)
			memTotalMb = (avail + 512) / 1024
			usedKB := avail - free
			if usedKB < 0 {
				usedKB = 0
			}
			memUsedMb = (usedKB + 512) / 1024
		}
	}
	return cpu, okCpu, temp, okTemp, ram, okRam, memTotalMb, memUsedMb
}
