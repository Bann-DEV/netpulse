// vitals.go — which vitals an SNMP/external poll actually supplied (issue #1537).
//
// #441 made buildRouter and GetMetricsRows null out CPU/RAM/temp for every
// SNMP/external source ("the source can't report vitals"), so the frontend hid
// the whole vitals row. Netgear FastPath (CPU/RAM/temp via the 4526 private MIB)
// and MikroTik SwOS (chassis temp) DO supply real readings, revived through the
// hasCpu/hasRam/hasTemp flags. resolveSnmpVitals centralises that decision so
// the two callers expose exactly what the poll measured — and nothing is faked
// as a 0 when the source has no reading.
package adapters

// snmpVitals is the set of vitals an SNMP/external poll actually measured, plus
// the memory pool in MiB (for the detail's "X of Y MB" readout).
type snmpVitals struct {
	cpu, ram, temp *int
	available      bool
	memTotalMb     int
	memUsedMb      int
}

// resolveSnmpVitals returns the vitals the poll supplied (nil where it had no
// reading) and whether any exists. available drives Router.VitalsAvailable so a
// source with real readings is displayed instead of hidden.
func resolveSnmpVitals(p *routerPolled) snmpVitals {
	var v snmpVitals
	if p == nil {
		return v
	}
	if p.hasCpu {
		v.cpu = iptr(p.cpu)
	}
	if p.hasRam {
		v.ram = iptr(p.ram)
	}
	if p.hasTemp {
		v.temp = iptr(p.temp)
	}
	v.available = v.cpu != nil || v.ram != nil || v.temp != nil
	v.memTotalMb, v.memUsedMb = p.memTotalMb, p.memUsedMb
	return v
}
