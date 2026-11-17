package s390

import "testing"

func TestSIGPNormalAndInitialResetHaveDistinctArchitecturalEffects(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2})
	// Actual SIGP reset (0c) and initial-reset (0b), CPU address in GR1.
	if err := m.Load([]Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x8000, Data: []byte{0xae, 0x01, 0, 0x0c, 0xae, 0x01, 0, 0x0b}}}, false); err != nil {
		t.Fatal(err)
	}
	issuer, target := m.CPUs[0], m.CPUs[1]
	issuer.GR[1] = 1
	target.GR[7], target.AR[9], target.FPR[2] = 17, 29, 0x4120000000000000
	target.PSW = PSW{IA: 0x3456, Amode31: true, Wait: true}
	target.Prefix, target.CR[7], target.ClockComparator = 0x4000, 0x76543000, 123
	target.Stopped, target.Check = true, true
	target.extPending = extInterruptKey
	m.Run(1)
	if issuer.PSW.CC != 0 || !target.Stopped || target.Check || target.extPending != 0 || target.PSW.IA != 0x3456 || !target.PSW.Wait || target.Prefix != 0x4000 || target.CR[7] != 0x76543000 || target.ClockComparator != 123 {
		t.Fatal("SIGP normal reset altered retained architectural state or kept pending conditions")
	}
	m.Run(1)
	if issuer.PSW.CC != 0 || !target.Stopped || target.PSW.IA != 0 || target.PSW.Wait || target.Prefix != 0 || target.CR[7] != 0 || target.ClockComparator != 0 {
		t.Fatal("SIGP initial reset did not initialize control state")
	}
	if target.GR[7] != 17 || target.AR[9] != 29 || target.FPR[2] != 0x4120000000000000 {
		t.Fatal("SIGP initial reset incorrectly cleared data banks")
	}
}
