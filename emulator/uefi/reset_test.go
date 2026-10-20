package uefi

import (
	"errors"
	"testing"
)

func TestFirmwareResetAndPersistentVariables(t *testing.T) {
	const gate = 0x1000
	m := &Machine{services: map[uint64]string{gate: "ResetSystem"}, variables: map[variableKey]Variable{}}
	f := &Firmware{machine: m}
	for kind := uint64(0); kind <= 2; kind++ {
		_, err := f.Call(gate, [10]uint64{kind})
		var reset *ResetRequest
		if !errors.As(err, &reset) || reset.Type != uint32(kind) {
			t.Fatalf("reset %d: %v", kind, err)
		}
	}
	if _, err := f.Call(gate, [10]uint64{3}); err == nil {
		t.Fatal("unsupported platform reset returned success")
	}
	id := "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
	for _, v := range []Variable{{Name: "persistent", GUID: id, Attributes: 7, Data: []byte{42}}, {Name: "volatile", GUID: id, Attributes: 6, Data: []byte{1}}} {
		if err := m.SetVariable(v); err != nil {
			t.Fatal(err)
		}
	}
	saved := f.NonvolatileVariables()
	if len(saved) != 1 || saved[0].Name != "persistent" {
		t.Fatal(saved)
	}
	saved[0].Data[0] = 43
	if f.NonvolatileVariables()[0].Data[0] != 42 {
		t.Fatal("snapshot aliases live store")
	}
	replacement := &Firmware{machine: &Machine{variables: map[variableKey]Variable{}}}
	if err := replacement.RestoreNonvolatileVariables(saved); err != nil {
		t.Fatal(err)
	}
	saved[0].Data[0] = 44
	if replacement.NonvolatileVariables()[0].Data[0] != 43 {
		t.Fatal("restored data aliases input")
	}
	// Deletion must survive a subsequent boot, not resurrect default values.
	if err := replacement.RestoreNonvolatileVariables(nil); err != nil || len(replacement.NonvolatileVariables()) != 0 {
		t.Fatal(err)
	}
}
