package rpm

import (
	"bytes"
	"testing"
)

// IBM's HMC help RPM describes 81,451 files with many parallel per-file arrays.
// Total values may exceed one million while both raw and decoded metadata fit
// comfortably within the declared byte budget; count alone is not the budget.
func TestLargeParallelFileArrays(t *testing.T) {
	fields := make([]field, 14)
	for i := range fields {
		fields[i] = field{uint32(6000 + i), 4, 81451, make([]byte, 81451*4)}
	}
	data, _, _ := fixture(fields...)
	pkg, err := Open(bytes.NewReader(data), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg.Header.Entries) != 14 || len(pkg.Header.Entries[13].Numbers) != 81451 {
		t.Fatal("lost array entries")
	}
	// Raw bytes still fit, but decoded uint64 arrays exceed this smaller limit.
	if _, err := Open(bytes.NewReader(data), Limits{65536, 6 << 20}); err == nil {
		t.Fatal("ignored decoded byte budget")
	}
}
