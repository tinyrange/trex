package windows

import "testing"

func TestPEImportEntryRVAs(t *testing.T) {
	tests := []struct {
		name               string
		is64               bool
		index              uint32
		wantTable, wantIAT uint32
	}{
		{name: "pe32 first", index: 0, wantTable: 0x2000, wantIAT: 0x3000},
		{name: "pe32 later", index: 3, wantTable: 0x200c, wantIAT: 0x300c},
		{name: "pe32+ later", is64: true, index: 3, wantTable: 0x2018, wantIAT: 0x3018},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table, iat := peImportEntryRVAs(0x2000, 0x3000, test.index, test.is64)
			if table != test.wantTable || iat != test.wantIAT {
				t.Fatalf("got table=%#x IAT=%#x, want table=%#x IAT=%#x", table, iat, test.wantTable, test.wantIAT)
			}
		})
	}
}
