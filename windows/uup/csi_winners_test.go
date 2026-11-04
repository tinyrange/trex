package uup

import "testing"

const winnerIdentity = "Microsoft-Windows-Test, Culture=neutral, Version=10.0.26100.9457, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS"

func TestCSIWinnerChangeNativeSelection(t *testing.T) {
	// These distinguish native impactful-install selection from a blanket maximum
	// over installed membership, and replacement from cross-branch removal.
	const old = "10.0.26100.9457"
	const lower = "10.0.26100.1"
	const next = "10.0.26100.9711"
	const branch = "10.26300.26100.9457"
	tests := []struct {
		name, current string
		members       []string
		changes       []CSIWinnerVersionChange
		want          CSIWinnerChange
	}{
		{name: "unchanged membership is not activation", current: old, members: []string{old, branch}},
		{name: "new higher nonimpactful owner", current: old, members: []string{old, next}, changes: []CSIWinnerVersionChange{{next, true, false}}},
		{name: "no effective winner without impact", members: []string{next}, changes: []CSIWinnerVersionChange{{next, true, false}}},
		{name: "first impactful install", members: []string{lower, next}, changes: []CSIWinnerVersionChange{{lower, true, true}, {next, true, false}}, want: CSIWinnerChange{Winner: lower}},
		{name: "upgrade within branch", current: old, members: []string{old, next}, changes: []CSIWinnerVersionChange{{next, true, true}}, want: CSIWinnerChange{Winner: next, Shadowed: old}},
		{name: "old version does not replace enablement winner", current: branch, members: []string{branch, next}, changes: []CSIWinnerVersionChange{{next, true, true}}},
		{name: "remove winner falls back without new install", current: branch, members: []string{lower, next}, changes: []CSIWinnerVersionChange{{branch, false, false}}, want: CSIWinnerChange{Winner: next, Shadowed: branch}},
		{name: "all removals excluded from fallback", current: branch, members: []string{lower}, changes: []CSIWinnerVersionChange{{branch, false, false}, {next, false, false}}, want: CSIWinnerChange{Winner: lower, Shadowed: branch}},
		{name: "remove final winner", current: old, changes: []CSIWinnerVersionChange{{old, false, false}}, want: CSIWinnerChange{Shadowed: old}},
		{name: "reinstall same winner", current: old, members: []string{old}, changes: []CSIWinnerVersionChange{{old, true, true}}},
		{name: "numeric not lexical order", current: "10.0.9.0", members: []string{"10.0.9.0", "10.0.10.0"}, changes: []CSIWinnerVersionChange{{"10.0.10.0", true, true}}, want: CSIWinnerChange{Winner: "10.0.10.0", Shadowed: "10.0.9.0"}},
		{name: "zero version is not missing", members: []string{"0.0.0.0"}, changes: []CSIWinnerVersionChange{{"0.0.0.0", true, true}}, want: CSIWinnerChange{Winner: "0.0.0.0"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := AnalyzeCSIWinnerChange([]byte(winnerIdentity), test.current, test.members, test.changes)
			if err != nil || got != test.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestCSIWinnerChangeServicingScope(t *testing.T) {
	const base = "Microsoft.VC90.CRT, Culture=neutral, Version=9.0.30729.1, PublicKeyToken=1fc8b3b9a1e18e3, ProcessorArchitecture=x86"
	const other = "10.0.1.0"
	for _, kind := range []string{"policy", "win32-policy", "Win32-Policy"} {
		got, err := AnalyzeCSIWinnerChange([]byte(base+", Type="+kind), "", []string{other}, []CSIWinnerVersionChange{{other, true, true}})
		if err != nil || got.Winner != other {
			t.Fatalf("policy %s: %+v, %v", kind, got, err)
		}
	}
	for _, suffix := range []string{"", ", Type=win32", ", Type=notpolicy", ", Type=-policy", ", Type=-POLICY"} {
		_, err := AnalyzeCSIWinnerChange([]byte(base+suffix), "", []string{other}, nil)
		if err == nil {
			t.Fatalf("ordinary SxS accepted unrelated major/minor: %s", suffix)
		}
	}
	got, err := AnalyzeCSIWinnerChange([]byte(base), "9.0.30729.1", []string{"9.0.30729.1", "9.0.30729.9"}, []CSIWinnerVersionChange{{"9.0.30729.9", true, true}})
	if err != nil || got.Winner != "9.0.30729.9" {
		t.Fatalf("same-branch SxS: %+v, %v", got, err)
	}
}

func TestCSIWinnerChangeRejectsIncompleteOrAmbiguousInputs(t *testing.T) {
	for _, version := range []string{"10.0.1", "10.0.1.2.3", "10.0.65536.0", "10.0.-1.0", "10.0.01.0", "10.0.+1.0"} {
		if _, err := AnalyzeCSIWinnerChange([]byte(winnerIdentity), "", []string{version}, nil); err == nil {
			t.Errorf("accepted version %q", version)
		}
	}
	const v = "10.0.26100.9457"
	tests := []struct {
		name, current string
		members       []string
		changes       []CSIWinnerVersionChange
	}{
		{name: "duplicate membership", members: []string{v, v}},
		{name: "duplicate change", members: []string{v}, changes: []CSIWinnerVersionChange{{v, true, false}, {v, true, true}}},
		{name: "missing final member", changes: []CSIWinnerVersionChange{{v, true, true}}},
		{name: "removed still member", members: []string{v}, changes: []CSIWinnerVersionChange{{v, false, false}}},
		{name: "missing current without removal", current: v},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := AnalyzeCSIWinnerChange([]byte(winnerIdentity), test.current, test.members, test.changes); err == nil {
				t.Fatal("accepted inconsistent winner inputs")
			}
		})
	}
	if _, err := AnalyzeCSIWinnerChange([]byte("abbreviated-key-name"), "", nil, nil); err == nil {
		t.Fatal("accepted lossy identity")
	}
}
