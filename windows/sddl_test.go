package windows

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCompileSDDLNativeConditionalACE(t *testing.T) {
	// Independent control: descriptor 432, last DACL ACE in image6 of the
	// 26300.9457 base install.wim. This file ACE has no propagation flags;
	// the manifest's corresponding directory declaration uses OICI instead.
	want := []byte("\x09\x00\x98\x00\xa9\x00\x12\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x21\x02\x00\x00artx\xf8\x1c\x00\x00\x00W\x00I\x00N\x00:\x00/\x00/\x00S\x00Y\x00S\x00A\x00P\x00P\x00I\x00D\x00\x10\x52\x00\x00\x00M\x00i\x00c\x00r\x00o\x00s\x00o\x00f\x00t\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00.\x00C\x00l\x00i\x00e\x00n\x00t\x00.\x00C\x00B\x00S\x00_\x00c\x00w\x005\x00n\x001\x00h\x002\x00t\x00x\x00y\x00e\x00w\x00y\x00\x86\x00\x00\x00")
	for _, flags := range []string{"", "OICI"} {
		raw, err := CompileSDDL(`D:P(XA;` + flags + `;0x1200A9;;;BU;(WIN://SYSAPPID Contains "MicrosoftWindows.Client.CBS_cw5n1h2txyewy"))`)
		if err != nil {
			t.Fatal(err)
		}
		_, entries, err := ParseACL(raw[20:])
		if err != nil || len(entries) != 1 {
			t.Fatalf("parse: %v %v", entries, err)
		}
		expected := bytes.Clone(want)
		if flags != "" {
			expected[1] = 3
		}
		if !bytes.Equal(entries[0].Data, expected) {
			t.Fatalf("ACE:\ngot  %x\nwant %x", entries[0].Data, expected)
		}
	}
}

func TestCompileSDDLPreservesACLStates(t *testing.T) {
	for _, tc := range []struct {
		text       string
		control    uint16
		dacl, sacl bool
	}{
		{"O:SY", 0x8000, false, false},
		{"D:", 0x8004, true, false},
		{"D:NO_ACCESS_CONTROL", 0x8004, false, false},
		{"O:SYG:SYD:AIS:AI", 0x8c14, true, true},
		{"D:PARAIS:PARAI", 0xbf14, true, true},
	} {
		raw, err := CompileSDDL(tc.text)
		if err != nil {
			t.Fatal(err)
		}
		if got := binary.LittleEndian.Uint16(raw[2:]); got != tc.control {
			t.Fatalf("%s control %x want %x", tc.text, got, tc.control)
		}
		for _, part := range []struct {
			offset  int
			present bool
		}{{16, tc.dacl}, {12, tc.sacl}} {
			offset := binary.LittleEndian.Uint32(raw[part.offset:])
			if (offset != 0) != part.present {
				t.Fatalf("%s offset %d", tc.text, offset)
			}
			if offset != 0 {
				_, entries, err := ParseACL(raw[offset : offset+8])
				if err != nil || len(entries) != 0 {
					t.Fatalf("empty ACL: %v %v", entries, err)
				}
			}
		}
	}
}

func TestCompileSDDLRightsAndSIDs(t *testing.T) {
	raw, err := CompileSDDL("S:(AU;FASA;0x000D0116;;;WD)D:P(A;;GRGX;;;BA)(A;;FRFX;;;LU)O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SY")
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(raw[2:]) != 0x9014 {
		t.Fatal("control")
	}
	d := int(binary.LittleEndian.Uint32(raw[16:]))
	s := int(binary.LittleEndian.Uint32(raw[12:]))
	_, aces, err := ParseACL(raw[d:s])
	if err != nil {
		t.Fatal(err)
	}
	if aces[0].Mask != 0xa0000000 || aces[1].Mask != 0x1200a9 {
		t.Fatal("generic rights were mapped or file rights incorrect")
	}
	sid, _ := SIDString(aces[1].SID)
	if sid != "S-1-5-32-559" {
		t.Fatal(sid)
	}
	_, audit, err := ParseACL(raw[s:])
	if err != nil {
		t.Fatal(err)
	}
	if audit[0].Type != 2 || audit[0].Flags != 0xc0 || audit[0].Mask != 0xd0116 {
		t.Fatal(audit)
	}
}

func TestCompileSDDLRejectsUnsupported(t *testing.T) {
	for _, text := range []string{"", "(inherit)", "O:", "O:DAO:SY", "O:SYG:SYG:BU", "D:Q", "D:(A;;FA;;;DA)", "D:(A;;ZZ;;;SY)", "D:(A;;0x100000000;;;SY)", "D:(A;;FA;guid;;SY)", "D:(AU;SA;FA;;;SY)", "S:(A;;FA;;;SY)", "D:(A;;FA;;;SY;)", "D:(XA;;FA;;;BU)", `D:(XA;;FA;;;BU;(WIN://SYSAPPID == "x"))`, `D:(XA;;FA;;;BU;(WIN://SYSAPPID Contains "x" || "y"))`, `D:(XA;;FA;;;BU;(WIN://SYSAPPID Contains "x\"y"))`, "D:(A;;FA;;;S-1-5-4294967296)", "D:(A;;FA;;;S-1-281474976710656-0)", "D:(A;;FA;;;SY))", "D:(A;;FA;;;SY", "O:SY\x00"} {
		if _, err := CompileSDDL(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	if _, err := CompileSDDL("D:" + strings.Repeat("(A;;FA;;;SY)", 4000)); err == nil {
		t.Fatal("accepted ACL extent overflow")
	}
}

func TestCompileSDDLNativeDirectoryAliases(t *testing.T) {
	// WCP 10.0.26100.9441 LocalConvertStringSDToSD_Rev1, fixed aliases
	// with LsaOpenPolicy explicitly denied. Domain-relative DA failed 0x539.
	aliases := map[string]string{
		"AU": "S-1-5-11", "BO": "S-1-5-32-551", "CO": "S-1-3-0",
		"IU": "S-1-5-4", "LS": "S-1-5-19", "LW": "S-1-16-4096",
		"NO": "S-1-5-32-556", "NS": "S-1-5-20", "RC": "S-1-5-12",
		"SU": "S-1-5-6", "UD": "S-1-5-84-0-0-0-0-0",
	}
	for alias, want := range aliases {
		raw, err := CompileSDDL("O:" + alias)
		if err != nil {
			t.Fatal(alias, err)
		}
		offset := binary.LittleEndian.Uint32(raw[4:])
		got, err := SIDString(raw[offset:])
		if err != nil || got != want {
			t.Fatalf("%s: %s, %v; want %s", alias, got, err, want)
		}
	}
	if _, err := CompileSDDL("O:DA"); err == nil {
		t.Fatal("domain context was guessed")
	}
}

func TestCompileSDDLNativeDirectoryRights(t *testing.T) {
	// Independent native parser captures, including concatenated numeric terms.
	masks := map[string]uint32{
		"CC": 1, "DC": 2, "LC": 4, "SW": 8, "RP": 0x10, "WP": 0x20,
		"DT": 0x40, "LO": 0x80, "CR": 0x100,
		"KA": 0xf003f, "KR": 0x20019, "KW": 0x20006, "KX": 0x20019,
		"1": 1, "010": 8, "08": 8,
		"WDWOSD0x1000000": 0x10d0000, "0x1000000WD": 0x1040000, "1WD": 0x40001,
	}
	for text, want := range masks {
		raw, err := CompileSDDL("D:(A;;" + text + ";;;SY)")
		if err != nil {
			t.Fatal(text, err)
		}
		offset := binary.LittleEndian.Uint32(raw[16:])
		_, entries, err := ParseACL(raw[offset:])
		if err != nil || len(entries) != 1 {
			t.Fatalf("%s: %v", text, err)
		}
		if entries[0].Mask != want {
			t.Fatalf("%s: %x, want %x", text, entries[0].Mask, want)
		}
	}
	for _, text := range []string{"0x", "0x100000000", "4294967296", "-1", "+1", "WDunknown"} {
		if _, err := CompileSDDL("D:(A;;" + text + ";;;SY)"); err == nil {
			t.Fatal("accepted", text)
		}
	}
}

func TestCompileSDDLNativeMandatoryLabel(t *testing.T) {
	// Complete native descriptor, not synthesized via the implementation.
	want := []byte("\x01\x00\x10\x80\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x11\x03\x14\x00\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x10\x00\x10\x00\x00")
	got, err := CompileSDDL("S:(ML;OICI;1;;;LW)")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%x, %v; want %x", got, err, want)
	}
	want[32] = 7
	got, err = CompileSDDL("S:(ML;OICI;7;;;S-1-16-4096)")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%x, %v; want %x", got, err, want)
	}
	for _, text := range []string{"S:(ML;;1;;;SY)", "S:(ML;SA;1;;;LW)", "S:(ML;;8;;;LW)", "D:(ML;;1;;;LW)"} {
		if _, err := CompileSDDL(text); err == nil {
			t.Fatal("accepted", text)
		}
	}
}

func TestCompileSDDLNativeExists(t *testing.T) {
	// Exact ACE from WCP LocalConvertStringSDToSD_Rev1, not an evaluated predicate.
	want := []byte("\x09\x00\x40\x00\xa9\x00\x12\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x21\x02\x00\x00artx\xf8\x1c\x00\x00\x00W\x00I\x00N\x00:\x00/\x00/\x00S\x00Y\x00S\x00A\x00P\x00P\x00I\x00D\x00\x87\x00\x00")
	raw, err := CompileSDDL("D:(XA;;FRFX;;;BU;(exists WIN://SYSAPPID))")
	if err != nil {
		t.Fatal(err)
	}
	_, entries, err := ParseACL(raw[20:])
	if err != nil || len(entries) != 1 {
		t.Fatalf("%v %v", entries, err)
	}
	if !bytes.Equal(entries[0].Data, want) {
		t.Fatalf("got %x; want %x", entries[0].Data, want)
	}
	for _, expression := range []string{"exists ", "exists WIN://SYSAPPID || true", "not_exists WIN://SYSAPPID", "exists @User.x", "exists WIN://SYSAPPID == 1"} {
		if _, err := CompileSDDL("D:(XA;;FRFX;;;BU;(" + expression + "))"); err == nil {
			t.Fatal("accepted", expression)
		}
	}
}

func TestCompileSDDLNativeRegistryAliases(t *testing.T) {
	// Captured from pinned WCP 26100.9441 whole-manifest ProcessKeys and its
	// native SDDL converter, not generated from this parser's alias table.
	for _, tc := range []struct {
		alias string
		sid   []byte
	}{
		{"AN", []byte{1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0}},
		{"BG", []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x22, 2, 0, 0}},
		{"CG", []byte{1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0}},
		{"OW", []byte{1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0}},
		{"SO", []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x25, 2, 0, 0}},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			raw, err := CompileSDDL("D:(A;;KA;;;" + tc.alias + ")")
			if err != nil {
				t.Fatal(err)
			}
			offset := binary.LittleEndian.Uint32(raw[16:])
			_, entries, err := ParseACL(raw[offset:])
			if err != nil || len(entries) != 1 {
				t.Fatalf("ACL: %v %v", entries, err)
			}
			if !bytes.Equal(entries[0].SID, tc.sid) || entries[0].Mask != 0xf003f {
				t.Fatalf("native alias SID/mask: %x/%x", entries[0].SID, entries[0].Mask)
			}
		})
	}
	// LA needs an explicit account-domain context, unlike these fixed SIDs.
	if _, err := CompileSDDL("D:(A;;KA;;;LA)"); err == nil {
		t.Fatal("domain-relative administrator alias accepted without context")
	}
}

func TestCompileSDDLExplicitAccountDomain(t *testing.T) {
	// Pinned WCP ProcessKeys with a NULL DNS-domain SID queried account-domain
	// information and emitted exactly this image-identity SID plus RID 500.
	domain := "S-1-5-21-1517966988-1889328950-60993633"
	got, err := CompileSDDLWithAccountDomain("D:(A;;KA;;;LA)", domain)
	if err != nil {
		t.Fatal(err)
	}
	want, err := CompileSDDL("D:(A;;KA;;;" + domain + "-500)")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("native LA descriptor: %x / %x, %v", got, want, err)
	}
	for _, invalid := range []string{"", "SY", "S-1-5-32-544", domain + "-500", "S-1-1-21-1-2-3", "S-1-5-21-1-2-4294967296", "S-1-5-21-01-2-3"} {
		if _, err := CompileSDDLWithAccountDomain("D:(A;;KA;;;LA)", invalid); err == nil {
			t.Errorf("accepted invalid account domain %q", invalid)
		}
	}
	if _, err := CompileSDDLWithAccountDomain("D:(A;;KA;;;DA)", domain); err == nil {
		t.Fatal("broadened unverified relative alias support")
	}
	for _, text := range []string{"O:LAG:SYD:(A;;KA;;;LA)", "O:SYG:LAD:(A;;KA;;;SY)"} {
		got, err := CompileSDDLWithAccountDomain(text, domain)
		want, wantErr := CompileSDDL(strings.ReplaceAll(text, "LA", domain+"-500"))
		if err != nil || wantErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("principal context: %q: %v/%v", text, err, wantErr)
		}
	}
}

func TestCompileSDDLNativeRegistryNegation(t *testing.T) {
	// Complete descriptor captured from WCP 26100.9441 ProcessKeys and its
	// native SDDL converter for the update's local-attribute NOT predicate.
	want := []byte("\x01\x00\x04\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00X\x00\x01\x00\x00\x00\x09\x02P\x00\x1f\x00\x03\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x21\x02\x00\x00artx\xf8\x2e\x00\x00\x00W\x00I\x00N\x00:\x00/\x00/\x00I\x00S\x00M\x00U\x00L\x00T\x00I\x00S\x00E\x00S\x00S\x00I\x00O\x00N\x00S\x00K\x00U\x00\xa2")
	got, err := CompileSDDL("D:(XA;CI;KRKWSD;;;BU;(!(WIN://ISMULTISESSIONSKU)))")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %x, %v; want %x", got, err, want)
	}
	for _, expression := range []string{"!()", "!WIN://ISMULTISESSIONSKU", "!((WIN://ISMULTISESSIONSKU))", "!(WIN://ISMULTISESSIONSKU || true)", "!(exists WIN://ISMULTISESSIONSKU)", "!(WIN://ISMULTISESSIONSKU) && true"} {
		if _, err := CompileSDDL("D:(XA;;KA;;;BU;(" + expression + "))"); err == nil {
			t.Fatal("accepted", expression)
		}
	}
}

func TestCompileSDDLCryptoOperators(t *testing.T) {
	// First two ACEs of Server 26100.32230 SYSTEM/ControlSet001/Control/
	// Cryptography/Configuration/Local, paired with its manifest's CY alias.
	raw, err := CompileSDDL("D:PAI(A;OICI;CCDCLCSWRPWPSDRC;;;CY)(A;OICIIO;SDGXGWGR;;;CY)")
	if err != nil {
		t.Fatal(err)
	}
	_, entries, err := ParseACL(raw[20:])
	if err != nil || len(entries) != 2 {
		t.Fatalf("ACL: %v %v", entries, err)
	}
	expected := [][]byte{
		[]byte("\x00\x03\x18\x00\x3f\x00\x03\x00\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x39\x02\x00\x00"),
		[]byte("\x00\x0b\x18\x00\x00\x00\x01\xe0\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x39\x02\x00\x00"),
	}
	for i := range entries {
		if !bytes.Equal(entries[i].Data, expected[i]) {
			t.Fatalf("ACE%d: %x want %x", i, entries[i].Data, expected[i])
		}
	}
}
