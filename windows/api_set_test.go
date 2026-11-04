package windows

import (
	"encoding/binary"
	"testing"
)

func apiSetFixture() []byte {
	data := make([]byte, 2048)
	put := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	put(0, 6)
	put(4, uint32(len(data)))
	put(8, 2)
	put(12, 2)
	put(16, 40)
	put(20, 88)
	put(24, 31)
	next := 208
	text := func(value string) (uint32, uint32) {
		start := next
		for _, c := range []byte(value) {
			binary.LittleEndian.PutUint16(data[next:], uint16(c))
			next += 2
		}
		return uint32(start), uint32(next - start)
	}
	contract, length := text("api-ms-win-test-l1-1-0")
	put(40, 1)
	put(44, contract)
	put(48, length)
	put(52, length-4)
	put(56, 112)
	put(60, 3)
	contract, length = text("ext-ms-win-empty-l1-1-0")
	put(68, contract)
	put(72, length)
	put(76, length-4)
	put(80, 172)
	put(84, 1)
	value := func(offset int, importer, host string) {
		io, il := text(importer)
		ho, hl := text(host)
		put(offset+4, io)
		put(offset+8, il)
		put(offset+12, ho)
		put(offset+16, hl)
	}
	value(112, "", "kernelbase.dll")
	value(132, "drvstore.dll", "advapi32.dll")
	value(152, "disabled.dll", "")
	value(172, "special.dll", "sechost.dll")
	hashes := []struct{ hash, index uint32 }{}
	for index := uint32(0); index < 2; index++ {
		at := uint32(40) + 24*index
		name := binary.LittleEndian.Uint32(data[at+4:])
		length := binary.LittleEndian.Uint32(data[at+12:])
		hash := uint32(0)
		for offset := uint32(0); offset < length; offset += 2 {
			hash = hash*31 + uint32(binary.LittleEndian.Uint16(data[name+offset:]))
		}
		hashes = append(hashes, struct{ hash, index uint32 }{hash, index})
	}
	if hashes[0].hash > hashes[1].hash {
		hashes[0], hashes[1] = hashes[1], hashes[0]
	}
	for index, item := range hashes {
		put(88+8*index, item.hash)
		put(92+8*index, item.index)
	}
	return data
}

func TestAPISetNamespaceImporterSelectionAndOwnership(t *testing.T) {
	data := apiSetFixture()
	parsed, err := ParseAPISetNamespace(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Flags != 2 || parsed.HashFactor != 31 || len(parsed.Entries) != 2 || parsed.Entries[0].Flags != 1 {
		t.Fatal("namespace metadata was lost")
	}
	for _, test := range []struct {
		contract, importer, want string
		ok                       bool
	}{
		{"API-MS-WIN-TEST-L1-1-0.DLL", "", "kernelbase.dll", true},
		{"api-ms-win-test-l1-1-0", "DRVSTORE", "advapi32.dll", true},
		{"api-ms-win-test-l1-1-0", "unrelated.dll", "kernelbase.dll", true},
		{"api-ms-win-test-l1-1-0", "disabled.dll", "", false},
		{"ext-ms-win-empty-l1-1-0", "special.dll", "sechost.dll", true},
		{"ext-ms-win-empty-l1-1-0", "", "sechost.dll", true},
		{"api-ms-win-test-l1-1-9", "", "kernelbase.dll", true},
		{"api-ms-win-test-l1-2-0", "", "", false},
		{"api-ms-win-missing-l1-1-0", "", "", false},
	} {
		got, ok := parsed.Resolve(test.contract, test.importer)
		if got != test.want || ok != test.ok {
			t.Fatalf("Resolve(%q,%q)=(%q,%v)", test.contract, test.importer, got, ok)
		}
	}
	for i := range data {
		data[i] = 0
	}
	if host, ok := parsed.Resolve("api-ms-win-test-l1-1-0", "drvstore.dll"); !ok || host != "advapi32.dll" {
		t.Fatal("parser retained mutable source bytes")
	}
}

func TestAPISetNamespaceRejectsMalformedBoundsAndAmbiguity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func([]byte)
	}{
		{"version", func(b []byte) { binary.LittleEndian.PutUint32(b, 4) }},
		{"small declared size", func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 27) }},
		{"oversize", func(b []byte) { binary.LittleEndian.PutUint32(b[4:], 0xffffffff) }},
		{"entry count overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[12:], 0xffffffff) }},
		{"entry offset overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[16:], 0xfffffff0) }},
		{"hash offset overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 0xfffffff8) }},
		{"name offset overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 0xfffffffc) }},
		{"odd name length", func(b []byte) { binary.LittleEndian.PutUint32(b[48:], 7) }},
		{"oversize hash name", func(b []byte) { binary.LittleEndian.PutUint32(b[52:], 1000) }},
		{"values offset overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[56:], 0xfffffff0) }},
		{"values count overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 0xffffffff) }},
		{"host offset overflow", func(b []byte) { binary.LittleEndian.PutUint32(b[124:], 0xffffffff) }},
		{"UTF16 surrogate", func(b []byte) { binary.LittleEndian.PutUint16(b[208:], 0xd800) }},
		{"embedded nul", func(b []byte) { binary.LittleEndian.PutUint16(b[210:], 0) }},
		{"host path", func(b []byte) { at := binary.LittleEndian.Uint32(b[124:]); binary.LittleEndian.PutUint16(b[at:], '\\') }},
		{"duplicate contract", func(b []byte) { copy(b[68:80], b[44:56]) }},
		{"ambiguous default host", func(b []byte) { binary.LittleEndian.PutUint32(b[140:], 0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := apiSetFixture()
			test.change(b)
			if value, err := ParseAPISetNamespace(b); err == nil || value != nil {
				t.Fatal("malformed namespace accepted or partially exposed")
			}
		})
	}
	valid := apiSetFixture()
	for end := 0; end < len(valid); end++ {
		if _, err := ParseAPISetNamespace(valid[:end]); err == nil {
			t.Fatalf("accepted prefix length %d", end)
		}
	}
}

func FuzzAPISetNamespaceBounds(f *testing.F) {
	f.Add(apiSetFixture())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseAPISetNamespace(data)
	})
}
