package windows

import (
	"encoding/binary"
	"testing"
)

func TestAPISetImporterSelectorsAreNotLoadRequests(t *testing.T) {
	for _, test := range []struct{ stored, requested, want string }{
		{"service.exe", "service.exe", "advapi32.dll"},
		{"drvstore", "drvstore.dll", "kernelbase.dll"},
	} {
		data := apiSetFixture()
		at := binary.LittleEndian.Uint32(data[136:])
		for index, c := range []byte(test.stored) {
			binary.LittleEndian.PutUint16(data[int(at)+2*index:], uint16(c))
		}
		binary.LittleEndian.PutUint32(data[140:], uint32(len(test.stored)*2))
		namespace, err := ParseAPISetNamespace(data)
		if err != nil {
			t.Fatal(err)
		}
		if namespace.Entries[0].Values[1].Importer != test.stored {
			t.Fatal("stored selector was rewritten")
		}
		host, ok := namespace.Resolve("api-ms-win-test-l1-1-0", test.requested)
		if !ok || host != test.want {
			t.Fatalf("selector %q query %q=(%q,%v)", test.stored, test.requested, host, ok)
		}
	}
}
