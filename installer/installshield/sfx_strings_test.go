package installshield

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func stringSFXRecord(name, full, payload string) string {
	return fmt.Sprintf("%s%c%s%c0.0.0.0%c%d%c%s", name, 0, full, 0, 0, len(payload), 0, payload)
}
func TestStringSFXBoundaries(t *testing.T) {
	first := stringSFXRecord("data1.cab", `Disk1\data1.cab`, "ISc( embedded MSCF decoy")
	second := stringSFXRecord("setup.ini", `Disk1\setup.ini`, "settings")
	a, recognized, err := openSFX(&starfile.Bytes{Data: []byte(first + second)}, 0)
	if err != nil || !recognized || len(a.names) != 2 {
		t.Fatal(a, recognized, err)
	}
	v, found, err := a.Get(starlark.String("/disk1/SETUP.INI"))
	if err != nil || !found {
		t.Fatal(found, err)
	}
	b, err := starfile.ReadAll(v.(starfile.File))
	if err != nil || string(b) != "settings" {
		t.Fatal(string(b), err)
	}
	for _, tail := range []string{
		second[:len(second)-1],
		stringSFXRecord("bad", "../bad", "x"),
		stringSFXRecord("data1.cab", `disk1\DATA1.CAB`, "ISc("),
		"unterminated",
	} {
		_, recognized, err := openSFX(&starfile.Bytes{Data: []byte(first + tail)}, 0)
		if !recognized || err == nil {
			t.Fatalf("bad tail accepted: %q (%v, %v)", tail, recognized, err)
		}
	}
	_, recognized, err = openSFX(&starfile.Bytes{Data: []byte(stringSFXRecord("data1.cab", `Disk1\data1.cab`, "not a cabinet but arbitrary executable overlay"))}, 0)
	if recognized || err != nil {
		t.Fatal(recognized, err)
	}
}
