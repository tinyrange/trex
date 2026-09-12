package installshield

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func sfxFixture() []byte {
	data := make([]byte, 46)
	copy(data, "InstallShield\x00")
	binary.LittleEndian.PutUint32(data[14:], 2)
	for _, entry := range []struct{ name, payload string }{{"prerequisite.exe", "MSCF decoy"}, {"Product.msi", "database"}} {
		header := make([]byte, 312)
		copy(header, entry.name)
		binary.LittleEndian.PutUint32(header[268:], uint32(len(entry.payload)))
		data = append(data, header...)
		data = append(data, entry.payload...)
	}
	return data
}
func TestSFXUsesDeclaredFileBoundaries(t *testing.T) {
	data := append(sfxFixture(), []byte("certificate tail")...)
	a, recognized, err := openSFX(&starfile.Bytes{Data: data}, 0)
	if err != nil || !recognized {
		t.Fatal(recognized, err)
	}
	if a.size != int64(len(sfxFixture())) || len(a.names) != 2 {
		t.Fatal(a)
	}
	v, found, err := a.Get(starlark.String("/PRODUCT.MSI"))
	if err != nil || !found {
		t.Fatal(err)
	}
	content, err := starfile.ReadAll(v.(starfile.File))
	if err != nil || string(content) != "database" {
		t.Fatal(string(content), err)
	}
}
func TestSFXRejectsInvalidRecords(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"path", func(b []byte) { copy(b[46:], "../bad.exe\x00") }},
		{"flags", func(b []byte) { b[46+260] = 1 }},
		{"length", func(b []byte) { binary.LittleEndian.PutUint32(b[46+268:], 0xffffffff) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := sfxFixture()
			test.mutate(data)
			_, recognized, err := openSFX(&starfile.Bytes{Data: data}, 0)
			if !recognized || err == nil {
				t.Fatal(recognized, err)
			}
		})
	}
}
func TestInstallerMediaRejectsUnrecognizedDirectory(t *testing.T) {
	files := starlark.NewDict(1)
	_ = files.SetKey(starlark.String("readme.txt"), &starfile.Bytes{Data: []byte("hello")})
	_, err := MediaBuiltin(nil, nil, starlark.Tuple{files}, nil)
	if err == nil || !strings.Contains(err.Error(), "no supported") {
		t.Fatal(err)
	}
}
