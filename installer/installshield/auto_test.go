package installshield

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestAutoInstallerPayloadAndOriginalEXE(t *testing.T) {
	for _, test := range []struct {
		name, format, member string
		data, want           []byte
	}{
		{"cab", "embedded_cab", "hello.txt", append([]byte("MZ launcher data"), uncompressedTestCabinet("hello.txt", []byte("hello installer"))...), []byte("hello installer")},
		{"installshield", "installshield4", "ungrouped/Bin/legacy.bin", append([]byte("MZ launcher data"), uncompressedTestCabinet("data1.cab", installShieldV4Fixture(t))...), []byte("legacy compressed payload")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := auto.Open(&starfile.Bytes{Data: test.data}, "setup.exe", auto.Options{})
			info, err := root.Metadata()
			if err != nil || info.Format != test.format || !info.Container {
				t.Fatalf("metadata=%+v %v", info, err)
			}
			child, err := root.Resolve(test.member)
			if err != nil {
				t.Fatal(err)
			}
			data, err := starfile.ReadAll(child.Reader())
			if err != nil || !bytes.Equal(data, test.want) {
				t.Fatalf("payload %q %v", data, err)
			}
			original, err := starfile.ReadAll(root.Reader())
			if err != nil || !bytes.Equal(original, test.data) {
				t.Fatal("original executable changed", err)
			}
		})
	}
}
func TestAutoInstallerSFXAndOrdinaryExecutable(t *testing.T) {
	exe := make([]byte, 1024)
	copy(exe, "MZ")
	binary.LittleEndian.PutUint32(exe[0x3c:], 64)
	copy(exe[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(exe[70:], 1)
	binary.LittleEndian.PutUint16(exe[68:], 0x14c)
	binary.LittleEndian.PutUint16(exe[84:], 224)
	binary.LittleEndian.PutUint16(exe[88:], 0x10b)
	binary.LittleEndian.PutUint32(exe[88+60:], 512)
	binary.LittleEndian.PutUint32(exe[88+92:], 16)
	copy(exe[312:], ".text")
	binary.LittleEndian.PutUint32(exe[312+16:], 512)
	binary.LittleEndian.PutUint32(exe[312+20:], 512)
	plain := auto.Open(&starfile.Bytes{Data: exe}, "program.exe", auto.Options{})
	info, err := plain.Metadata()
	if err != nil || info.Container {
		t.Fatal(info, err)
	}
	root := auto.Open(&starfile.Bytes{Data: append(exe, sfxFixture()...)}, "setup.exe", auto.Options{})
	info, err = root.Metadata()
	if err != nil || info.Format != "installshield_sfx" {
		t.Fatal(info, err)
	}
	file, err := root.Resolve("Product.msi")
	if err != nil {
		t.Fatal(err)
	}
	data, err := starfile.ReadAll(file.Reader())
	if err != nil || string(data) != "database" {
		t.Fatal(string(data), err)
	}
}
