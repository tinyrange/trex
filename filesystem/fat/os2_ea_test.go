package fat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestOS2EAHandleTables(t *testing.T) {
	for _, spec := range []struct {
		size int64
		bits int
	}{{10 << 20, 12}, {16 << 20, 16}, {256 << 20, 16}} {
		t.Run(fmt.Sprint(spec), func(t *testing.T) {
			dir := filesystemapi.New()
			wants := map[string][]byte{}
			for i := 0; i < 140; i++ {
				name := fmt.Sprintf("/F%03d.TXT", i)
				dir.PutFile(name, filesystemapi.FileRecord{Data: []byte("payload"), Size: 7})
				value := []byte{byte(i), 0, 0xff}
				if i == 0 {
					value = bytes.Repeat([]byte{0xab}, 6000)
				}
				wants[name] = value
				if err := dir.SetExtendedAttributes(name, []filesystemapi.ExtendedAttribute{{Name: ".TEST", Flags: 0x80, Value: value}}); err != nil {
					t.Fatal(err)
				}
			}
			label, _ := fat32VolumeLabel("OS2EAS")
			image, err := buildFATImageWithOptionsAndGeometryAndBPB(dir, spec.size, nil, 63, label, nil, true, true, nil, spec.bits)
			if err != nil {
				t.Fatal(err)
			}
			// Caller state must not acquire the synthetic metadata file.
			if _, ok := dir.Snapshot().Files["/EA DATA. SF"]; ok {
				t.Fatal("builder mutated input")
			}
			volume, err := newFATImage(image)
			if err != nil {
				t.Fatal(err)
			}
			value, ok, err := volume.Get(starlark.String("/EA DATA. SF"))
			if err != nil || !ok {
				t.Fatal("EA file missing", err)
			}
			data, err := starfile.ReadAll(value.(starfile.File))
			if err != nil {
				t.Fatal(err)
			}
			boot := make([]byte, 512)
			if _, err = image.ReadAt(boot, 0); err != nil {
				t.Fatal(err)
			}
			cluster := int(boot[13]) * 512
			rootOffset := int64(binary.LittleEndian.Uint16(boot[14:]))*512 + int64(boot[16])*int64(binary.LittleEndian.Uint16(boot[22:]))*512
			entries := make([]byte, int(binary.LittleEndian.Uint16(boot[17:]))*32)
			if _, err = image.ReadAt(entries, rootOffset); err != nil {
				t.Fatal(err)
			}
			count := 0
			for off := 0; off < len(entries) && entries[off] != 0; off += 32 {
				e := entries[off : off+32]
				if e[11] == 0x0f || e[11]&8 != 0 {
					continue
				}
				if string(e[:11]) == "EA DATA  SF" {
					if e[11]&7 != 7 {
						t.Fatal("EA file is not hidden/system/readonly")
					}
					continue
				}
				name := "/" + strings.TrimRight(string(e[:8]), " ") + "." + strings.TrimRight(string(e[8:11]), " ")
				want := wants[name]
				handle := int(binary.LittleEndian.Uint16(e[20:22]))
				if handle < 1 || handle > 140 {
					t.Fatal("bad handle", name, handle)
				}
				base := int(binary.LittleEndian.Uint16(data[32+2*(handle/128):]))
				rel := int(binary.LittleEndian.Uint16(data[512+2*handle:]))
				set := (base + rel) * cluster
				if set < 512 || set+30 > len(data) {
					t.Fatal("set outside EA file", handle, set)
				}
				b := data[set:]
				if binary.LittleEndian.Uint16(b) != 0x4145 || int(binary.LittleEndian.Uint16(b[2:])) != handle || binary.LittleEndian.Uint32(b[4:]) != 1 {
					t.Fatal("set identity", handle)
				}
				if string(bytes.TrimRight(b[8:22], "\x00")) != strings.TrimPrefix(name, "/") {
					t.Fatal("wrong EA owner", name)
				}
				listLen := int(binary.LittleEndian.Uint32(b[26:]))
				if listLen != 4+5+5+len(want) || b[30] != 0x80 || b[31] != 5 || int(binary.LittleEndian.Uint16(b[32:])) != len(want) || string(b[34:40]) != ".TEST\x00" || !bytes.Equal(b[40:40+len(want)], want) {
					t.Fatal("EA payload", name)
				}
				f, found, err := volume.Get(starlark.String(name))
				if err != nil || !found {
					t.Fatal(name, err)
				}
				payload, err := starfile.ReadAll(f.(starfile.File))
				if err != nil || string(payload) != "payload" {
					t.Fatal("EA handle corrupted data cluster", name, err)
				}
				count++
			}
			if count != 140 || binary.LittleEndian.Uint16(data) != 0x4445 || binary.LittleEndian.Uint16(data[512:]) != 0xffff {
				t.Fatal("header/handle count", count)
			}
		})
	}
}

func TestOS2EARejectsUnrepresentableInput(t *testing.T) {
	label, _ := fat32VolumeLabel("OS2EAS")
	for _, which := range []string{"root", "collision", "oversize"} {
		t.Run(which, func(t *testing.T) {
			dir := filesystemapi.New()
			dir.PutFile("/A", filesystemapi.FileRecord{})
			target := "/A"
			value := []byte("value")
			if which == "root" {
				target = "/"
			}
			if which == "collision" {
				dir.PutFile("/EA DATA. SF", filesystemapi.FileRecord{})
			}
			if which == "oversize" {
				value = make([]byte, 65535)
			}
			if err := dir.SetExtendedAttributes(target, []filesystemapi.ExtendedAttribute{{Name: ".TEST", Value: value}}); err != nil {
				if which == "oversize" {
					return
				}
				t.Fatal(err)
			}
			if _, err := buildFAT16Image(dir, 16<<20, nil, 63, label); err == nil {
				t.Fatal("accepted invalid EA construction")
			}
		})
	}
}
