package fat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"testing"
)

func TestFAT12RootCapacityCoherentLayout(t *testing.T) {
	for _, capacity := range []int{128, 224, 512} {
		dir := filesystemapi.New()
		payload := bytes.Repeat([]byte("cluster data"), 200)
		dir.PutFile("/TEST.REG", filesystemapi.FileRecord{Data: payload, Size: int64(len(payload))})
		value, err := FAT12Builtin(nil, nil, starlark.Tuple{dir, starlark.MakeInt(1440 << 10)}, []starlark.Tuple{{starlark.String("root_entries"), starlark.MakeInt(capacity)}})
		if err != nil {
			t.Fatal(err)
		}
		file := value.(starfile.File)
		data, err := starfile.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if got := int(binary.LittleEndian.Uint16(data[17:])); got != capacity {
			t.Fatalf("root field=%d want%d", got, capacity)
		}
		volume, err := newFATImage(file)
		if err != nil {
			t.Fatal(err)
		}
		expected := (int64(binary.LittleEndian.Uint16(data[14:])) + 2*int64(binary.LittleEndian.Uint16(data[22:])) + int64(capacity/16)) * 512
		if volume.dataOffset != expected || volume.rootDirSectors != int64(capacity/16) {
			t.Fatalf("incoherent layout: %+v", volume)
		}
		entry, found, err := volume.Get(starlark.String("/TEST.REG"))
		if err != nil || !found {
			t.Fatal(err)
		}
		actual, err := starfile.ReadAll(entry.(starfile.File))
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("cluster-chain data mismatch %v", err)
		}
		if !bytes.Equal(data[expected:expected+int64(len(payload))], payload) {
			t.Fatal("directory allocation disagrees with BPB data origin")
		}
	}
}
func TestFAT12RootCapacityBounds(t *testing.T) {
	for _, capacity := range []int{-1, 0, 1, 15, 17, 65536} {
		if _, err := FAT12Builtin(nil, nil, starlark.Tuple{filesystemapi.New(), starlark.MakeInt(1440 << 10)}, []starlark.Tuple{{starlark.String("root_entries"), starlark.MakeInt(capacity)}}); err == nil {
			t.Fatalf("accepted root capacity%d", capacity)
		}
	}
	dir := filesystemapi.New()
	for n := 0; n < 224; n++ {
		dir.PutFile(fmt.Sprintf("/F%03d.TXT", n), filesystemapi.FileRecord{Data: []byte("x"), Size: 1})
	}
	if _, err := FAT12Builtin(nil, nil, starlark.Tuple{dir, starlark.MakeInt(1440 << 10)}, []starlark.Tuple{{starlark.String("root_entries"), starlark.MakeInt(224)}}); err == nil {
		t.Fatal("accepted root overflow including label/terminator")
	}
}
