package fat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestFAT16BuilderRoundTrip(t *testing.T) {
	dir := filesystemapi.New()
	dir.Mkdir("/WINNT/System32")
	dir.PutFile("/NTLDR", filesystemapi.FileRecord{Data: []byte("loader"), Size: 6})
	dir.PutFile("/WINNT/System32/kernel32.dll", filesystemapi.FileRecord{Data: []byte("kernel"), Size: 6})
	label, err := fat32VolumeLabel("WINDOWS NT")
	if err != nil {
		t.Fatal(err)
	}
	image, err := buildFAT16Image(dir, 256*1024*1024, nil, 2048, label)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newFATImage(image)
	if err != nil {
		t.Fatal(err)
	}
	if volume.fatType != 16 {
		t.Fatalf("FAT type = %d, want 16", volume.fatType)
	}
	for name, want := range map[string][]byte{
		"/NTLDR":                       []byte("loader"),
		"/WINNT/System32/kernel32.dll": []byte("kernel"),
	} {
		value, found, err := volume.Get(starlark.String(name))
		if err != nil || !found {
			t.Fatalf("%s: found=%t err=%v", name, found, err)
		}
		got, err := starfile.ReadAll(value.(starfile.File))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestFAT12BuilderRoundTrip(t *testing.T) {
	dir := filesystemapi.New()
	payload := bytes.Repeat([]byte("trex DOS "), 2048)
	dir.PutFile("/IO.SYS", filesystemapi.FileRecord{Data: payload, Size: int64(len(payload))})
	dir.PutFile("/COMMAND.COM", filesystemapi.FileRecord{Data: []byte("shell"), Size: 5})
	label, err := fat32VolumeLabel("MS-DOS")
	if err != nil {
		t.Fatal(err)
	}
	image, err := buildFATImageWithOptionsAndGeometryAndBPB(
		dir, 10*1024*1024, nil, 63, label,
		[]string{"/IO.SYS", "/COMMAND.COM"}, false, false, nil, 12,
	)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newFATImage(image)
	if err != nil {
		t.Fatal(err)
	}
	if volume.fatType != 12 {
		t.Fatalf("FAT type = %d, want 12", volume.fatType)
	}
	value, found, err := volume.Get(starlark.String("/IO.SYS"))
	if err != nil || !found {
		t.Fatalf("IO.SYS: found=%t err=%v", found, err)
	}
	got, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("IO.SYS decoded %d bytes, want %d", len(got), len(payload))
	}
}

func TestFAT16BuilderUsesConfiguredBootTemplate(t *testing.T) {
	dir := filesystemapi.New()
	label, _ := fat32VolumeLabel("WINDOWS NT")
	bootCode := make([]byte, 512)
	copy(bootCode[:3], []byte{0xeb, 0x3c, 0x90})
	bootCode[100] = 0xa5
	image, err := buildFAT16Image(dir, 64*1024*1024, bootCode, 63, label)
	if err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := image.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if sector[100] != 0xa5 {
		t.Fatalf("boot template byte = %#x, want 0xa5", sector[100])
	}
	if got := binary.LittleEndian.Uint32(sector[28:32]); got != 63 {
		t.Fatalf("hidden sectors = %d, want 63", got)
	}
	if got := string(sector[54:62]); got != "FAT16   " {
		t.Fatalf("filesystem type = %q, want FAT16", got)
	}
}

func TestFAT16BuilderCanPreservePreExtendedBPBBootCode(t *testing.T) {
	dir := filesystemapi.New()
	label, _ := fat32VolumeLabel("MS-DOS")
	bootCode := make([]byte, 512)
	bootCode[36] = 0xa5
	bootCode[54] = 0x5a
	image, err := buildFAT16ImageWithOptionsAndGeometryAndBPB(dir, 32*1024*1024, bootCode, 63, label, nil, false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := image.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if sector[36] != 0xa5 || sector[54] != 0x5a {
		t.Fatalf("legacy boot code bytes = %#x, %#x, want %#x, %#x", sector[36], sector[54], 0xa5, 0x5a)
	}
}

func TestFAT16BuilderRejectsOversizedBootCode(t *testing.T) {
	dir := filesystemapi.New()
	_, err := FAT16Builtin(nil, nil, starlark.Tuple{
		dir,
		starlark.MakeInt(64 * 1024 * 1024),
	}, []starlark.Tuple{
		{starlark.String("boot_code"), starlark.Bytes(make([]byte, 513))},
	})
	if err == nil {
		t.Fatal("oversized boot code was accepted")
	}
}

func TestFAT16BuilderHonorsBootFileOrderWithoutDirectoryLabel(t *testing.T) {
	dir := filesystemapi.New()
	dir.PutFile("/COMMAND.COM", filesystemapi.FileRecord{Data: []byte("command"), Size: 7})
	dir.PutFile("/CONFIG.SYS", filesystemapi.FileRecord{Data: []byte("config"), Size: 6})
	dir.PutFile("/IO.SYS", filesystemapi.FileRecord{Data: []byte("io"), Size: 2})
	dir.PutFile("/MSDOS.SYS", filesystemapi.FileRecord{Data: []byte("msdos"), Size: 5})
	label, _ := fat32VolumeLabel("MS-DOS")
	image, err := buildFAT16ImageWithOptions(dir, 32*1024*1024, nil, 63, label, []string{"/IO.SYS", "/MSDOS.SYS", "/COMMAND.COM"}, false)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newFATImage(image)
	if err != nil {
		t.Fatal(err)
	}
	root := make([]byte, 4*32)
	if _, err := image.ReadAt(root, volume.rootDirOffset); err != nil {
		t.Fatal(err)
	}
	if got := []string{fatShortName(root[0:11]), fatShortName(root[32:43]), fatShortName(root[64:75])}; got[0] != "IO.SYS" || got[1] != "MSDOS.SYS" || got[2] != "COMMAND.COM" {
		t.Fatalf("root entry order = %#v", got)
	}
	clusters := []uint16{
		binary.LittleEndian.Uint16(root[26:28]),
		binary.LittleEndian.Uint16(root[32+26 : 32+28]),
		binary.LittleEndian.Uint16(root[64+26 : 64+28]),
	}
	if clusters[0] != 2 || clusters[1] != 3 || clusters[2] != 4 {
		t.Fatalf("boot file clusters = %v", clusters)
	}
}

func TestFAT16BuilderAllocatesDirectoryTerminatorCluster(t *testing.T) {
	dir := filesystemapi.New()
	dir.Mkdir("/FULL")
	for index := 0; index < 30; index++ {
		name := fmt.Sprintf("/FULL/F%02d.BIN", index)
		dir.PutFile(name, filesystemapi.FileRecord{Data: []byte{byte(index)}, Size: 1})
	}
	label, _ := fat32VolumeLabel("DIRECTORY")
	image, err := buildFAT16Image(dir, 32*1024*1024, nil, 63, label)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newFATImage(image)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := volume.Get(starlark.String("/FULL/F29.BIN"))
	if err != nil || !found {
		t.Fatalf("last directory member: found=%t err=%v", found, err)
	}
	got, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{29}) {
		t.Fatalf("last directory member = %v, want [29]", got)
	}
}
