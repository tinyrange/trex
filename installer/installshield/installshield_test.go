package installshield

import (
	"bytes"
	"compress/flate"
	"crypto/md5"
	"encoding/binary"
	"io"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func rawDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := flate.NewWriter(&output, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func installShieldV6Fixture(t *testing.T) (starfile.File, map[uint16]starfile.File, map[string][]starfile.File) {
	t.Helper()
	internal := []byte("compressed application payload")
	externalData := []byte("compiled installer script")
	compressed := rawDeflate(t, internal)
	volume := make([]byte, 84+2+len(compressed))
	binary.LittleEndian.PutUint32(volume[0:4], installShieldSignature)
	copy(volume[84:], []byte{byte(len(compressed)), byte(len(compressed) >> 8)})
	copy(volume[86:], compressed)

	header := make([]byte, 0xc00)
	binary.LittleEndian.PutUint32(header[0:4], installShieldSignature)
	binary.LittleEndian.PutUint32(header[4:8], 0x0100600c)
	binary.LittleEndian.PutUint32(header[12:16], 0x200)
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(header)-0x200))
	descriptor := 0x200
	table := 0x800
	binary.LittleEndian.PutUint32(header[descriptor+0x0c:], uint32(table-descriptor))
	binary.LittleEndian.PutUint32(header[descriptor+0x14:], 0x400)
	binary.LittleEndian.PutUint32(header[descriptor+0x18:], 0x400)
	binary.LittleEndian.PutUint32(header[descriptor+0x1c:], 1)
	binary.LittleEndian.PutUint32(header[descriptor+0x28:], 2)
	binary.LittleEndian.PutUint32(header[descriptor+0x2c:], 4)

	// One file group and one component connected through their hash lists.
	binary.LittleEndian.PutUint32(header[descriptor+0x3e:], 0x300)
	binary.LittleEndian.PutUint32(header[descriptor+0x15a:], 0x340)
	groupList := descriptor + 0x300
	binary.LittleEndian.PutUint32(header[groupList+4:], 0x320)
	groupDescriptor := descriptor + 0x320
	binary.LittleEndian.PutUint32(header[groupDescriptor:], 0x380)
	binary.LittleEndian.PutUint32(header[groupDescriptor+0x16:], 0)
	binary.LittleEndian.PutUint32(header[groupDescriptor+0x1a:], 1)
	binary.LittleEndian.PutUint32(header[groupDescriptor+0x3a:], 0x4c0)
	copy(header[descriptor+0x380:], "Program Files\x00")
	copy(header[descriptor+0x4c0:], "<TARGETDIR>\x00")

	componentList := descriptor + 0x340
	binary.LittleEndian.PutUint32(header[componentList+4:], 0x400)
	componentDescriptor := descriptor + 0x400
	binary.LittleEndian.PutUint32(header[componentDescriptor:], 0x390)
	copy(header[descriptor+0x390:], "<Data>\\Program Files\x00")
	countAt := componentDescriptor + 4 + 0x6b
	binary.LittleEndian.PutUint16(header[countAt:], 1)
	binary.LittleEndian.PutUint32(header[countAt+2:], 0x480)
	binary.LittleEndian.PutUint32(header[descriptor+0x480:], 0x380)

	// Directory/name strings are relative to the file-table base.
	binary.LittleEndian.PutUint32(header[table:], 0x300)
	copy(header[table+0x300:], "Bin\x00")
	copy(header[table+0x310:], "app.exe\x00")
	copy(header[table+0x320:], "setup.inx\x00")
	writeFile := func(index int, nameOffset uint32, flags uint16, expanded, packed uint64, dataOffset uint64, digest [16]byte) {
		record := header[table+4+index*0x57:]
		binary.LittleEndian.PutUint16(record[0:2], flags)
		binary.LittleEndian.PutUint64(record[2:10], expanded)
		binary.LittleEndian.PutUint64(record[10:18], packed)
		binary.LittleEndian.PutUint64(record[18:26], dataOffset)
		copy(record[0x1a:0x2a], digest[:])
		binary.LittleEndian.PutUint32(record[0x3a:0x3e], nameOffset)
		binary.LittleEndian.PutUint16(record[0x3e:0x40], 0)
		binary.LittleEndian.PutUint16(record[0x55:0x57], 1)
	}
	writeFile(0, 0x310, installShieldFileCompressed, uint64(len(internal)), uint64(len(compressed)+2), 84, md5.Sum(internal))
	writeFile(1, 0x320, 0, uint64(len(externalData)), uint64(len(externalData)), 0, md5.Sum(externalData))
	return &starfile.Bytes{Name: "data1.hdr", Data: header},
		map[uint16]starfile.File{1: &starfile.Bytes{Name: "data1.cab", Data: volume}},
		map[string][]starfile.File{"setup.inx": {&starfile.Bytes{Name: "setup.inx", Data: externalData}}}
}

func installShieldV5Fixture(t *testing.T) (starfile.File, map[uint16]starfile.File, map[string][]starfile.File) {
	t.Helper()
	internal := []byte("a compressed payload split across cabinet volumes")
	compressed := rawDeflate(t, internal)
	encoded := append([]byte{byte(len(compressed)), byte(len(compressed) >> 8)}, compressed...)
	splitAt := len(encoded) / 2
	volume := func(first, last uint32, firstPart, lastPart []byte) []byte {
		size := 60 + len(firstPart) + len(lastPart)
		data := make([]byte, size)
		binary.LittleEndian.PutUint32(data[0:4], installShieldSignature)
		binary.LittleEndian.PutUint32(data[20:24], 60)
		binary.LittleEndian.PutUint32(data[28:32], first)
		binary.LittleEndian.PutUint32(data[32:36], last)
		if len(firstPart) != 0 {
			binary.LittleEndian.PutUint32(data[36:40], 60)
			binary.LittleEndian.PutUint32(data[44:48], uint32(len(firstPart)))
			copy(data[60:], firstPart)
		}
		if len(lastPart) != 0 {
			offset := 60 + len(firstPart)
			binary.LittleEndian.PutUint32(data[48:52], uint32(offset))
			binary.LittleEndian.PutUint32(data[56:60], uint32(len(lastPart)))
			copy(data[offset:], lastPart)
		}
		return data
	}
	volumes := map[uint16]starfile.File{
		1: &starfile.Bytes{Name: "data1.cab", Data: volume(0, 0, nil, encoded[:splitAt])},
		2: &starfile.Bytes{Name: "data2.cab", Data: volume(0, 1, encoded[splitAt:], nil)},
	}

	header := make([]byte, 0xc00)
	binary.LittleEndian.PutUint32(header[0:4], installShieldSignature)
	binary.LittleEndian.PutUint32(header[4:8], 0x0100500c)
	binary.LittleEndian.PutUint32(header[12:16], 0x200)
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(header)-0x200))
	descriptor := 0x200
	table := 0x800
	binary.LittleEndian.PutUint32(header[descriptor+0x0c:], uint32(table-descriptor))
	binary.LittleEndian.PutUint32(header[descriptor+0x14:], 0x400)
	binary.LittleEndian.PutUint32(header[descriptor+0x18:], 0x400)
	binary.LittleEndian.PutUint32(header[descriptor+0x1c:], 1)
	binary.LittleEndian.PutUint32(header[descriptor+0x28:], 2)

	binary.LittleEndian.PutUint32(header[descriptor+0x3e:], 0x300)
	binary.LittleEndian.PutUint32(header[descriptor+0x15a:], 0x340)
	groupList := descriptor + 0x300
	binary.LittleEndian.PutUint32(header[groupList+4:], 0x320)
	groupDescriptor := descriptor + 0x320
	binary.LittleEndian.PutUint32(header[groupDescriptor:], 0x380)
	binary.LittleEndian.PutUint32(header[groupDescriptor+0x4c:], 0)
	binary.LittleEndian.PutUint32(header[groupDescriptor+0x50:], 1)
	copy(header[descriptor+0x380:], "Program Files\x00")
	componentList := descriptor + 0x340
	binary.LittleEndian.PutUint32(header[componentList+4:], 0x400)
	componentDescriptor := descriptor + 0x400
	binary.LittleEndian.PutUint32(header[componentDescriptor:], 0x390)
	copy(header[descriptor+0x390:], "Main Program\x00")
	countAt := componentDescriptor + 4 + 0x6c
	binary.LittleEndian.PutUint16(header[countAt:], 1)
	binary.LittleEndian.PutUint32(header[countAt+2:], 0x480)
	binary.LittleEndian.PutUint32(header[descriptor+0x480:], 0x380)

	binary.LittleEndian.PutUint32(header[table:], 0x300)
	copy(header[table+0x300:], "Dir\x00")
	copy(header[table+0x310:], "split.bin\x00")
	copy(header[table+0x320:], "same.bin\x00")
	writeFile := func(index int, recordOffset, nameOffset uint32, flags uint16, expanded, packed, dataOffset uint32) {
		binary.LittleEndian.PutUint32(header[table+4+index*4:], recordOffset)
		record := header[table+int(recordOffset):]
		binary.LittleEndian.PutUint32(record[0:4], nameOffset)
		binary.LittleEndian.PutUint16(record[4:6], 0)
		binary.LittleEndian.PutUint16(record[8:10], flags)
		binary.LittleEndian.PutUint32(record[10:14], expanded)
		binary.LittleEndian.PutUint32(record[14:18], packed)
		binary.LittleEndian.PutUint32(record[0x26:0x2a], dataOffset)
	}
	writeFile(0, 0x100, 0x310, installShieldFileCompressed, uint32(len(internal)), uint32(len(encoded)), 0xfeed0000)
	writeFile(1, 0x13a, 0x320, 0, 8, 8, 0)
	external := make(map[string][]starfile.File)
	addInstallShieldExternal(external, "/other/same.bin", &starfile.Bytes{Name: "wrong", Data: []byte("wrongone")})
	addInstallShieldExternal(external, "/Dir/same.bin", &starfile.Bytes{Name: "right", Data: []byte("external")})
	return &starfile.Bytes{Name: "data1.hdr", Data: header}, volumes, external
}

func TestInstallShieldV5ReadsSplitAndPathQualifiedExternalFiles(t *testing.T) {
	header, volumes, external := installShieldV5Fixture(t)
	archive, err := Open(header, volumes, external)
	if err != nil {
		t.Fatal(err)
	}
	if archive.version != 5 || len(archive.groups) != 1 || archive.groups[0].firstFile != 0 || archive.groups[0].lastFile != 1 {
		t.Fatalf("unexpected metadata: version=%d groups=%+v", archive.version, archive.groups)
	}
	if got := archive.components[0].fileGroups; len(got) != 1 || got[0] != "Program Files" {
		t.Fatalf("component groups = %v", got)
	}
	for name, want := range map[string]string{
		"/Program Files/Dir/split.bin": "a compressed payload split across cabinet volumes",
		"/Program Files/Dir/same.bin":  "external",
	} {
		value, found, err := archive.Get(starlark.String(name))
		if err != nil || !found {
			t.Fatalf("lookup %q = %v, %v", name, found, err)
		}
		got, err := io.ReadAll(io.NewSectionReader(value.(starfile.File), 0, value.(starfile.File).Size()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%q = %q, want %q", name, got, want)
		}
	}
}

func TestInstallShieldV6ParsesMetadataAndReadsFiles(t *testing.T) {
	header, volumes, external := installShieldV6Fixture(t)
	archive, err := Open(header, volumes, external)
	if err != nil {
		t.Fatal(err)
	}
	if archive.version != 6 || len(archive.files) != 2 || len(archive.groups) != 1 || len(archive.components) != 1 {
		t.Fatalf("metadata = version %d, %d files, %d groups, %d components", archive.version, len(archive.files), len(archive.groups), len(archive.components))
	}
	if got := archive.files[0].components; len(got) != 1 || got[0] != "<Data>/Program Files" {
		t.Fatalf("components = %v", got)
	}
	if got, want := archive.groups[0].target, "<TARGETDIR>"; got != want {
		t.Fatalf("group target = %q, want %q", got, want)
	}
	for name, want := range map[string]string{
		"/program files/bin/APP.EXE": "compressed application payload",
		"setup.inx":                  "compiled installer script",
	} {
		value, found, err := archive.Get(starlark.String(name))
		if err != nil || !found {
			t.Fatalf("lookup %q = %v, %v", name, found, err)
		}
		got, err := io.ReadAll(io.NewSectionReader(value.(starfile.File), 0, value.(starfile.File).Size()))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%q = %q, want %q", name, got, want)
		}
	}
}

func TestInstallShieldRejectsTruncatedDescriptor(t *testing.T) {
	header := make([]byte, 20)
	binary.LittleEndian.PutUint32(header[:4], installShieldSignature)
	binary.LittleEndian.PutUint32(header[4:8], 0x0100600c)
	binary.LittleEndian.PutUint32(header[12:16], 20)
	binary.LittleEndian.PutUint32(header[16:20], 1)
	if _, err := Open(&starfile.Bytes{Name: "bad.hdr", Data: header}, nil, nil); err == nil {
		t.Fatal("truncated descriptor was accepted")
	}
}

func TestInstallShieldParsesShellObjectDatabase(t *testing.T) {
	const descriptor = uint64(0x20)
	data := make([]byte, 0x300)
	putString := func(relative uint32, value string) {
		copy(data[descriptor+uint64(relative):], value+"\x00")
	}
	putString(0x100, "Example Tools")
	putString(0x120, "<SHELL_OBJECT_FOLDER>")
	putString(0x140, "Example")
	putString(0x150, "PRODUCT_NAME_NV")
	putString(0x170, `<TARGETDIR>\example.exe`)
	putString(0x190, "--start")
	putString(0x1a0, "<TARGETDIR>")
	putString(0x1b0, "")

	folder := descriptor + 0x10
	binary.LittleEndian.PutUint32(data[folder:], 0x100)
	binary.LittleEndian.PutUint32(data[folder+4:], 0x120)
	binary.LittleEndian.PutUint16(data[folder+14:], 1)
	binary.LittleEndian.PutUint32(data[folder+16:], 0x60)
	binary.LittleEndian.PutUint32(data[descriptor+0x60:], 0x70)
	record := descriptor + 0x70
	binary.LittleEndian.PutUint32(data[record:], 0x140)
	binary.LittleEndian.PutUint32(data[record+4:], 0x150)
	binary.LittleEndian.PutUint16(data[record+8:], 0)
	binary.LittleEndian.PutUint32(data[record+10:], 0x170)
	binary.LittleEndian.PutUint32(data[record+15:], 0x190)
	binary.LittleEndian.PutUint32(data[record+19:], 0x1a0)
	binary.LittleEndian.PutUint32(data[record+23:], 0x1b0)
	binary.LittleEndian.PutUint32(data[record+27:], 2)
	binary.LittleEndian.PutUint32(data[record+31:], 0x1b0)
	binary.LittleEndian.PutUint32(data[record+39:], ^uint32(0))
	binary.LittleEndian.PutUint32(data[record+43:], 1)

	readString := func(offset uint64) (string, error) {
		if offset >= uint64(len(data)) {
			return "", io.ErrUnexpectedEOF
		}
		end := bytes.IndexByte(data[offset:], 0)
		if end < 0 {
			return "", io.ErrUnexpectedEOF
		}
		return string(data[offset : offset+uint64(end)]), nil
	}
	shortcuts, err := parseInstallShieldShortcuts(data, descriptor, 6, readString)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(shortcuts), 1; got != want {
		t.Fatalf("shortcuts = %d, want %d", got, want)
	}
	shortcut := shortcuts[0]
	if shortcut.folder != "Example Tools" || shortcut.folderRoot != "<SHELL_OBJECT_FOLDER>" || shortcut.target != `<TARGETDIR>\example.exe` || shortcut.arguments != "--start" || shortcut.iconIndex != 2 {
		t.Fatalf("shortcut = %+v", shortcut)
	}
}

func TestInstallShieldParsesSpecialFolderShellObjects(t *testing.T) {
	const descriptor = uint64(0x20)
	data := make([]byte, 0x700)
	putString := func(relative uint32, value string) {
		copy(data[descriptor+uint64(relative):], value+"\x00")
	}
	putString(0x400, "Desktop Icon")
	putString(0x420, "UltraPlayer")
	putString(0x440, `<TARGETDIR>\UPlayer.exe`)
	putString(0x470, "Programs Icon")

	// The descriptor points at four relative special-folder descriptor slots.
	binary.LittleEndian.PutUint32(data[descriptor+0x27e:], 0x2a0)
	specialTable := descriptor + 0x2a0
	binary.LittleEndian.PutUint32(data[specialTable:], 0x2c0)
	binary.LittleEndian.PutUint32(data[specialTable+8:], 0x2e0)

	putFolder := func(relative, table, record uint32) {
		folder := descriptor + uint64(relative)
		binary.LittleEndian.PutUint16(data[folder+14:], 1)
		binary.LittleEndian.PutUint32(data[folder+16:], table)
		binary.LittleEndian.PutUint32(data[descriptor+uint64(table):], record)
	}
	putFolder(0x2c0, 0x320, 0x340)
	putFolder(0x2e0, 0x324, 0x380)
	putRecord := func(relative, name uint32) {
		record := descriptor + uint64(relative)
		binary.LittleEndian.PutUint32(data[record:], name)
		binary.LittleEndian.PutUint32(data[record+4:], 0x420)
		binary.LittleEndian.PutUint32(data[record+10:], 0x440)
		binary.LittleEndian.PutUint32(data[record+19:], 0x440)
		binary.LittleEndian.PutUint32(data[record+39:], ^uint32(0))
		binary.LittleEndian.PutUint32(data[record+43:], 1)
	}
	putRecord(0x340, 0x400)
	putRecord(0x380, 0x470)

	readString := func(offset uint64) (string, error) {
		if offset >= uint64(len(data)) {
			return "", io.ErrUnexpectedEOF
		}
		end := bytes.IndexByte(data[offset:], 0)
		if end < 0 {
			return "", io.ErrUnexpectedEOF
		}
		return string(data[offset : offset+uint64(end)]), nil
	}
	shortcuts, err := parseInstallShieldShortcuts(data, descriptor, 6, readString)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(shortcuts), 2; got != want {
		t.Fatalf("shortcuts = %d, want %d", got, want)
	}
	if got, want := shortcuts[0].folderRoot, "<DESKTOP_FOLDER>"; got != want {
		t.Fatalf("desktop root = %q, want %q", got, want)
	}
	if got, want := shortcuts[1].folderRoot, "<SHELL_OBJECT_FOLDER>"; got != want {
		t.Fatalf("programs root = %q, want %q", got, want)
	}
}

func TestInstallShieldV5FindsRootShellObjectDatabaseStructurally(t *testing.T) {
	const descriptor = uint64(0x20)
	data := make([]byte, 0x280)
	putString := func(relative uint32, value string) {
		copy(data[descriptor+uint64(relative):], value+"\x00")
	}
	putString(0x100, "Example")
	putString(0x120, "Example Application")
	putString(0x150, `<TARGETDIR>\example.exe`)

	folder := descriptor + 0x40
	binary.LittleEndian.PutUint16(data[folder+14:], 1)
	binary.LittleEndian.PutUint32(data[folder+16:], 0x60)
	binary.LittleEndian.PutUint32(data[descriptor+0x60:], 0x70)
	record := descriptor + 0x70
	binary.LittleEndian.PutUint32(data[record:], 0x100)
	binary.LittleEndian.PutUint32(data[record+4:], 0x120)
	binary.LittleEndian.PutUint32(data[record+10:], 0x150)

	readString := func(offset uint64) (string, error) {
		if offset >= uint64(len(data)) {
			return "", io.ErrUnexpectedEOF
		}
		end := bytes.IndexByte(data[offset:], 0)
		if end < 0 {
			return "", io.ErrUnexpectedEOF
		}
		return string(data[offset : offset+uint64(end)]), nil
	}
	shortcuts, err := parseInstallShieldShortcuts(data, descriptor, 5, readString)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(shortcuts), 1; got != want {
		t.Fatalf("shortcuts = %d, want %d", got, want)
	}
	if shortcut := shortcuts[0]; shortcut.folder != "" || shortcut.display != "Example Application" || shortcut.target != `<TARGETDIR>\example.exe` {
		t.Fatalf("shortcut = %+v", shortcut)
	}
}
