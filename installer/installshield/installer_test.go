package installshield

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"

	"go.starlark.net/starlark"
)

func uncompressedTestCabinet(name string, payload []byte) []byte {
	const (
		headerSize = 36
		folderSize = 8
		fileSize   = 16
		blockSize  = 8
	)
	fileOffset := headerSize + folderSize
	dataOffset := fileOffset + fileSize + len(name) + 1
	totalSize := dataOffset + blockSize + len(payload)
	data := make([]byte, totalSize)
	copy(data[0:4], "MSCF")
	binary.LittleEndian.PutUint32(data[8:12], uint32(totalSize))
	binary.LittleEndian.PutUint32(data[16:20], uint32(fileOffset))
	data[24] = 3
	data[25] = 1
	binary.LittleEndian.PutUint16(data[26:28], 1)
	binary.LittleEndian.PutUint16(data[28:30], 1)
	binary.LittleEndian.PutUint32(data[headerSize:headerSize+4], uint32(dataOffset))
	binary.LittleEndian.PutUint16(data[headerSize+4:headerSize+6], 1)
	binary.LittleEndian.PutUint32(data[fileOffset:fileOffset+4], uint32(len(payload)))
	copy(data[fileOffset+fileSize:], name)
	binary.LittleEndian.PutUint16(data[dataOffset+4:dataOffset+6], uint16(len(payload)))
	binary.LittleEndian.PutUint16(data[dataOffset+6:dataOffset+8], uint16(len(payload)))
	copy(data[dataOffset+blockSize:], payload)
	return data
}

func TestInstallerFindsAndExtractsEmbeddedCabinet(t *testing.T) {
	payload := []byte("PowerToys payload")
	cabinet := uncompressedTestCabinet("tweakui.exe", payload)
	prefix := append([]byte("MZ"), bytes.Repeat([]byte{0xcc}, int(installerScanWindow)-5)...)
	prefix = append(prefix, []byte("MSCF invalid decoy")...)
	offset := len(prefix)
	data := append(prefix, cabinet...)
	source := &starfile.Bytes{Name: "setup.exe", Data: data}
	archive, err := OpenInstaller(source, int64(len(data)), false, bytecache.New(bytecache.DefaultBytes), 1)
	if err != nil {
		t.Fatal(err)
	}
	if archive.format != "embedded_cab" || archive.offset != int64(offset) || archive.size != int64(len(cabinet)) {
		t.Fatalf("installer metadata = %s, %d, %d", archive.format, archive.offset, archive.size)
	}
	value, found, err := archive.Get(starlark.String("/TWEAKUI.EXE"))
	if err != nil || !found {
		t.Fatalf("payload lookup = %v, %v", found, err)
	}
	got, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestInstallerRejectsUnsupportedAndBoundedInputs(t *testing.T) {
	cabinet := uncompressedTestCabinet("file.txt", []byte("data"))
	plain := &starfile.Bytes{Name: "plain.cab", Data: cabinet}
	if _, err := OpenInstaller(plain, int64(len(cabinet)), false, bytecache.New(1024), 1); err == nil || !strings.Contains(err.Error(), "not a DOS or PE executable") {
		t.Fatalf("plain CAB error = %v", err)
	}

	prefix := append([]byte("MZ"), bytes.Repeat([]byte{0}, 100)...)
	installer := &starfile.Bytes{Name: "setup.exe", Data: append(prefix, cabinet...)}
	if _, err := OpenInstaller(installer, 64, false, bytecache.New(1024), 1); err == nil || !strings.Contains(err.Error(), "first 64 bytes") {
		t.Fatalf("bounded scan error = %v", err)
	}
}

func TestInstallerStarlarkSurface(t *testing.T) {
	cabinet := uncompressedTestCabinet("readme.txt", []byte("hello"))
	source := &starfile.Bytes{Name: "setup.exe", Data: append([]byte("MZ launcher data"), cabinet...)}
	thread := &starlark.Thread{Name: "installer_test.star"}
	value, err := InstallerBuiltin(thread, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	archive := value.(*Installer)
	format, err := archive.Attr("format")
	if err != nil || string(format.(starlark.String)) != "embedded_cab" {
		t.Fatalf("format = %v, %v", format, err)
	}
	files, err := archive.Attr("files")
	if err != nil || files.(*starlark.List).Len() != 1 {
		t.Fatalf("files = %v, %v", files, err)
	}
}

func TestInstallerProbeReportsSupportedAndUnknownInputs(t *testing.T) {
	cabinet := uncompressedTestCabinet("readme.txt", []byte("hello"))
	supported := &starfile.Bytes{Name: "setup.exe", Data: append([]byte("MZ launcher data"), cabinet...)}
	unknown := &starfile.Bytes{Name: "unknown.exe", Data: append([]byte("MZ no known payload"), bytes.Repeat([]byte{0}, 64)...)}
	thread := &starlark.Thread{Name: "installer_probe_test.star"}

	value, err := ProbeBuiltin(thread, nil, starlark.Tuple{supported}, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe := value.(*starlark.Dict)
	got, found, err := probe.Get(starlark.String("supported"))
	if err != nil || !found || got != starlark.True {
		t.Fatalf("supported = %v, %v, %v", got, found, err)
	}
	got, found, err = probe.Get(starlark.String("format"))
	if err != nil || !found || got != starlark.String("embedded_cab") {
		t.Fatalf("format = %v, %v, %v", got, found, err)
	}

	value, err = ProbeBuiltin(thread, nil, starlark.Tuple{unknown}, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe = value.(*starlark.Dict)
	got, found, err = probe.Get(starlark.String("supported"))
	if err != nil || !found || got != starlark.False {
		t.Fatalf("unknown supported = %v, %v, %v", got, found, err)
	}
	got, found, err = probe.Get(starlark.String("error"))
	if err != nil || !found || !strings.Contains(string(got.(starlark.String)), "no supported payload") {
		t.Fatalf("unknown error = %v, %v, %v", got, found, err)
	}
}

func TestInstallerProbeRecognizesUnsupportedInstallShieldVersion(t *testing.T) {
	header := make([]byte, 20)
	binary.LittleEndian.PutUint32(header[0:4], installShieldSignature)
	binary.LittleEndian.PutUint32(header[4:8], 0x01004201)
	cabinet := uncompressedTestCabinet("data1.hdr", header)
	source := &starfile.Bytes{Name: "setup.exe", Data: append([]byte("MZ launcher data"), cabinet...)}
	thread := &starlark.Thread{Name: "installer_probe_version_test.star"}

	value, err := ProbeBuiltin(thread, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe := value.(*starlark.Dict)
	for name, want := range map[string]starlark.Value{
		"supported":  starlark.False,
		"recognized": starlark.True,
		"format":     starlark.String("installshield4"),
	} {
		got, found, err := probe.Get(starlark.String(name))
		if err != nil || !found || got != want {
			t.Fatalf("%s = %v, %v, %v; want %v", name, got, found, err, want)
		}
	}
}
