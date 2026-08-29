package windows

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.starlark.net/starlark"
)

func TestPDBOMapAndSectionSelection(t *testing.T) {
	omap := make([]byte, 24)
	binary.LittleEndian.PutUint32(omap[0:4], 0x1000)
	binary.LittleEndian.PutUint32(omap[4:8], 0x2000)
	binary.LittleEndian.PutUint32(omap[8:12], 0x1100)
	binary.LittleEndian.PutUint32(omap[12:16], 0)
	binary.LittleEndian.PutUint32(omap[16:20], 0x1200)
	binary.LittleEndian.PutUint32(omap[20:24], 0x4000)
	symbols := []pdbSymbol{{name: "mapped", rva: 0x1010}, {name: "discarded", rva: 0x1110}, {name: "later", rva: 0x1204}}
	got := applyPDBOMap(symbols, omap)
	if len(got) != 2 || got[0].rva != 0x2010 || got[1].rva != 0x4004 {
		t.Fatalf("OMAP result = %#v", got)
	}
	dbi := make([]byte, 64+22)
	binary.LittleEndian.PutUint32(dbi[48:52], 22)
	binary.LittleEndian.PutUint16(dbi[64+5*2:], 5)
	binary.LittleEndian.PutUint16(dbi[64+10*2:], 10)
	if stream, err := pdbSectionHeaderStream(dbi, true); err != nil || stream != 10 {
		t.Fatalf("original section stream = %d, %v", stream, err)
	}
}

func TestPDBGUIDFormatting(t *testing.T) {
	data := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8}
	if got, want := formatPDBGUID(data), "12345678-9ABC-DEF0-0102-030405060708"; got != want {
		t.Fatalf("GUID = %q, want %q", got, want)
	}
}

func TestPDBMSF2DirectoryAndPascalPublicSymbol(t *testing.T) {
	const blockSize = 512
	data := make([]byte, 4*blockSize)
	copy(data, pdbMSF20Magic)
	binary.LittleEndian.PutUint32(data[44:48], blockSize)
	binary.LittleEndian.PutUint16(data[48:50], 1)
	binary.LittleEndian.PutUint16(data[50:52], 4)
	// Two descriptors plus one 16-bit stream block number.
	binary.LittleEndian.PutUint32(data[52:56], 22)
	binary.LittleEndian.PutUint16(data[60:62], 3)
	directory := data[3*blockSize:]
	binary.LittleEndian.PutUint16(directory[0:2], 2)
	binary.LittleEndian.PutUint32(directory[4:8], 0)
	binary.LittleEndian.PutUint32(directory[12:16], 4)
	binary.LittleEndian.PutUint16(directory[20:22], 2)
	copy(data[2*blockSize:], "test")
	msf, err := parsePDBMSF(&starfile.Bytes{Name: "old.pdb", Data: data}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := msf.stream(1)
	if err != nil || !bytes.Equal(stream, []byte("test")) || msf.version != 2 {
		t.Fatalf("MSF2 stream = %q, version = %d, err = %v", stream, msf.version, err)
	}

	name := []byte("symbol")
	record := make([]byte, 15+len(name))
	binary.LittleEndian.PutUint16(record[0:2], uint16(len(record)-2))
	binary.LittleEndian.PutUint16(record[2:4], 0x1009)
	binary.LittleEndian.PutUint32(record[8:12], 0x24)
	binary.LittleEndian.PutUint16(record[12:14], 1)
	record[14] = byte(len(name))
	copy(record[15:], name)
	symbols := appendPDBSymbols(nil, record, []uint32{0x1000})
	if len(symbols) != 1 || symbols[0].name != "symbol" || symbols[0].rva != 0x1024 {
		t.Fatalf("old CodeView symbols = %#v", symbols)
	}
}

func TestSymbolServerUsesExplicitURLAndBoundsResponse(t *testing.T) {
	requestPath := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestPath <- request.URL.Path
		_, _ = writer.Write([]byte("pdb-data"))
	}))
	defer server.Close()
	value, err := windowsSymbolServerBuiltin(nil, nil, starlark.Tuple{starlark.String(server.URL), starlark.String("kernel.pdb"), starlark.String("ABC1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if value.(starfile.File).Size() != 8 {
		t.Fatalf("fetched size = %d", value.(starfile.File).Size())
	}
	if path := <-requestPath; path != "/kernel.pdb/ABC1/kernel.pdb" {
		t.Fatalf("request path = %q", path)
	}
	_, err = windowsSymbolServerBuiltin(nil, nil, starlark.Tuple{starlark.String(server.URL), starlark.String("kernel.pdb"), starlark.String("ABC1")}, []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(4)}})
	if err == nil {
		t.Fatal("oversized symbol response succeeded")
	}
}
