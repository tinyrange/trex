package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.starlark.net/starlark"
)

type identityOnlyPDBFile struct {
	*starfile.Bytes
	reads int
}

func (f *identityOnlyPDBFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= 1024 {
		return 0, fmt.Errorf("unexpected symbol-stream read")
	}
	f.reads++
	return f.Bytes.ReadAt(p, off)
}

func TestPDBIdentityDoesNotReadSymbols(t *testing.T) {
	data := make([]byte, 1536)
	binary.LittleEndian.PutUint32(data[8:], 4)
	copy(data[12:], []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8})
	binary.LittleEndian.PutUint32(data[512+8:], 1)
	f := &identityOnlyPDBFile{Bytes: &starfile.Bytes{Data: data}}
	msf := &pdbMSF{file: f, blockSize: 512, numBlocks: 3, version: 7, streamLimit: 1024,
		sizes: []uint32{0, 28, 0, 64, 512}, streams: [][]uint32{nil, {0}, nil, {1}, {2}}}
	p, dbi, err := msf.identity()
	if err != nil {
		t.Fatal(err)
	}
	if f.reads != 2 || len(p.symbols) != 0 || len(dbi) != 64 || p.age != 4 || p.dbiAge != 1 || p.guid != "12345678-9ABC-DEF0-0102-030405060708" {
		t.Fatalf("identity: %+v, reads=%d, DBI=%d", p, f.reads, len(dbi))
	}
	if err := p.validateImageAge(1); err != nil {
		t.Fatal(err)
	}
	if err := p.validateImageAge(4); err == nil {
		t.Fatal("accepted mismatched DBI age")
	}
	if _, err := msf.stream(4); err == nil {
		t.Fatal("read guard did not cover symbol stream")
	}
	msf.sizes[3] = 12
	if _, _, err := msf.identity(); err == nil {
		t.Fatal("accepted short DBI stream")
	}
}

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

func TestPDBImageAgeValidation(t *testing.T) {
	for _, tc := range []struct {
		name             string
		info, dbi, image uint32
		valid            bool
	}{
		{"exact", 1, 1, 1, true},
		{"post-link-update", 4, 1, 1, true},
		{"older-info", 1, 2, 2, false},
		{"different-symbol-records", 4, 3, 1, false},
		{"equal-info-wrong-dbi", 4, 3, 4, false},
		{"legacy-dbi", 4, 0, 1, true},
		{"legacy-older-info", 1, 0, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Minimal MSF7 with independent Info and DBI streams, an empty
			// public-symbol stream, and one section header.
			const blockSize = 512
			data := make([]byte, 6*blockSize)
			copy(data, pdbMSFMagic)
			binary.LittleEndian.PutUint32(data[32:], blockSize)
			binary.LittleEndian.PutUint32(data[40:], 6)
			binary.LittleEndian.PutUint32(data[44:], 40)
			binary.LittleEndian.PutUint32(data[52:], 1)
			binary.LittleEndian.PutUint32(data[blockSize:], 2)
			directory := data[2*blockSize:]
			for i, value := range []uint32{6, 0, 28, 0, 86, 0, 40, 3, 4, 5} {
				binary.LittleEndian.PutUint32(directory[i*4:], value)
			}
			binary.LittleEndian.PutUint32(data[3*blockSize+8:], tc.info)
			dbi := data[4*blockSize:]
			binary.LittleEndian.PutUint32(dbi[8:], tc.dbi)
			binary.LittleEndian.PutUint16(dbi[20:], 4)
			binary.LittleEndian.PutUint32(dbi[48:], 22)
			for i := 64; i < 86; i += 2 {
				binary.LittleEndian.PutUint16(dbi[i:], 0xffff)
			}
			binary.LittleEndian.PutUint16(dbi[74:], 5)
			parsed, err := parsePDB(&starfile.Bytes{Name: "age.pdb", Data: data}, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.age != tc.info || parsed.dbiAge != tc.dbi {
				t.Fatalf("parsed ages = %d/%d", parsed.age, parsed.dbiAge)
			}
			if err := parsed.validateImageAge(tc.image); (err == nil) != tc.valid {
				t.Fatalf("validateImageAge(%d) = %v, want valid=%v", tc.image, err, tc.valid)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(data)
			}))
			defer server.Close()
			args := starlark.Tuple{starlark.String(server.URL), starlark.String("age.pdb"), starlark.String("TEST1")}
			kwargs := []starlark.Tuple{
				{starlark.String("guid"), starlark.String("00000000-0000-0000-0000-000000000000")},
				{starlark.String("age"), starlark.MakeUint64(uint64(tc.image))},
			}
			if _, err := windowsSymbolServerBuiltin(nil, nil, args, kwargs); (err == nil) != tc.valid {
				t.Fatalf("symbol_server age validation = %v, want valid=%v", err, tc.valid)
			}
			kwargs[1][1] = starlark.MakeUint64(1<<32 + uint64(tc.image))
			if _, err := windowsSymbolServerBuiltin(nil, nil, args, kwargs); err == nil {
				t.Fatal("symbol_server accepted truncated 64-bit age")
			}
			kwargs[1][1] = starlark.MakeUint64(uint64(tc.image))
			kwargs[0][1] = starlark.String("11111111-0000-0000-0000-000000000000")
			if _, err := windowsSymbolServerBuiltin(nil, nil, args, kwargs); err == nil {
				t.Fatal("symbol_server accepted different GUID")
			}
		})
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
