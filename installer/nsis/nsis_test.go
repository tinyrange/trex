package nsis

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// These synthetic containers are authored here; no upstream implementation or
// executable fixture is redistributed. The metadata represents a conditional
// File instruction, an ignored CreateDirectory, a SetOutPath, and two more File
// instructions referencing the same payload (including a duplicate filename).
func metadataFixture() []byte {
	b := make([]byte, 68)
	put := binary.LittleEndian.PutUint32
	// All empty pre-code blocks start at 68. Instructions end at 236.
	for i := 0; i < 3; i++ {
		put(b[4+i*8:], 68)
	}
	put(b[24:], 6)
	instructions := [][7]uint32{
		{12, 0, 4, 6},
		{20, 0, 1, 0, 0x12345678, 0x9abcdef0},
		{11, 11, 0}, // not SetOutPath: must not change directory hint
		{11, 23, 1},
		{20, 1, 31, 7},
		{20, 1, 1, 7},
	}
	for _, instr := range instructions {
		for _, v := range instr {
			b = binary.LittleEndian.AppendUint32(b, v)
		}
	}
	put(b[28:], uint32(len(b)))
	// offsets: 1=first.txt, 11=ignored-dir, 23=$INSTDIR\bin, 31=second.txt
	b = append(b, []byte("\x00first.txt\x00ignored-dir\x00\xfd\x95\x80\\bin\x00second.txt\x00")...)
	for i := 4; i < 7; i++ {
		put(b[4+i*8:], uint32(len(b)))
	}
	return b
}

func fixture(t testing.TB, metadata []byte, compressed bool, stub int) []byte {
	t.Helper()
	packed := bytes.Clone(metadata)
	var bit uint32
	if compressed {
		var dst bytes.Buffer
		w, err := flate.NewWriter(&dst, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(metadata); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		// Go emits a final empty stored block with NLEN. NSIS omits NLEN.
		encoded := dst.Bytes()
		if !bytes.HasSuffix(encoded, []byte{0, 0, 255, 255}) {
			t.Fatal("unexpected encoder trailer")
		}
		packed = encoded[:len(encoded)-2]
		bit = 0x80000000
	}
	b := make([]byte, stub+28)
	if stub > 0 {
		copy(b, "MZ")
	}
	copy(b[stub+4:], []byte{0xef, 0xbe, 0xad, 0xde, 'N', 'u', 'l', 'l', 's', 'o', 'f', 't', 'I', 'n', 's', 't'})
	binary.LittleEndian.PutUint32(b[stub+20:], uint32(len(metadata)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(packed))|bit)
	b = append(b, packed...)
	b = binary.LittleEndian.AppendUint32(b, 3)
	b = append(b, 'a', 'b', 'c')
	// Listing must not decompress this deliberately invalid compressed payload.
	b = binary.LittleEndian.AppendUint32(b, 0x80000002)
	b = append(b, 0xff, 0xff)
	b = append(b, 0, 0, 0, 0) // unverified CRC
	binary.LittleEndian.PutUint32(b[stub+24:], uint32(len(b)-stub))
	return b
}

type guardedSource struct {
	storage.Reader
	forbidden [][2]int64
}

func (g guardedSource) ReadAt(p []byte, off int64) (int, error) {
	for _, r := range g.forbidden {
		if off < r[1] && off+int64(len(p)) > r[0] {
			return 0, errors.New("unexpected member-content read")
		}
	}
	return g.Reader.ReadAt(p, off)
}

func TestListMetadataOnly(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		name := "stored"
		if compressed {
			name = "deflate"
		}
		t.Run(name, func(t *testing.T) {
			b := fixture(t, metadataFixture(), compressed, 1024)
			// Authenticode data outside length_of_all_following_data is not payload.
			b = append(b, []byte("signature trailer")...)
			dataOffset := int64(1024+32) + int64(binary.LittleEndian.Uint32(b[1052:])&0x7fffffff)
			source := guardedSource{Reader: bytes.NewReader(b), forbidden: [][2]int64{
				{dataOffset + 4, dataOffset + 7}, {dataOffset + 11, dataOffset + 13},
			}}
			got, err := List(source, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got.HeaderOffset != 1024 || got.DataOffset != dataOffset || got.HeaderSize != int64(len(metadataFixture())) || got.Instructions != 6 || got.HeaderCompression != name {
				t.Fatalf("unexpected header: %+v", got)
			}
			if len(got.Entries) != 3 {
				t.Fatalf("entries: %+v", got.Entries)
			}
			a, second, c := got.Entries[0], got.Entries[1], got.Entries[2]
			if a.Name != "first.txt" || a.Instruction != 1 || a.DirectoryInstruction != -1 || a.OutputDirectory != "$OUTDIR" || a.Compressed || a.PackedSize != 3 || a.FileTime != 0x9abcdef012345678 {
				t.Fatalf("first: %+v", a)
			}
			if second.Name != "second.txt" || second.OutputDirectory != "$INSTDIR\\bin" || second.DirectoryInstruction != 3 || second.Offset != dataOffset+7 || !second.Compressed || second.PackedSize != 2 {
				t.Fatalf("second: %+v", second)
			}
			if c.Name != a.Name || c.Offset != second.Offset || c.Instruction != 5 {
				t.Fatalf("duplicate lost: %+v", c)
			}
		})
	}
}

func TestLimitsAndMalformedContainers(t *testing.T) {
	good := fixture(t, metadataFixture(), false, 512)
	mutate := func(at int, word uint32) []byte {
		b := bytes.Clone(good)
		binary.LittleEndian.PutUint32(b[at:], word)
		return b
	}
	cases := []struct {
		name    string
		data    []byte
		options Options
		want    error
	}{
		{"short", []byte("MZ"), Options{}, ErrNoMatch},
		{"no signature", make([]byte, 512), Options{}, ErrNoMatch},
		{"scan limit", good, Options{MaxScanBytes: 512}, ErrLimit},
		{"negative limit", good, Options{MaxMetadataBytes: -1}, nil},
		{"metadata limit", good, Options{MaxMetadataBytes: 68}, ErrLimit},
		{"instruction limit", good, Options{MaxInstructions: 5}, ErrLimit},
		{"flags", mutate(512, 0x100), Options{}, ErrUnsupported},
		{"container bounds", mutate(536, 0xffffffff), Options{}, nil},
		{"short header", mutate(532, 10), Options{}, nil},
		{"bad packed length", mutate(540, 0x8000ffff), Options{}, ErrUnsupported},
		{"bad stored length", mutate(540, 3), Options{}, ErrUnsupported},
		{"instruction count", mutate(544+24, 0xffffffff), Options{}, ErrLimit},
		{"code bounds", mutate(544+20, 0xffffff), Options{}, nil},
		{"string bounds", mutate(544+28, 0xffffff), Options{}, nil},
		{"language bounds", mutate(544+36, 0xffffff), Options{}, nil},
		{"name offset", mutate(544+68+28+8, 0xffffff), Options{}, nil},
		{"payload offset", mutate(544+68+28+12, 0xffffffff), Options{}, nil},
		{"payload length", mutate(544+len(metadataFixture()), 0x7fffffff), Options{}, nil},
		{"truncated", good[:len(good)-1], Options{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := List(bytes.NewReader(tc.data), tc.options)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
	// A caller's large instruction limit must not wrap down to a uint32.
	if uint64(^uint(0)>>1) > 1<<32 {
		n := uint64(1) << 32
		if _, err := List(bytes.NewReader(good), Options{MaxInstructions: int(n)}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBadMetadataCompression(t *testing.T) {
	b := fixture(t, metadataFixture(), true, 0)
	for _, size := range []uint32{68, uint32(len(metadataFixture()) + 1)} {
		bad := bytes.Clone(b)
		binary.LittleEndian.PutUint32(bad[20:], size)
		if _, err := List(bytes.NewReader(bad), Options{}); err == nil {
			t.Fatal("accepted wrong expanded length")
		}
	}
	bad := bytes.Clone(b)
	bad[32] = 7 // reserved DEFLATE block type
	if _, err := List(bytes.NewReader(bad), Options{}); err == nil {
		t.Fatal("accepted corrupt compressed metadata")
	}
}

func TestStringExpressions(t *testing.T) {
	cases := []struct{ encoded, want string }{
		{"plain.txt", "plain.txt"},
		{"\xfd\x95\x80\\bin", "$INSTDIR\\bin"},
		{"\xfd\x9b\x80", "${VAR:27}"}, // version-dependent internal variables are not guessed
		{"\xfe\xa6\xaa", "${SHELL:a6,aa}"},
		{"\xff\x85\x80", "${LANG:5}"},
		{"cost$5\xfc\xff", "cost$$5\xff"},
	}
	for _, tc := range cases {
		got, raw, err := decodeString([]byte("\x00"+tc.encoded+"\x00"), 1)
		if err != nil || got != tc.want || string(raw) != tc.encoded {
			t.Fatalf("%q: got %q raw %x err %v", tc.encoded, got, raw, err)
		}
	}
	got, _, err := decodeString(nil, -3)
	if err != nil || got != "${LANG:2}" {
		t.Fatalf("language reference %q %v", got, err)
	}
	for _, s := range []string{"unterminated", "\xfd\x80\x00", "\xfc\x00", "\x01x\x00", strings.Repeat("x", 65537) + "\x00"} {
		if _, _, err := decodeString([]byte(s), 0); err == nil {
			t.Fatalf("accepted %q", s[:min(len(s), 20)])
		}
	}
}

func TestListingBuiltin(t *testing.T) {
	f := &starfile.Bytes{Name: "setup.exe", Data: fixture(t, metadataFixture(), false, 0)}
	value, err := ListBuiltin(nil, nil, starlark.Tuple{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := value.(starlark.HasAttrs).Attr("entries")
	if err != nil || entries.(*starlark.List).Len() != 3 {
		t.Fatalf("entries %v: %v", entries, err)
	}
	first := entries.(*starlark.List).Index(0).(starlark.HasAttrs)
	raw, err := first.Attr("raw_name")
	if err != nil || raw != starlark.Bytes("first.txt") {
		t.Fatalf("raw name: %v, %v", raw, err)
	}
	if _, err := ListBuiltin(nil, nil, starlark.Tuple{starlark.String("not a file")}, nil); err == nil {
		t.Fatal("accepted non-file")
	}
}

func TestShortRead(t *testing.T) {
	b := fixture(t, metadataFixture(), false, 0)
	source := guardedSource{Reader: bytes.NewReader(b), forbidden: [][2]int64{{32, 33}}}
	if _, err := List(source, Options{}); err == nil {
		t.Fatal("ignored metadata read failure")
	}
	if err := readAt(bytes.NewReader([]byte{1}), make([]byte, 2), 0); !errors.Is(err, io.EOF) {
		t.Fatalf("short read: %v", err)
	}
}

func FuzzList(f *testing.F) {
	f.Add(fixture(f, metadataFixture(), false, 0))
	f.Add(fixture(f, metadataFixture(), true, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = List(bytes.NewReader(data), Options{MaxScanBytes: 4096, MaxMetadataBytes: 8192, MaxInstructions: 256})
	})
}
