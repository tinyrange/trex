package star

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"go.starlark.net/starlark"
)

type observedBinaryFile struct {
	*immutableBytesFile
	reads [][2]int64
}

func (f *observedBinaryFile) ReadAt(data []byte, offset int64) (int, error) {
	f.reads = append(f.reads, [2]int64{offset, int64(len(data))})
	return f.immutableBytesFile.ReadAt(data, offset)
}

func TestBinaryViewCursorBuilderAndLayout(t *testing.T) {
	source := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	file := &immutableBytesFile{name: "test", data: source}
	viewValue, err := binaryViewBuiltin(nil, nil, starlark.Tuple{file}, []starlark.Tuple{
		{starlark.String("offset"), starlark.MakeInt(1)},
		{starlark.String("size"), starlark.MakeInt(6)},
	})
	if err != nil {
		t.Fatal(err)
	}
	view := viewValue.(*binaryByteView)
	if view.base != file || view.off != 1 || view.size != 6 {
		t.Fatalf("view = %#v, want zero-copy range over source", view)
	}
	sliced, ok := view.Slice(1, 4, 1).(*binaryByteView)
	if !ok || sliced.base != file || sliced.off != 2 || sliced.size != 3 {
		t.Fatalf("slice = %#v, want zero-copy nested range", sliced)
	}
	if got := sliced.Slice(2, -1, -1); got != starlark.Bytes("\x05\x04\x03") {
		t.Fatalf("strided slice = %v, want 050403", got)
	}

	cursorValue, err := binaryCursorBuiltin(nil, nil, starlark.Tuple{view}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := cursorValue.(*binaryCursor)
	got, err := cursor.readInteger("u16le", 2, binary.LittleEndian, false)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := got.(starlark.Int).Uint64(); !ok || value != 0x0302 {
		t.Fatalf("u16le = %v", got)
	}

	builderValue, err := binaryBuilderBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("limit"), starlark.MakeInt(8)}})
	if err != nil {
		t.Fatal(err)
	}
	builder := builderValue.(*binaryBuilder)
	if err := builder.appendData("test", []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if err := builder.appendData("test", []byte{5, 6, 7, 8, 9}); err == nil {
		t.Fatal("builder accepted data beyond its limit")
	}

	layout, err := compileBinaryLayout("<H2sI")
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"kind", "tag", "value"} {
		layout.fields[i].name = name
	}
	recordValue, err := layout.decodeBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\x34\x12ok\x78\x56\x34\x12")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	record := recordValue.(*binaryRecord)
	if got, _ := record.Attr("kind"); got.String() != "4660" {
		t.Fatalf("kind = %v", got)
	}
	if got, _ := record.Attr("tag"); got != starlark.Bytes("ok") {
		t.Fatalf("tag = %v", got)
	}
}

func TestBinaryScalarAPIs(t *testing.T) {
	module := Builtins()
	thread := &starlark.Thread{Name: "binary scalar test"}
	tests := []struct {
		name    string
		value   starlark.Value
		encoded starlark.Bytes
		decoded string
	}{
		{name: "u32le", value: starlark.MakeUint64(0x89abcdef), encoded: "\xef\xcd\xab\x89", decoded: "2309737967"},
		{name: "i16be", value: starlark.MakeInt(-2), encoded: "\xff\xfe", decoded: "-2"},
		{name: "i8", value: starlark.MakeInt(-128), encoded: "\x80", decoded: "-128"},
		{name: "u64be", value: starlark.MakeUint64(0x0102030405060708), encoded: "\x01\x02\x03\x04\x05\x06\x07\x08", decoded: "72623859790382856"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := starlark.Call(thread, module[test.name].(starlark.Callable), starlark.Tuple{test.value}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if encoded != test.encoded {
				t.Fatalf("encoded = %v, want %v", encoded, test.encoded)
			}
			source := &observedBinaryFile{immutableBytesFile: &immutableBytesFile{name: "scalar", data: append([]byte("prefix"), []byte(test.encoded)...)}}
			decoded, err := starlark.Call(thread, module["read_"+test.name].(starlark.Callable), starlark.Tuple{source}, []starlark.Tuple{
				{starlark.String("offset"), starlark.MakeInt(6)},
			})
			if err != nil {
				t.Fatal(err)
			}
			if decoded.String() != test.decoded {
				t.Fatalf("decoded = %s, want %s", decoded, test.decoded)
			}
			if len(source.reads) != 1 || source.reads[0] != [2]int64{6, int64(len(test.encoded))} {
				t.Fatalf("reads = %v, want one scalar-width read", source.reads)
			}
		})
	}

	if _, err := starlark.Call(thread, module["u8"].(starlark.Callable), starlark.Tuple{starlark.MakeInt(256)}, nil); err == nil {
		t.Fatal("u8 accepted an overflowing value")
	}
	if _, err := starlark.Call(thread, module["i8"].(starlark.Callable), starlark.Tuple{starlark.MakeInt(128)}, nil); err == nil {
		t.Fatal("i8 accepted an overflowing value")
	}

	builderValue, err := binaryBuilderBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	builder := builderValue.(*binaryBuilder)
	appendI32, _ := builder.Attr("i32le")
	if _, err := starlark.Call(thread, appendI32.(starlark.Callable), starlark.Tuple{starlark.MakeInt(-7)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := builder.appendData("padding", make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	patch, _ := builder.Attr("patch_u32be")
	if _, err := starlark.Call(thread, patch.(starlark.Callable), starlark.Tuple{starlark.MakeInt(4), starlark.MakeUint64(0x12345678)}, nil); err != nil {
		t.Fatal(err)
	}
	if got := starlark.Bytes(builder.data); got != starlark.Bytes("\xf9\xff\xff\xff\x12\x34\x56\x78") {
		t.Fatalf("builder = %v", got)
	}
}

func BenchmarkBinaryReadU32LELazyFile(b *testing.B) {
	file := &immutableBytesFile{name: "scalar", data: make([]byte, 4096)}
	callable := Builtins()["read_u32le"].(starlark.Callable)
	thread := &starlark.Thread{Name: "binary scalar benchmark"}
	args := starlark.Tuple{file, starlark.MakeInt(2048)}
	b.ReportAllocs()
	for range b.N {
		if _, err := starlark.Call(thread, callable, args, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBinaryLayoutEncode(t *testing.T) {
	layout, err := compileBinaryLayout("<H2si")
	if err != nil {
		t.Fatal(err)
	}
	for index, name := range []string{"kind", "tag", "delta"} {
		layout.fields[index].name = name
	}
	values := starlark.NewDict(3)
	for name, value := range map[string]starlark.Value{
		"kind":  starlark.MakeInt(0x1234),
		"tag":   starlark.Bytes("ok"),
		"delta": starlark.MakeInt(-7),
	} {
		if err := values.SetKey(starlark.String(name), value); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := layout.encodeBuiltin(nil, nil, starlark.Tuple{values}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != starlark.Bytes("\x34\x12ok\xf9\xff\xff\xff") {
		t.Fatalf("encoded = %v", encoded)
	}
	recordValue, err := layout.decodeBuiltin(nil, nil, starlark.Tuple{encoded}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := layout.encodeBuiltin(nil, nil, starlark.Tuple{recordValue}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reencoded != encoded {
		t.Fatalf("record round trip = %v, want %v", reencoded, encoded)
	}
}

func TestBinaryBitsAndExtents(t *testing.T) {
	view, err := newBinaryByteView(starlark.Bytes("\x96"))
	if err != nil {
		t.Fatal(err)
	}
	bits := &binaryBitCursor{view: view, order: "msb"}
	got, err := bits.readValue(4)
	if err != nil || got != 9 {
		t.Fatalf("MSB bits = %d, %v", got, err)
	}
	bits = &binaryBitCursor{view: view, order: "lsb"}
	got, err = bits.readValue(4)
	if err != nil || got != 6 {
		t.Fatalf("LSB bits = %d, %v", got, err)
	}

	extents := starlark.NewList([]starlark.Value{
		starlark.Tuple{starlark.MakeInt(2), starlark.Bytes("abc")},
		starlark.Tuple{starlark.MakeInt(7), starlark.Bytes("z")},
	})
	value, err := binaryExtentsBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(9), extents}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(value.(File), 0, 9))
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 0, 'a', 'b', 'c', 0, 0, 'z', 0}; !bytes.Equal(data, want) {
		t.Fatalf("extents = %v, want %v", data, want)
	}
}

func TestBinaryDecodeAndReplace(t *testing.T) {
	decoded, err := binaryDecodeBuiltin(nil, nil, starlark.Tuple{starlark.String("41420043"), starlark.String("hex")}, nil)
	if err != nil || decoded != starlark.Bytes("AB\x00C") {
		t.Fatalf("decode = %v, %v", decoded, err)
	}
	replaced, err := binaryReplaceBuiltin(nil, nil, starlark.Tuple{decoded, starlark.Bytes("B\x00"), starlark.Bytes("xy")}, nil)
	if err != nil || replaced != starlark.Bytes("AxyC") {
		t.Fatalf("replace = %v, %v", replaced, err)
	}
}

func TestBinaryBase64Encoding(t *testing.T) {
	value, err := binaryBase64Builtin(nil, nil, starlark.Tuple{starlark.Bytes("binary\x00data")}, nil)
	if err != nil || value != starlark.String("YmluYXJ5AGRhdGE=") {
		t.Fatalf("base64 = %v, %v", value, err)
	}
	value, err = binaryBase64Builtin(nil, nil, starlark.Tuple{starlark.Bytes("\xfb\xff")}, []starlark.Tuple{
		{starlark.String("url"), starlark.True},
		{starlark.String("padding"), starlark.False},
	})
	if err != nil || value != starlark.String("-_8") {
		t.Fatalf("base64url = %v, %v", value, err)
	}
	if _, err := binaryBase64Builtin(nil, nil, starlark.Tuple{starlark.Bytes("too large")}, []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(4)}}); err == nil {
		t.Fatal("base64 accepted output beyond its limit")
	}
	value, err = binaryBase64Builtin(nil, nil, starlark.Tuple{starlark.Bytes("x")}, []starlark.Tuple{
		{starlark.String("padding"), starlark.False},
		{starlark.String("maximum"), starlark.MakeInt(2)},
	})
	if err != nil || value != starlark.String("eA") {
		t.Fatalf("bounded raw base64 = %v, %v", value, err)
	}
}

func TestBinaryHexEncoding(t *testing.T) {
	value, err := binaryHexBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\x00\xab\xff")}, nil)
	if err != nil || value != starlark.String("00abff") {
		t.Fatalf("hex = %v, %v", value, err)
	}
	if _, err := binaryHexBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\x00\xab")}, []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt(3)}}); err == nil {
		t.Fatal("hex accepted output beyond its limit")
	}
}

func TestBinaryTextDecoding(t *testing.T) {
	value, err := binaryTextBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("h\x00i\x00\x00\x00x\x00")}, []starlark.Tuple{
		{starlark.String("encoding"), starlark.String("utf16le")},
		{starlark.String("nul"), starlark.True},
	})
	if err != nil || value != starlark.String("hi") {
		t.Fatalf("UTF-16 text = %v, %v", value, err)
	}
	if _, err := binaryTextBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("\xff"), starlark.String("utf8")}, nil); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestBinaryViewFindIndices(t *testing.T) {
	view, err := newBinaryByteView(starlark.Bytes("prefix-alpha-middle-beta-suffix"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := view.findIndicesBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{
		starlark.Bytes("beta"), starlark.Bytes("missing"), starlark.Bytes("alpha"), starlark.Bytes(""),
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(*starlark.List).String(); got != "[0, 2, 3]" {
		t.Fatalf("find_indices = %s, want [0, 2, 3]", got)
	}
}

func TestBinaryViewFindIndicesLargeFixedWidthSet(t *testing.T) {
	data := bytes.Repeat([]byte{0xcc}, (128<<10)+32)
	patterns := make([]starlark.Value, 64)
	for index := range patterns {
		pattern := bytes.Repeat([]byte{byte(index)}, 16)
		patterns[index] = starlark.Bytes(pattern)
	}
	copy(data[(128<<10)-8:], []byte(patterns[7].(starlark.Bytes)))
	copy(data[len(data)-16:], []byte(patterns[51].(starlark.Bytes)))
	view, err := newBinaryByteView(starlark.Bytes(data))
	if err != nil {
		t.Fatal(err)
	}
	value, err := view.findIndicesBuiltin(nil, nil, starlark.Tuple{starlark.NewList(patterns)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(*starlark.List).String(); got != "[7, 51]" {
		t.Fatalf("find_indices = %s, want [7, 51]", got)
	}
}

func TestBinaryViewFindAll(t *testing.T) {
	view, err := newBinaryByteView(starlark.Bytes("aaaa-prefix-aa"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := view.findAllBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("aa")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := value.(*starlark.List).String(); got != "[0, 1, 2, 12]" {
		t.Fatalf("find_all = %s, want [0, 1, 2, 12]", got)
	}
	if _, err := view.findAllBuiltin(nil, nil, starlark.Tuple{starlark.Bytes("a")}, []starlark.Tuple{{starlark.String("limit"), starlark.MakeInt(2)}}); err == nil {
		t.Fatal("find_all accepted more matches than its limit")
	}
}

func TestBinaryViewCompareModes(t *testing.T) {
	tests := []struct {
		name   string
		left   string
		right  string
		signed bool
		exact  bool
		want   int64
	}{
		{name: "default ordering", left: "a\x10", right: "a\x20", want: -1},
		{name: "default length difference", left: "abcd", right: "a", want: 3},
		{name: "exact unsigned", left: "a\x10", right: "a\x20", exact: true, want: -16},
		{name: "exact unsigned tail", left: "a\x20", right: "a", exact: true, want: 32},
		{name: "signed ordering", left: "\x80", right: "\x7f", signed: true, want: -1},
		{name: "exact signed", left: "\x80", right: "\x7f", signed: true, exact: true, want: -255},
		{name: "exact signed left tail", left: "a\x80", right: "a", signed: true, exact: true, want: -128},
		{name: "exact signed right tail", left: "a", right: "a\x80", signed: true, exact: true, want: 128},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, err := newBinaryByteView(starlark.Bytes(test.left))
			if err != nil {
				t.Fatal(err)
			}
			kwargs := []starlark.Tuple{
				{starlark.String("signed"), starlark.Bool(test.signed)},
				{starlark.String("exact"), starlark.Bool(test.exact)},
			}
			value, err := left.compareBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(test.right)}, kwargs)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := value.(starlark.Int).Int64()
			if !ok || got != test.want {
				t.Fatalf("compare = %v, want %d", value, test.want)
			}
		})
	}
}
