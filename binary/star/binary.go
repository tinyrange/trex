package star

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	windowsapi "github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
)

const defaultBinaryBuilderLimit = 512 << 20

type File = starfile.File

type binaryScalarCodec struct {
	name   string
	width  int
	order  binary.ByteOrder
	signed bool
	float  bool
}

var binaryScalarCodecs = []binaryScalarCodec{
	{name: "u8", width: 1, order: binary.LittleEndian},
	{name: "i8", width: 1, order: binary.LittleEndian, signed: true},
	{name: "u16le", width: 2, order: binary.LittleEndian},
	{name: "u16be", width: 2, order: binary.BigEndian},
	{name: "i16le", width: 2, order: binary.LittleEndian, signed: true},
	{name: "i16be", width: 2, order: binary.BigEndian, signed: true},
	{name: "u32le", width: 4, order: binary.LittleEndian},
	{name: "u32be", width: 4, order: binary.BigEndian},
	{name: "i32le", width: 4, order: binary.LittleEndian, signed: true},
	{name: "i32be", width: 4, order: binary.BigEndian, signed: true},
	{name: "u64le", width: 8, order: binary.LittleEndian},
	{name: "u64be", width: 8, order: binary.BigEndian},
	{name: "i64le", width: 8, order: binary.LittleEndian, signed: true},
	{name: "i64be", width: 8, order: binary.BigEndian, signed: true},
	{name: "f32le", width: 4, order: binary.LittleEndian, float: true},
	{name: "f32be", width: 4, order: binary.BigEndian, float: true},
	{name: "f64le", width: 8, order: binary.LittleEndian, float: true},
	{name: "f64be", width: 8, order: binary.BigEndian, float: true},
}

func binaryScalarCodecNamed(name string) (binaryScalarCodec, bool) {
	for _, codec := range binaryScalarCodecs {
		if codec.name == name {
			return codec, true
		}
	}
	return binaryScalarCodec{}, false
}

func Builtins() starlark.StringDict {
	attrs := starlark.StringDict{
		"annotate": starlark.NewBuiltin("annotate", binaryAnnotateBuiltin),
		"base64":   starlark.NewBuiltin("base64", binaryBase64Builtin),
		"bits":     starlark.NewBuiltin("bits", binaryBitsBuiltin),
		"builder":  starlark.NewBuiltin("builder", binaryBuilderBuiltin),
		"concat":   starlark.NewBuiltin("concat", binaryConcatBuiltin),
		"cursor":   starlark.NewBuiltin("cursor", binaryCursorBuiltin),
		"decode":   starlark.NewBuiltin("decode", binaryDecodeBuiltin),
		"encode":   starlark.NewBuiltin("encode", binaryEncodeBuiltin),
		"extents":  starlark.NewBuiltin("extents", binaryExtentsBuiltin),
		"hex":      starlark.NewBuiltin("hex", binaryHexBuiltin),
		"layout":   starlark.NewBuiltin("layout", binaryLayoutBuiltin),
		"replace":  starlark.NewBuiltin("replace", binaryReplaceBuiltin),
		"strings":  starlark.NewBuiltin("strings", binaryStringsBuiltin),
		"text":     starlark.NewBuiltin("text", binaryTextBuiltin),
		"view":     starlark.NewBuiltin("view", binaryViewBuiltin),
		"xml":      starlark.NewBuiltin("xml", binaryXMLBuiltin),
	}
	for _, codec := range binaryScalarCodecs {
		codec := codec
		attrs[codec.name] = starlark.NewBuiltin("binary."+codec.name, codec.encodeBuiltin)
		attrs["read_"+codec.name] = starlark.NewBuiltin("binary.read_"+codec.name, codec.readBuiltin)
	}
	return attrs
}

func (codec binaryScalarCodec) encodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs(codec.name, args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := codec.encode(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", codec.name, err)
	}
	return starlark.Bytes(data), nil
}

func (codec binaryScalarCodec) readBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var offset int64
	name := "read_" + codec.name
	if err := starlark.UnpackArgs(name, args, kwargs, "source", &source, "offset?", &offset); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(source)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if offset < 0 || int64(codec.width) > view.size-offset {
		return nil, fmt.Errorf("%s: need %d bytes at offset %d, input size is %d", name, codec.width, offset, view.size)
	}
	var storage [8]byte
	if _, err := view.ReadAt(storage[:codec.width], offset); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return codec.decode(storage[:codec.width]), nil
}

func (codec binaryScalarCodec) encode(value starlark.Value) ([]byte, error) {
	data := make([]byte, codec.width)
	if codec.float {
		floating, ok := value.(starlark.Float)
		if !ok {
			return nil, fmt.Errorf("got %s, want float", value.Type())
		}
		if codec.width == 4 {
			codec.order.PutUint32(data, math.Float32bits(float32(floating)))
		} else {
			codec.order.PutUint64(data, math.Float64bits(float64(floating)))
		}
		return data, nil
	}
	integer, ok := value.(starlark.Int)
	if !ok {
		return nil, fmt.Errorf("got %s, want int", value.Type())
	}
	var bits uint64
	if codec.signed {
		n, ok := integer.Int64()
		if !ok || codec.width < 8 && (n < -(int64(1)<<(codec.width*8-1)) || n >= int64(1)<<(codec.width*8-1)) {
			return nil, fmt.Errorf("value does not fit in signed %d bits", codec.width*8)
		}
		bits = uint64(n)
	} else {
		n, ok := integer.Uint64()
		if !ok || codec.width < 8 && n >= uint64(1)<<(codec.width*8) {
			return nil, fmt.Errorf("value does not fit in unsigned %d bits", codec.width*8)
		}
		bits = n
	}
	switch codec.width {
	case 1:
		data[0] = byte(bits)
	case 2:
		codec.order.PutUint16(data, uint16(bits))
	case 4:
		codec.order.PutUint32(data, uint32(bits))
	case 8:
		codec.order.PutUint64(data, bits)
	}
	return data, nil
}

func (codec binaryScalarCodec) decode(data []byte) starlark.Value {
	var bits uint64
	switch codec.width {
	case 1:
		bits = uint64(data[0])
	case 2:
		bits = uint64(codec.order.Uint16(data))
	case 4:
		bits = uint64(codec.order.Uint32(data))
	case 8:
		bits = codec.order.Uint64(data)
	}
	if codec.float {
		if codec.width == 4 {
			return starlark.Float(math.Float32frombits(uint32(bits)))
		}
		return starlark.Float(math.Float64frombits(bits))
	}
	if codec.signed {
		switch codec.width {
		case 1:
			return starlark.MakeInt(int(int8(bits)))
		case 2:
			return starlark.MakeInt(int(int16(bits)))
		case 4:
			return starlark.MakeInt64(int64(int32(bits)))
		case 8:
			return starlark.MakeInt64(int64(bits))
		}
	}
	return starlark.MakeUint64(bits)
}

func binaryHexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := defaultBinaryBuilderLimit
	if err := starlark.UnpackArgs("hex", args, kwargs, "value", &value, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 {
		return nil, fmt.Errorf("hex: maximum must be non-negative")
	}
	data, err := bytesForBinaryValueLimited(value, int64(maximum/2))
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	encodedSize := hex.EncodedLen(len(data))
	if encodedSize > maximum {
		return nil, fmt.Errorf("hex: output size %d exceeds limit %d", encodedSize, maximum)
	}
	return starlark.String(hex.EncodeToString(data)), nil
}

func binaryBase64Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	url := false
	padding := true
	maximum := defaultBinaryBuilderLimit
	if err := starlark.UnpackArgs("base64", args, kwargs, "value", &value, "url?", &url, "padding?", &padding, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 {
		return nil, fmt.Errorf("base64: maximum must be non-negative")
	}
	maximumInput := maximum / 4 * 3
	if !padding {
		switch maximum % 4 {
		case 2:
			maximumInput++
		case 3:
			maximumInput += 2
		}
	}
	data, err := bytesForBinaryValueLimited(value, int64(maximumInput))
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	encodedSize := base64.StdEncoding.EncodedLen(len(data))
	if !padding {
		encodedSize = base64.RawStdEncoding.EncodedLen(len(data))
	}
	if encodedSize > maximum {
		return nil, fmt.Errorf("base64: output size %d exceeds limit %d", encodedSize, maximum)
	}
	encoding := base64.StdEncoding
	if url {
		encoding = base64.URLEncoding
	}
	if !padding {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	return starlark.String(encoding.EncodeToString(data)), nil
}

func binaryTextBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	encoding := "utf8"
	nul := false
	maximum := 16 << 20
	if err := starlark.UnpackArgs("text", args, kwargs, "value", &value, "encoding?", &encoding, "nul?", &nul, "maximum?", &maximum); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("text: %w", err)
	}
	if maximum < 0 || len(data) > maximum {
		return nil, fmt.Errorf("text: input size %d exceeds limit %d", len(data), maximum)
	}
	switch strings.ToLower(strings.ReplaceAll(encoding, "-", "")) {
	case "ascii":
		if nul {
			if end := bytes.IndexByte(data, 0); end >= 0 {
				data = data[:end]
			}
		}
		for _, value := range data {
			if value > 0x7f {
				return nil, fmt.Errorf("text: input is not ASCII")
			}
		}
		return starlark.String(string(data)), nil
	case "utf8":
		if nul {
			if end := bytes.IndexByte(data, 0); end >= 0 {
				data = data[:end]
			}
		}
		if !utf8.Valid(data) {
			return nil, fmt.Errorf("text: input is not valid UTF-8")
		}
		return starlark.String(string(data)), nil
	case "utf16le", "utf16be":
		if len(data)%2 != 0 {
			return nil, fmt.Errorf("text: UTF-16 input has odd size")
		}
		var order binary.ByteOrder = binary.LittleEndian
		if strings.Contains(strings.ToLower(encoding), "be") {
			order = binary.BigEndian
		}
		units := make([]uint16, 0, len(data)/2)
		for offset := 0; offset < len(data); offset += 2 {
			unit := order.Uint16(data[offset : offset+2])
			if nul && unit == 0 {
				break
			}
			units = append(units, unit)
		}
		return starlark.String(string(utf16.Decode(units))), nil
	default:
		return nil, fmt.Errorf("text: unsupported encoding %q", encoding)
	}
}

func binaryDecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, encoding string
	maximum := defaultBinaryBuilderLimit
	if err := starlark.UnpackArgs("decode", args, kwargs, "value", &value, "encoding", &encoding, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum < 0 {
		return nil, fmt.Errorf("decode: maximum must be non-negative")
	}
	var data []byte
	var err error
	switch strings.ToLower(strings.ReplaceAll(encoding, "-", "")) {
	case "hex", "base16":
		data, err = hex.DecodeString(value)
	case "base64":
		data, err = base64.StdEncoding.DecodeString(value)
	case "base64url":
		data, err = base64.RawURLEncoding.DecodeString(value)
	default:
		return nil, fmt.Errorf("decode: unsupported encoding %q", encoding)
	}
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(data) > maximum {
		return nil, fmt.Errorf("decode: output size %d exceeds limit %d", len(data), maximum)
	}
	return starlark.Bytes(data), nil
}

func binaryReplaceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, oldValue, newValue starlark.Value
	count := -1
	maximum := defaultBinaryBuilderLimit
	if err := starlark.UnpackArgs("replace", args, kwargs, "value", &value, "old", &oldValue, "new", &newValue, "count?", &count, "maximum?", &maximum); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("replace: value: %w", err)
	}
	oldData, err := bytesForBinaryValue(oldValue)
	if err != nil || len(oldData) == 0 {
		return nil, fmt.Errorf("replace: old must be non-empty binary data")
	}
	newData, err := bytesForBinaryValue(newValue)
	if err != nil {
		return nil, fmt.Errorf("replace: new: %w", err)
	}
	if count < -1 || maximum < 0 {
		return nil, fmt.Errorf("replace: invalid count or maximum")
	}
	result := bytes.Replace(data, oldData, newData, count)
	if len(result) > maximum {
		return nil, fmt.Errorf("replace: output size %d exceeds limit %d", len(result), maximum)
	}
	return starlark.Bytes(result), nil
}

func binaryEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value string
	encoding := "utf8"
	nul := false
	if err := starlark.UnpackArgs("encode", args, kwargs, "value", &value, "encoding?", &encoding, "nul?", &nul); err != nil {
		return nil, err
	}
	var data []byte
	switch strings.ToLower(strings.ReplaceAll(encoding, "-", "")) {
	case "utf8":
		data = []byte(value)
		if nul {
			data = append(data, 0)
		}
	case "ascii":
		data = make([]byte, len(value))
		for index, character := range []byte(value) {
			if character > 0x7f {
				return nil, fmt.Errorf("encode: value is not ASCII")
			}
			data[index] = character
		}
		if nul {
			data = append(data, 0)
		}
	case "utf16le", "utf16be":
		units := utf16.Encode([]rune(value))
		if nul {
			units = append(units, 0)
		}
		data = make([]byte, len(units)*2)
		var order binary.ByteOrder = binary.LittleEndian
		if strings.Contains(strings.ToLower(encoding), "be") {
			order = binary.BigEndian
		}
		for index, unit := range units {
			order.PutUint16(data[index*2:], unit)
		}
	default:
		return nil, fmt.Errorf("encode: unsupported encoding %q", encoding)
	}
	return starlark.Bytes(data), nil
}

func binaryStringsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	encoding := "ascii"
	minimum := 4
	maximum := 64 << 20
	if err := starlark.UnpackArgs("strings", args, kwargs, "value", &value, "encoding?", &encoding, "minimum?", &minimum, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if minimum < 1 || maximum < 0 {
		return nil, fmt.Errorf("strings: minimum must be positive and maximum non-negative")
	}
	if file, ok := value.(File); ok && file.Size() > int64(maximum) {
		return nil, fmt.Errorf("strings: input size %d exceeds limit %d", file.Size(), maximum)
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("strings: %w", err)
	}
	var found []string
	switch strings.ToLower(encoding) {
	case "ascii":
		found = scanASCIIStrings(data, minimum)
	case "utf16le", "utf-16le":
		found = windowsapi.ScanUTF16Strings(data, minimum)
	default:
		return nil, fmt.Errorf("strings: encoding must be ascii or utf16le")
	}
	values := make([]starlark.Value, len(found))
	for index, value := range found {
		values[index] = starlark.String(value)
	}
	return starlark.NewList(values), nil
}

func scanASCIIStrings(data []byte, minimum int) []string {
	var out []string
	for offset := 0; offset < len(data); {
		start := offset
		for offset < len(data) && (data[offset] >= 0x20 && data[offset] <= 0x7e || data[offset] == '\t') {
			offset++
		}
		if offset-start >= minimum {
			out = append(out, string(data[start:offset]))
		}
		offset++
	}
	return out
}

type annotatedFile struct {
	File
	attrs starlark.StringDict
}

func binaryAnnotateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var attrs *starlark.Dict
	if err := starlark.UnpackArgs("annotate", args, kwargs, "file", &value, "attrs", &attrs); err != nil {
		return nil, err
	}
	file, ok := value.(File)
	if !ok {
		return nil, fmt.Errorf("annotate: got %s, want file", value.Type())
	}
	values := make(starlark.StringDict, attrs.Len())
	for _, item := range attrs.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("annotate: attribute name is %s, want string", item[0].Type())
		}
		values[name] = item[1]
	}
	return &annotatedFile{File: file, attrs: values}, nil
}

func (f *annotatedFile) String() string { return fmt.Sprintf("<annotated %s>", f.File.String()) }
func (f *annotatedFile) Attr(name string) (starlark.Value, error) {
	if value, ok := f.attrs[name]; ok {
		return value, nil
	}
	if attrs, ok := f.File.(starlark.HasAttrs); ok {
		return attrs.Attr(name)
	}
	return nil, nil
}
func (f *annotatedFile) AttrNames() []string {
	names := make([]string, 0, len(f.attrs)+len(starfile.AttrNames()))
	if attrs, ok := f.File.(starlark.HasAttrs); ok {
		names = append(names, attrs.AttrNames()...)
	}
	for name := range f.attrs {
		if !slicesContains(names, name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type immutableBytesFile struct {
	name string
	data []byte
}

func (f *immutableBytesFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *immutableBytesFile) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *immutableBytesFile) Size() int64 { return int64(len(f.data)) }
func (f *immutableBytesFile) String() string {
	return fmt.Sprintf("<file %s size=%d>", f.name, len(f.data))
}
func (f *immutableBytesFile) Type() string         { return "file" }
func (f *immutableBytesFile) Freeze()              {}
func (f *immutableBytesFile) Truth() starlark.Bool { return starlark.True }
func (f *immutableBytesFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *immutableBytesFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *immutableBytesFile) AttrNames() []string { return starfile.AttrNames() }

// binaryByteView is an immutable bounded window over a File. It implements File
// so archive, filesystem, hash, and write operations can consume it directly.
type binaryByteView struct {
	base File
	off  int64
	size int64
}

func newBinaryByteView(value starlark.Value) (*binaryByteView, error) {
	switch value := value.(type) {
	case *binaryByteView:
		return value, nil
	case File:
		return &binaryByteView{base: value, size: value.Size()}, nil
	case starlark.Bytes:
		file := &immutableBytesFile{name: "bytes", data: []byte(value)}
		return &binaryByteView{base: file, size: file.Size()}, nil
	case starlark.String:
		file := &immutableBytesFile{name: "string", data: []byte(string(value))}
		return &binaryByteView{base: file, size: file.Size()}, nil
	default:
		return nil, fmt.Errorf("got %s, want file, bytes, string, or byte_view", value.Type())
	}
}

func (v *binaryByteView) subview(off, size int64) (*binaryByteView, error) {
	if off < 0 || size < 0 || off > v.size || size > v.size-off {
		return nil, fmt.Errorf("byte view range [%d:%d] exceeds size %d", off, off+size, v.size)
	}
	return &binaryByteView{base: v.base, off: v.off + off, size: size}, nil
}

func (v *binaryByteView) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(len(p)) > v.size-off {
		p = p[:v.size-off]
	}
	n, err := v.base.ReadAt(p, v.off+off)
	if err != nil && !(err == io.EOF && n == len(p)) {
		return n, err
	}
	if n != want {
		return n, io.EOF
	}
	return n, nil
}
func (v *binaryByteView) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("byte_view is read-only")
}
func (v *binaryByteView) Size() int64           { return v.size }
func (v *binaryByteView) Len() int              { return boundedInt(v.size) }
func (v *binaryByteView) String() string        { return fmt.Sprintf("<byte_view size=%d>", v.size) }
func (v *binaryByteView) Type() string          { return "byte_view" }
func (v *binaryByteView) Freeze()               {}
func (v *binaryByteView) Truth() starlark.Bool  { return starlark.Bool(v.size != 0) }
func (v *binaryByteView) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: byte_view") }
func (v *binaryByteView) Index(index int) starlark.Value {
	var data [1]byte
	if _, err := v.ReadAt(data[:], int64(index)); err != nil {
		return starlark.None
	}
	return starlark.MakeInt(int(data[0]))
}
func (v *binaryByteView) Slice(start, end, step int) starlark.Value {
	if step == 1 {
		view, _ := v.subview(int64(start), int64(end-start))
		return view
	}
	data := make([]byte, 0)
	if step > 0 {
		for index := start; index < end; index += step {
			data = append(data, byte(v.Index(index).(starlark.Int).BigInt().Uint64()))
		}
	} else {
		for index := start; index > end; index += step {
			data = append(data, byte(v.Index(index).(starlark.Int).BigInt().Uint64()))
		}
	}
	return starlark.Bytes(data)
}
func (v *binaryByteView) Iterate() starlark.Iterator { return &byteViewIterator{view: v} }
func (v *binaryByteView) AttrNames() []string {
	return []string{"bytes", "compare", "find", "find_all", "find_indices", "size", "slice"}
}
func (v *binaryByteView) Attr(name string) (starlark.Value, error) {
	switch name {
	case "size":
		return starlark.MakeInt64(v.size), nil
	case "slice":
		return starlark.NewBuiltin("slice", v.sliceBuiltin), nil
	case "bytes":
		return starlark.NewBuiltin("bytes", v.bytesBuiltin), nil
	case "find":
		return starlark.NewBuiltin("find", v.findBuiltin), nil
	case "find_all":
		return starlark.NewBuiltin("find_all", v.findAllBuiltin), nil
	case "find_indices":
		return starlark.NewBuiltin("find_indices", v.findIndicesBuiltin), nil
	case "compare":
		return starlark.NewBuiltin("compare", v.compareBuiltin), nil
	}
	return nil, nil
}

func (v *binaryByteView) findIndicesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values starlark.Value
	start := 0
	end := boundedInt(v.size)
	if err := starlark.UnpackArgs("find_indices", args, kwargs, "needles", &values, "start?", &start, "end?", &end); err != nil {
		return nil, err
	}
	if start < 0 || end < start || int64(end) > v.size {
		return nil, fmt.Errorf("find_indices: invalid range [%d:%d] for size %d", start, end, v.size)
	}
	iterable, ok := values.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("find_indices: needles is %s, want iterable", values.Type())
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	var value starlark.Value
	var needles [][]byte
	maximum := 0
	for iterator.Next(&value) {
		needle, err := bytesForBinaryValue(value)
		if err != nil {
			return nil, fmt.Errorf("find_indices: needle %d: %w", len(needles), err)
		}
		if len(needle) > defaultBinaryBuilderLimit || len(needles) >= 65536 {
			return nil, fmt.Errorf("find_indices: pattern limits exceeded")
		}
		needles = append(needles, needle)
		maximum = max(maximum, len(needle))
	}
	found := make([]bool, len(needles))
	remaining := len(needles)
	for index, needle := range needles {
		if len(needle) == 0 {
			found[index] = true
			remaining--
		}
	}
	if remaining > 0 && start < end {
		const chunkSize = 128 << 10
		buffer := make([]byte, chunkSize+max(0, maximum-1))
		var groups map[int]map[string][]int
		var lengths []int
		if remaining >= 16 {
			groups = make(map[int]map[string][]int)
			for index, needle := range needles {
				if len(needle) == 0 {
					continue
				}
				group := groups[len(needle)]
				if group == nil {
					group = make(map[string][]int)
					groups[len(needle)] = group
					lengths = append(lengths, len(needle))
				}
				key := string(needle)
				group[key] = append(group[key], index)
			}
			sort.Ints(lengths)
		}
		carry := 0
		for pos := int64(start); pos < int64(end) && remaining > 0; {
			count := min(int64(chunkSize), int64(end)-pos)
			n, readErr := v.ReadAt(buffer[carry:carry+int(count)], pos)
			if readErr != nil && readErr != io.EOF {
				return nil, readErr
			}
			window := buffer[:carry+n]
			if groups == nil {
				for index, needle := range needles {
					if !found[index] && len(needle) <= len(window) && bytes.Contains(window, needle) {
						found[index] = true
						remaining--
					}
				}
			} else {
				for _, length := range lengths {
					if length > len(window) {
						break
					}
					group := groups[length]
					for offset := 0; offset+length <= len(window) && remaining > 0; offset++ {
						for _, index := range group[string(window[offset:offset+length])] {
							if !found[index] {
								found[index] = true
								remaining--
							}
						}
					}
				}
			}
			carry = min(max(0, maximum-1), len(window))
			copy(buffer, window[len(window)-carry:])
			pos += int64(n)
			if n == 0 {
				break
			}
		}
	}
	indices := make([]starlark.Value, 0, len(needles)-remaining)
	for index, present := range found {
		if present {
			indices = append(indices, starlark.MakeInt(index))
		}
	}
	return starlark.NewList(indices), nil
}

type byteViewIterator struct {
	view  *binaryByteView
	index int64
}

func (it *byteViewIterator) Next(value *starlark.Value) bool {
	if it.index >= it.view.size {
		return false
	}
	*value = it.view.Index(int(it.index))
	it.index++
	return true
}
func (it *byteViewIterator) Done() {}

func (v *binaryByteView) sliceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	off, size, err := unpackBinaryRange("slice", args, kwargs, v.size)
	if err != nil {
		return nil, err
	}
	return v.subview(off, size)
}

func (v *binaryByteView) bytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	off, size, err := unpackBinaryRange("bytes", args, kwargs, v.size)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	if _, err := v.ReadAt(data, off); err != nil && err != io.EOF {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

func (v *binaryByteView) findBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var needleValue starlark.Value
	start := 0
	end := boundedInt(v.size)
	if err := starlark.UnpackArgs("find", args, kwargs, "needle", &needleValue, "start?", &start, "end?", &end); err != nil {
		return nil, err
	}
	needle, err := bytesForBinaryValue(needleValue)
	if err != nil {
		return nil, fmt.Errorf("find: %w", err)
	}
	if start < 0 || end < start || int64(end) > v.size {
		return nil, fmt.Errorf("find: invalid range [%d:%d] for size %d", start, end, v.size)
	}
	if len(needle) == 0 {
		return starlark.MakeInt(start), nil
	}
	const chunkSize = 128 << 10
	buffer := make([]byte, chunkSize+len(needle)-1)
	carry := 0
	for pos := int64(start); pos < int64(end); {
		count := int64(chunkSize)
		if count > int64(end)-pos {
			count = int64(end) - pos
		}
		n, readErr := v.ReadAt(buffer[carry:carry+int(count)], pos)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		window := buffer[:carry+n]
		if index := bytes.Index(window, needle); index >= 0 {
			return starlark.MakeInt64(pos - int64(carry) + int64(index)), nil
		}
		carry = min(len(needle)-1, len(window))
		copy(buffer, window[len(window)-carry:])
		pos += int64(n)
		if n == 0 {
			break
		}
	}
	return starlark.MakeInt(-1), nil
}

func (v *binaryByteView) findAllBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var needleValue starlark.Value
	start := 0
	end := boundedInt(v.size)
	limit := 1 << 20
	if err := starlark.UnpackArgs("find_all", args, kwargs, "needle", &needleValue, "start?", &start, "end?", &end, "limit?", &limit); err != nil {
		return nil, err
	}
	needle, err := bytesForBinaryValue(needleValue)
	if err != nil {
		return nil, fmt.Errorf("find_all: %w", err)
	}
	if start < 0 || end < start || int64(end) > v.size || limit < 0 {
		return nil, fmt.Errorf("find_all: invalid range or limit")
	}
	if len(needle) == 0 {
		return nil, fmt.Errorf("find_all: needle must not be empty")
	}
	if len(needle) > defaultBinaryBuilderLimit {
		return nil, fmt.Errorf("find_all: needle exceeds size limit")
	}

	const chunkSize = 128 << 10
	buffer := make([]byte, chunkSize+len(needle)-1)
	positions := make([]starlark.Value, 0)
	carry := 0
	nextMatch := int64(start)
	for pos := int64(start); pos < int64(end); {
		count := min(int64(chunkSize), int64(end)-pos)
		n, readErr := v.ReadAt(buffer[carry:carry+int(count)], pos)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		window := buffer[:carry+n]
		base := pos - int64(carry)
		search := max(0, int(nextMatch-base))
		for search+len(needle) <= len(window) {
			index := bytes.Index(window[search:], needle)
			if index < 0 {
				break
			}
			absolute := base + int64(search+index)
			if absolute+int64(len(needle)) > int64(end) {
				break
			}
			if len(positions) >= limit {
				return nil, fmt.Errorf("find_all: match limit %d exceeded", limit)
			}
			positions = append(positions, starlark.MakeInt64(absolute))
			nextMatch = absolute + 1
			search = int(nextMatch - base)
		}
		carry = min(len(needle)-1, len(window))
		copy(buffer, window[len(window)-carry:])
		pos += int64(n)
		if n == 0 {
			break
		}
	}
	return starlark.NewList(positions), nil
}

func (v *binaryByteView) compareBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var otherValue starlark.Value
	signed := false
	exact := false
	if err := starlark.UnpackArgs("compare", args, kwargs, "other", &otherValue, "signed?", &signed, "exact?", &exact); err != nil {
		return nil, err
	}
	other, err := newBinaryByteView(otherValue)
	if err != nil {
		return nil, fmt.Errorf("compare: %w", err)
	}
	const chunk = 128 << 10
	left, right := make([]byte, chunk), make([]byte, chunk)
	limit := min(v.size, other.size)
	for off := int64(0); off < limit; off += chunk {
		size := min(int64(chunk), limit-off)
		_, _ = v.ReadAt(left[:size], off)
		_, _ = other.ReadAt(right[:size], off)
		if !signed && !exact {
			if result := bytes.Compare(left[:size], right[:size]); result != 0 {
				return starlark.MakeInt(result), nil
			}
			continue
		}
		for index := int64(0); index < size; index++ {
			leftByte, rightByte := int(left[index]), int(right[index])
			if signed {
				leftByte, rightByte = int(int8(left[index])), int(int8(right[index]))
			}
			if leftByte != rightByte {
				if exact {
					return starlark.MakeInt(leftByte - rightByte), nil
				}
				if leftByte < rightByte {
					return starlark.MakeInt(-1), nil
				}
				return starlark.MakeInt(1), nil
			}
		}
	}
	if exact && v.size != other.size {
		var tail [1]byte
		if v.size > other.size {
			_, _ = v.ReadAt(tail[:], limit)
			value := int(tail[0])
			if signed {
				value = int(int8(tail[0]))
			}
			return starlark.MakeInt(value), nil
		}
		_, _ = other.ReadAt(tail[:], limit)
		value := int(tail[0])
		if signed {
			value = int(int8(tail[0]))
		}
		return starlark.MakeInt(-value), nil
	}
	return starlark.MakeInt64(v.size - other.size), nil
}

func binaryViewBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	offset := 0
	sizeValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("view", args, kwargs, "value", &value, "offset?", &offset, "size?", &sizeValue); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(value)
	if err != nil {
		return nil, fmt.Errorf("view: %w", err)
	}
	if offset < 0 || int64(offset) > view.size {
		return nil, fmt.Errorf("view: offset exceeds input")
	}
	size := view.size - int64(offset)
	if sizeValue != starlark.None {
		parsed, err := starlark.AsInt32(sizeValue)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("view: size must be a non-negative int")
		}
		size = int64(parsed)
	}
	return view.subview(int64(offset), size)
}

type binaryCursor struct {
	view   *binaryByteView
	offset int64
	frozen bool
}

func binaryCursorBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	offset := 0
	if err := starlark.UnpackArgs("cursor", args, kwargs, "value", &value, "offset?", &offset); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(value)
	if err != nil {
		return nil, fmt.Errorf("cursor: %w", err)
	}
	if offset < 0 || int64(offset) > view.size {
		return nil, fmt.Errorf("cursor: offset exceeds input")
	}
	return &binaryCursor{view: view, offset: int64(offset)}, nil
}

func (c *binaryCursor) String() string {
	return fmt.Sprintf("<binary.cursor offset=%d size=%d>", c.offset, c.view.size)
}
func (c *binaryCursor) Type() string          { return "binary.cursor" }
func (c *binaryCursor) Freeze()               { c.frozen = true }
func (c *binaryCursor) Truth() starlark.Bool  { return starlark.True }
func (c *binaryCursor) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", c.Type()) }
func (c *binaryCursor) AttrNames() []string {
	names := []string{"align", "bytes", "offset", "remaining", "seek", "skip"}
	for _, codec := range binaryScalarCodecs {
		names = append(names, codec.name)
	}
	sort.Strings(names)
	return names
}
func (c *binaryCursor) Attr(name string) (starlark.Value, error) {
	if name == "offset" {
		return starlark.MakeInt64(c.offset), nil
	}
	if name == "remaining" {
		return starlark.MakeInt64(c.view.size - c.offset), nil
	}
	methods := map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){
		"align": c.alignBuiltin, "bytes": c.readBytesBuiltin, "seek": c.seekBuiltin, "skip": c.skipBuiltin,
	}
	if method := methods[name]; method != nil {
		return starlark.NewBuiltin(name, method), nil
	}
	if codec, ok := binaryScalarCodecNamed(name); ok {
		return starlark.NewBuiltin("binary.cursor."+name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			data, err := c.take(name, codec.width)
			if err != nil {
				return nil, err
			}
			return codec.decode(data), nil
		}), nil
	}
	return nil, nil
}

func (c *binaryCursor) take(name string, size int) ([]byte, error) {
	if c.frozen {
		return nil, fmt.Errorf("%s: cursor is frozen", name)
	}
	if size < 0 || int64(size) > c.view.size-c.offset {
		return nil, fmt.Errorf("%s: need %d bytes at offset %d, only %d remain", name, size, c.offset, c.view.size-c.offset)
	}
	data := make([]byte, size)
	if _, err := c.view.ReadAt(data, c.offset); err != nil && err != io.EOF {
		return nil, err
	}
	c.offset += int64(size)
	return data, nil
}

func (c *binaryCursor) readInteger(name string, width int, order binary.ByteOrder, signed bool) (starlark.Value, error) {
	data, err := c.take(name, width)
	if err != nil {
		return nil, err
	}
	var value uint64
	switch width {
	case 1:
		value = uint64(data[0])
	case 2:
		value = uint64(order.Uint16(data))
	case 4:
		value = uint64(order.Uint32(data))
	case 8:
		value = order.Uint64(data)
	}
	if signed {
		switch width {
		case 1:
			return starlark.MakeInt(int(int8(value))), nil
		case 2:
			return starlark.MakeInt(int(int16(value))), nil
		case 4:
			return starlark.MakeInt64(int64(int32(value))), nil
		case 8:
			return starlark.MakeInt64(int64(value)), nil
		}
	}
	return starlark.MakeUint64(value), nil
}

func (c *binaryCursor) readBytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackArgs("bytes", args, kwargs, "size", &size); err != nil {
		return nil, err
	}
	data, err := c.take("bytes", size)
	return starlark.Bytes(data), err
}
func (c *binaryCursor) seekBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var offset int
	if err := starlark.UnpackArgs("seek", args, kwargs, "offset", &offset); err != nil {
		return nil, err
	}
	if c.frozen || offset < 0 || int64(offset) > c.view.size {
		return nil, fmt.Errorf("seek: invalid or frozen cursor offset %d", offset)
	}
	c.offset = int64(offset)
	return starlark.None, nil
}
func (c *binaryCursor) skipBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackArgs("skip", args, kwargs, "size", &size); err != nil {
		return nil, err
	}
	_, err := c.take("skip", size)
	return starlark.None, err
}
func (c *binaryCursor) alignBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var alignment int
	if err := starlark.UnpackArgs("align", args, kwargs, "alignment", &alignment); err != nil {
		return nil, err
	}
	if alignment <= 0 {
		return nil, fmt.Errorf("align: alignment must be positive")
	}
	padding := (int64(alignment) - c.offset%int64(alignment)) % int64(alignment)
	_, err := c.take("align", int(padding))
	return starlark.None, err
}

type binaryBuilder struct {
	data   []byte
	limit  int
	frozen bool
}

func binaryBuilderBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	capacity, limit := 0, defaultBinaryBuilderLimit
	if err := starlark.UnpackArgs("builder", args, kwargs, "capacity?", &capacity, "limit?", &limit); err != nil {
		return nil, err
	}
	if capacity < 0 || limit < 0 || capacity > limit {
		return nil, fmt.Errorf("builder: require 0 <= capacity <= limit")
	}
	return &binaryBuilder{data: make([]byte, 0, capacity), limit: limit}, nil
}

func (b *binaryBuilder) String() string {
	return fmt.Sprintf("<binary.builder size=%d limit=%d>", len(b.data), b.limit)
}
func (b *binaryBuilder) Type() string          { return "binary.builder" }
func (b *binaryBuilder) Freeze()               { b.frozen = true }
func (b *binaryBuilder) Truth() starlark.Bool  { return starlark.True }
func (b *binaryBuilder) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", b.Type()) }
func (b *binaryBuilder) AttrNames() []string {
	names := []string{"align", "append", "bytes", "file", "patch", "reserve", "size"}
	for _, codec := range binaryScalarCodecs {
		names = append(names, codec.name, "patch_"+codec.name)
	}
	sort.Strings(names)
	return names
}
func (b *binaryBuilder) Attr(name string) (starlark.Value, error) {
	if name == "size" {
		return starlark.MakeInt(len(b.data)), nil
	}
	methods := map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){
		"align": b.alignBuiltin, "append": b.appendBuiltin, "bytes": b.bytesBuiltin, "file": b.fileBuiltin,
		"patch": b.patchBuiltin, "reserve": b.reserveBuiltin,
	}
	if method := methods[name]; method != nil {
		return starlark.NewBuiltin(name, method), nil
	}
	if strings.HasPrefix(name, "patch_") {
		codec, ok := binaryScalarCodecNamed(strings.TrimPrefix(name, "patch_"))
		if !ok {
			return nil, nil
		}
		return starlark.NewBuiltin("binary.builder."+name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var offset int
			var value starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "offset", &offset, "value", &value); err != nil {
				return nil, err
			}
			data, err := codec.encode(value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if b.frozen || offset < 0 || len(data) > len(b.data)-offset {
				return nil, fmt.Errorf("%s: range [%d:%d] exceeds builder size %d or builder is frozen", name, offset, offset+len(data), len(b.data))
			}
			copy(b.data[offset:], data)
			return b, nil
		}), nil
	}
	if codec, ok := binaryScalarCodecNamed(name); ok {
		return starlark.NewBuiltin("binary.builder."+name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var value starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "value", &value); err != nil {
				return nil, err
			}
			data, err := codec.encode(value)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if err := b.appendData(name, data); err != nil {
				return nil, err
			}
			return b, nil
		}), nil
	}
	return nil, nil
}

func (b *binaryBuilder) appendData(name string, data []byte) error {
	if b.frozen {
		return fmt.Errorf("%s: builder is frozen", name)
	}
	if len(data) > b.limit-len(b.data) {
		return fmt.Errorf("%s: builder limit %d exceeded", name, b.limit)
	}
	b.data = append(b.data, data...)
	return nil
}
func (b *binaryBuilder) appendBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("append", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("append: %w", err)
	}
	if err := b.appendData("append", data); err != nil {
		return nil, err
	}
	return b, nil
}
func (b *binaryBuilder) reserveBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	size, fill := 0, 0
	if err := starlark.UnpackArgs("reserve", args, kwargs, "size", &size, "fill?", &fill); err != nil {
		return nil, err
	}
	if size < 0 || fill < 0 || fill > 255 {
		return nil, fmt.Errorf("reserve: invalid size or fill byte")
	}
	offset := len(b.data)
	data := bytes.Repeat([]byte{byte(fill)}, size)
	if err := b.appendData("reserve", data); err != nil {
		return nil, err
	}
	return starlark.MakeInt(offset), nil
}
func (b *binaryBuilder) patchBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	offset := 0
	var value starlark.Value
	if err := starlark.UnpackArgs("patch", args, kwargs, "offset", &offset, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}
	if b.frozen || offset < 0 || len(data) > len(b.data)-offset {
		return nil, fmt.Errorf("patch: range exceeds builder or builder is frozen")
	}
	copy(b.data[offset:], data)
	return b, nil
}
func (b *binaryBuilder) alignBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	alignment, fill := 0, 0
	if err := starlark.UnpackArgs("align", args, kwargs, "alignment", &alignment, "fill?", &fill); err != nil {
		return nil, err
	}
	if alignment <= 0 || fill < 0 || fill > 255 {
		return nil, fmt.Errorf("align: invalid alignment or fill byte")
	}
	padding := (alignment - len(b.data)%alignment) % alignment
	if err := b.appendData("align", bytes.Repeat([]byte{byte(fill)}, padding)); err != nil {
		return nil, err
	}
	return b, nil
}
func (b *binaryBuilder) bytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("bytes", args, kwargs); err != nil {
		return nil, err
	}
	return starlark.Bytes(bytes.Clone(b.data)), nil
}
func (b *binaryBuilder) fileBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("file", args, kwargs); err != nil {
		return nil, err
	}
	return &immutableBytesFile{name: "binary.builder", data: bytes.Clone(b.data)}, nil
}

type binaryBitCursor struct {
	view   *binaryByteView
	bit    int64
	order  string
	frozen bool
}

func binaryBitsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	order := "msb"
	if err := starlark.UnpackArgs("bits", args, kwargs, "value", &value, "order?", &order); err != nil {
		return nil, err
	}
	if order != "msb" && order != "lsb" {
		return nil, fmt.Errorf("bits: order must be msb or lsb")
	}
	view, err := newBinaryByteView(value)
	if err != nil {
		return nil, fmt.Errorf("bits: %w", err)
	}
	return &binaryBitCursor{view: view, order: order}, nil
}
func (b *binaryBitCursor) String() string {
	return fmt.Sprintf("<binary.bits offset=%d order=%s>", b.bit, b.order)
}
func (b *binaryBitCursor) Type() string          { return "binary.bits" }
func (b *binaryBitCursor) Freeze()               { b.frozen = true }
func (b *binaryBitCursor) Truth() starlark.Bool  { return starlark.True }
func (b *binaryBitCursor) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", b.Type()) }
func (b *binaryBitCursor) AttrNames() []string {
	return []string{"align", "drop", "offset", "peek", "read", "remaining"}
}
func (b *binaryBitCursor) Attr(name string) (starlark.Value, error) {
	if name == "offset" {
		return starlark.MakeInt64(b.bit), nil
	}
	if name == "remaining" {
		return starlark.MakeInt64(b.view.size*8 - b.bit), nil
	}
	if name == "read" {
		return starlark.NewBuiltin("read", b.readBuiltin), nil
	}
	if name == "peek" {
		return starlark.NewBuiltin("peek", b.peekBuiltin), nil
	}
	if name == "drop" {
		return starlark.NewBuiltin("drop", b.dropBuiltin), nil
	}
	if name == "align" {
		return starlark.NewBuiltin("align", b.alignBuiltin), nil
	}
	return nil, nil
}
func (b *binaryBitCursor) readValue(count int) (uint64, error) {
	if count < 0 || count > 64 || int64(count) > b.view.size*8-b.bit {
		return 0, fmt.Errorf("bit read of %d exceeds remaining input", count)
	}
	var result uint64
	for i := 0; i < count; i++ {
		byteOffset := b.bit / 8
		bitOffset := uint(b.bit % 8)
		var data [1]byte
		_, _ = b.view.ReadAt(data[:], byteOffset)
		var bit byte
		if b.order == "msb" {
			bit = (data[0] >> (7 - bitOffset)) & 1
		} else {
			bit = (data[0] >> bitOffset) & 1
		}
		if b.order == "msb" {
			result = result<<1 | uint64(bit)
		} else {
			result |= uint64(bit) << i
		}
		b.bit++
	}
	return result, nil
}
func (b *binaryBitCursor) readBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var count int
	if err := starlark.UnpackArgs("read", args, kwargs, "count", &count); err != nil {
		return nil, err
	}
	if b.frozen {
		return nil, fmt.Errorf("read: bit cursor is frozen")
	}
	value, err := b.readValue(count)
	if err != nil {
		return nil, err
	}
	return starlark.MakeUint64(value), nil
}
func (b *binaryBitCursor) peekBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var count int
	if err := starlark.UnpackArgs("peek", args, kwargs, "count", &count); err != nil {
		return nil, err
	}
	old := b.bit
	value, err := b.readValue(count)
	b.bit = old
	if err != nil {
		return nil, err
	}
	return starlark.MakeUint64(value), nil
}
func (b *binaryBitCursor) dropBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var count int
	if err := starlark.UnpackArgs("drop", args, kwargs, "count", &count); err != nil {
		return nil, err
	}
	if b.frozen || count < 0 || int64(count) > b.view.size*8-b.bit {
		return nil, fmt.Errorf("drop: invalid count or frozen cursor")
	}
	b.bit += int64(count)
	return starlark.None, nil
}
func (b *binaryBitCursor) alignBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	alignment := 8
	if err := starlark.UnpackArgs("align", args, kwargs, "alignment?", &alignment); err != nil {
		return nil, err
	}
	if alignment <= 0 {
		return nil, fmt.Errorf("align: alignment must be positive")
	}
	padding := (int64(alignment) - b.bit%int64(alignment)) % int64(alignment)
	return b.dropBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt64(padding)}, nil)
}

type binaryLayoutField struct {
	code byte
	size int
	name string
}
type binaryLayout struct {
	format string
	order  binary.ByteOrder
	fields []binaryLayoutField
	size   int
}

func binaryLayoutBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var format string
	names := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("layout", args, kwargs, "format", &format, "names?", &names); err != nil {
		return nil, err
	}
	layout, err := compileBinaryLayout(format)
	if err != nil {
		return nil, err
	}
	if names != starlark.None {
		iterable, ok := names.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("layout: names must be iterable")
		}
		iter := iterable.Iterate()
		defer iter.Done()
		var value starlark.Value
		index := 0
		for iter.Next(&value) {
			name, ok := starlark.AsString(value)
			if !ok || index >= len(layout.fields) {
				return nil, fmt.Errorf("layout: invalid field names")
			}
			layout.fields[index].name = name
			index++
		}
		if index != len(layout.fields) {
			return nil, fmt.Errorf("layout: got %d names for %d fields", index, len(layout.fields))
		}
	}
	for i := range layout.fields {
		if layout.fields[i].name == "" {
			layout.fields[i].name = "f" + strconv.Itoa(i)
		}
	}
	return layout, nil
}

func compileBinaryLayout(format string) (*binaryLayout, error) {
	if len(format) == 0 || (format[0] != '<' && format[0] != '>') {
		return nil, fmt.Errorf("layout: format must begin with < or >")
	}
	layout := &binaryLayout{format: format, order: binary.LittleEndian}
	if format[0] == '>' {
		layout.order = binary.BigEndian
	}
	count := 0
	for i := 1; i < len(format); i++ {
		if format[i] >= '0' && format[i] <= '9' {
			count = count*10 + int(format[i]-'0')
			continue
		}
		code := format[i]
		size := map[byte]int{'b': 1, 'B': 1, 'h': 2, 'H': 2, 'i': 4, 'I': 4, 'q': 8, 'Q': 8, 's': 1}[code]
		if size == 0 {
			return nil, fmt.Errorf("layout: unsupported format code %q", code)
		}
		if count == 0 {
			count = 1
		}
		if code == 's' {
			size = count
			count = 1
		}
		for range count {
			layout.fields = append(layout.fields, binaryLayoutField{code: code, size: size})
			layout.size += size
		}
		count = 0
	}
	if count != 0 {
		return nil, fmt.Errorf("layout: trailing repeat count")
	}
	return layout, nil
}
func (l *binaryLayout) String() string {
	return fmt.Sprintf("<binary.layout %q size=%d>", l.format, l.size)
}
func (l *binaryLayout) Type() string          { return "binary.layout" }
func (l *binaryLayout) Freeze()               {}
func (l *binaryLayout) Truth() starlark.Bool  { return starlark.True }
func (l *binaryLayout) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", l.Type()) }
func (l *binaryLayout) AttrNames() []string   { return []string{"decode", "encode", "size"} }
func (l *binaryLayout) Attr(name string) (starlark.Value, error) {
	if name == "size" {
		return starlark.MakeInt(l.size), nil
	}
	if name == "decode" {
		return starlark.NewBuiltin("decode", l.decodeBuiltin), nil
	}
	if name == "encode" {
		return starlark.NewBuiltin("encode", l.encodeBuiltin), nil
	}
	return nil, nil
}
func (l *binaryLayout) decodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	offset := 0
	if err := starlark.UnpackArgs("decode", args, kwargs, "value", &value, "offset?", &offset); err != nil {
		return nil, err
	}
	view, err := newBinaryByteView(value)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if offset < 0 || int64(l.size) > view.size-int64(offset) {
		return nil, fmt.Errorf("decode: record exceeds input")
	}
	data := make([]byte, l.size)
	_, _ = view.ReadAt(data, int64(offset))
	pos := 0
	values := make([]starlark.Value, len(l.fields))
	names := make([]string, len(l.fields))
	for i, field := range l.fields {
		chunk := data[pos : pos+field.size]
		pos += field.size
		names[i] = field.name
		switch field.code {
		case 's':
			values[i] = starlark.Bytes(bytes.Clone(chunk))
		case 'b':
			values[i] = starlark.MakeInt(int(int8(chunk[0])))
		case 'B':
			values[i] = starlark.MakeInt(int(chunk[0]))
		case 'h':
			values[i] = starlark.MakeInt(int(int16(l.order.Uint16(chunk))))
		case 'H':
			values[i] = starlark.MakeInt(int(l.order.Uint16(chunk)))
		case 'i':
			values[i] = starlark.MakeInt64(int64(int32(l.order.Uint32(chunk))))
		case 'I':
			values[i] = starlark.MakeUint64(uint64(l.order.Uint32(chunk)))
		case 'q':
			values[i] = starlark.MakeInt64(int64(l.order.Uint64(chunk)))
		case 'Q':
			values[i] = starlark.MakeUint64(l.order.Uint64(chunk))
		}
	}
	return &binaryRecord{names: names, values: values}, nil
}

func (l *binaryLayout) encodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("encode", args, kwargs, "values", &input); err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(l.fields))
	switch input := input.(type) {
	case *binaryRecord:
		for index, field := range l.fields {
			value, err := input.Attr(field.name)
			if err != nil || value == nil {
				return nil, fmt.Errorf("encode: record has no field %q", field.name)
			}
			values[index] = value
		}
	case *starlark.Dict:
		for index, field := range l.fields {
			value, found, err := input.Get(starlark.String(field.name))
			if err != nil {
				return nil, fmt.Errorf("encode: field %q: %w", field.name, err)
			}
			if !found {
				return nil, fmt.Errorf("encode: missing field %q", field.name)
			}
			values[index] = value
		}
	case starlark.Tuple:
		if len(input) != len(values) {
			return nil, fmt.Errorf("encode: got %d values, want %d", len(input), len(values))
		}
		copy(values, input)
	case *starlark.List:
		if input.Len() != len(values) {
			return nil, fmt.Errorf("encode: got %d values, want %d", input.Len(), len(values))
		}
		for index := range values {
			values[index] = input.Index(index)
		}
	default:
		return nil, fmt.Errorf("encode: got %s, want record, dict, list, or tuple", input.Type())
	}

	data := make([]byte, l.size)
	offset := 0
	for index, field := range l.fields {
		if field.code == 's' {
			raw, err := bytesForBinaryValue(values[index])
			if err != nil {
				return nil, fmt.Errorf("encode: field %q: %w", field.name, err)
			}
			if len(raw) != field.size {
				return nil, fmt.Errorf("encode: field %q has size %d, want %d", field.name, len(raw), field.size)
			}
			copy(data[offset:], raw)
			offset += field.size
			continue
		}
		name := map[byte]string{'b': "i8", 'B': "u8", 'h': "i16", 'H': "u16", 'i': "i32", 'I': "u32", 'q': "i64", 'Q': "u64"}[field.code]
		if field.size > 1 {
			if l.order == binary.LittleEndian {
				name += "le"
			} else {
				name += "be"
			}
		}
		codec, _ := binaryScalarCodecNamed(name)
		encoded, err := codec.encode(values[index])
		if err != nil {
			return nil, fmt.Errorf("encode: field %q: %w", field.name, err)
		}
		copy(data[offset:], encoded)
		offset += field.size
	}
	return starlark.Bytes(data), nil
}

type binaryRecord struct {
	names  []string
	values []starlark.Value
}

func (r *binaryRecord) String() string {
	var b strings.Builder
	b.WriteString("<binary.record")
	for i, n := range r.names {
		fmt.Fprintf(&b, " %s=%s", n, r.values[i])
	}
	b.WriteByte('>')
	return b.String()
}
func (r *binaryRecord) Type() string { return "binary.record" }
func (r *binaryRecord) Freeze() {
	for _, v := range r.values {
		v.Freeze()
	}
}
func (r *binaryRecord) Truth() starlark.Bool  { return starlark.True }
func (r *binaryRecord) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", r.Type()) }
func (r *binaryRecord) Attr(name string) (starlark.Value, error) {
	for i, n := range r.names {
		if n == name {
			return r.values[i], nil
		}
	}
	return nil, nil
}
func (r *binaryRecord) AttrNames() []string { return append([]string(nil), r.names...) }

func binaryConcatBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var parts *starlark.List
	if err := starlark.UnpackArgs("concat", args, kwargs, "parts", &parts); err != nil {
		return nil, err
	}
	extents := make([]filesystemapi.ExtentSpec, 0, parts.Len())
	var size int64
	for i := 0; i < parts.Len(); i++ {
		view, err := newBinaryByteView(parts.Index(i))
		if err != nil {
			return nil, fmt.Errorf("concat: parts[%d]: %w", i, err)
		}
		extents = append(extents, filesystemapi.ExtentSpec{Start: size, Size: view.size, File: view})
		size += view.size
		if size < 0 {
			return nil, fmt.Errorf("concat: size overflow")
		}
	}
	return filesystemapi.NewGeneratedImage("binary.concat", size, extents), nil
}

func binaryExtentsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	var values *starlark.List
	if err := starlark.UnpackArgs("extents", args, kwargs, "size", &size, "extents", &values); err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("extents: size must be non-negative")
	}
	extents := make([]filesystemapi.ExtentSpec, 0, values.Len())
	for i := 0; i < values.Len(); i++ {
		tuple, ok := values.Index(i).(starlark.Tuple)
		if !ok || len(tuple) != 2 {
			return nil, fmt.Errorf("extents: extent %d must be (offset, value)", i)
		}
		var start int64
		if err := starlark.AsInt(tuple[0], &start); err != nil || start < 0 {
			return nil, fmt.Errorf("extents: invalid offset at %d", i)
		}
		view, err := newBinaryByteView(tuple[1])
		if err != nil {
			return nil, fmt.Errorf("extents: extent %d: %w", i, err)
		}
		if start > int64(size) || view.size > int64(size)-start {
			return nil, fmt.Errorf("extents: extent %d exceeds output", i)
		}
		for _, old := range extents {
			if start < old.Start+old.Size && old.Start < start+view.size {
				return nil, fmt.Errorf("extents: extent %d overlaps another extent", i)
			}
		}
		extents = append(extents, filesystemapi.ExtentSpec{Start: start, Size: view.size, File: view})
	}
	return filesystemapi.NewGeneratedImage("binary.extents", int64(size), extents), nil
}

func binaryIntegerMethod(name string) (int, binary.ByteOrder, bool, bool) {
	signed := strings.HasPrefix(name, "i")
	var width int
	switch {
	case strings.HasPrefix(name, "u8") || strings.HasPrefix(name, "i8"):
		width = 1
	case strings.Contains(name, "16"):
		width = 2
	case strings.Contains(name, "32"):
		width = 4
	case strings.Contains(name, "64"):
		width = 8
	default:
		return 0, nil, false, false
	}
	var order binary.ByteOrder = binary.LittleEndian
	if strings.HasSuffix(name, "be") {
		order = binary.BigEndian
	}
	return width, order, signed, true
}
func bytesForBinaryValue(value starlark.Value) ([]byte, error) {
	if view, ok := value.(*binaryByteView); ok {
		data := make([]byte, view.size)
		_, err := view.ReadAt(data, 0)
		if err != nil && err != io.EOF {
			return nil, err
		}
		return data, nil
	}
	return starfile.BytesForValue(value, int64(^uint64(0)>>1))
}

func bytesForBinaryValueLimited(value starlark.Value, maximum int64) ([]byte, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("negative binary size limit")
	}
	switch value := value.(type) {
	case File:
		if value.Size() < 0 {
			return nil, fmt.Errorf("negative file size")
		}
		if value.Size() > maximum {
			return nil, fmt.Errorf("input size %d exceeds limit %d", value.Size(), maximum)
		}
	case starlark.String:
		if int64(len(value)) > maximum {
			return nil, fmt.Errorf("input size %d exceeds limit %d", len(value), maximum)
		}
	case starlark.Bytes:
		if int64(len(value)) > maximum {
			return nil, fmt.Errorf("input size %d exceeds limit %d", len(value), maximum)
		}
	}
	return bytesForBinaryValue(value)
}
func unpackBinaryRange(name string, args starlark.Tuple, kwargs []starlark.Tuple, total int64) (int64, int64, error) {
	offset := 0
	sizeValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs(name, args, kwargs, "offset?", &offset, "size?", &sizeValue); err != nil {
		return 0, 0, err
	}
	if offset < 0 || int64(offset) > total {
		return 0, 0, fmt.Errorf("%s: offset exceeds input", name)
	}
	size := total - int64(offset)
	if sizeValue != starlark.None {
		parsed, err := starlark.AsInt32(sizeValue)
		if err != nil || parsed < 0 {
			return 0, 0, fmt.Errorf("%s: size must be a non-negative int", name)
		}
		size = int64(parsed)
	}
	if size > total-int64(offset) {
		return 0, 0, fmt.Errorf("%s: range exceeds input", name)
	}
	return int64(offset), size, nil
}
func boundedInt(value int64) int {
	if value > int64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}
