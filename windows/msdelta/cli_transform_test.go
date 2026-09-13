package msdelta

import (
	"bytes"
	"testing"
)

func TestCLIMetadataStoresMappedIndexAtSourceWidth(t *testing.T) {
	// vmconnect26100.1591 maps a TypeRef namespace string index0x95af
	// through37773->77149 to0x12f7f. The narrow prepared cell holds0x2f7f;
	// it is neither left unchanged nor allowed to overwrite its next cell.
	for _, width := range []uint8{2, 4} {
		source := make([]byte, 32)
		m := &cliMetadata{CLIPreprocessInfo: &CLIPreprocessInfo{HeapWidths: [3]uint8{width, 2, 2}}}
		m.Rows[1], m.tableOffsets[1], m.rowSizes[1] = 1, 8, 2+2*int(width)
		if width == 2 {
			put16(source, 10, 0x95af)
			put16(source, 12, 7)
		} else {
			put32(source, 10, 0x95af)
			put32(source, 14, 7)
		}
		target := &CLIPreprocessInfo{HeapMaps: [4][]PERiftEntry{
			0: {{Source: 0, Target: 0}, {Source: 7, Target: 9}, {Source: 8, Target: 8}, {Source: 37773, Target: 77149}},
		}}
		dst, want := bytes.Clone(source), bytes.Clone(source)
		if err := transformCLIMetadata(dst, source, m, target, riftTable{}); err != nil {
			t.Fatal(err)
		}
		if width == 2 {
			put16(want, 10, 0x2f7f)
			put16(want, 12, 9)
		} else {
			put32(want, 10, 0x12f7f)
			put32(want, 14, 9)
		}
		if !bytes.Equal(dst, want) {
			t.Fatalf("width%d: got%x, want%x", width, dst, want)
		}
	}
}

func TestCLIRemapMetadataAndSharedSignature(t *testing.T) {
	source := make([]byte, 256)
	m := &cliMetadata{CLIPreprocessInfo: &CLIPreprocessInfo{HeapWidths: [3]uint8{2, 2, 2}}}
	m.Rows[4], m.Rows[10] = 1, 1 // Field, MemberRef share a FieldSig blob.
	m.tableOffsets[4], m.rowSizes[4] = 32, 6
	m.tableOffsets[10], m.rowSizes[10] = 48, 6
	m.Streams[2] = CLIStreamInfo{Offset: 128, Size: 64}
	put16(source, 34, 7)      // name
	put16(source, 36, 1)      // blob
	put16(source, 48, 2<<3|1) // MemberRefParent: TypeRef RID2
	put16(source, 50, 7)
	put16(source, 52, 1)
	copy(source[129:], []byte{3, 6, 0x12, 2<<2 | 1}) // FIELD CLASS TypeRef RID2
	target := &CLIPreprocessInfo{}
	target.HeapMaps[0] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 7, Target: 9}}
	target.HeapMaps[2] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 1, Target: 4}}
	target.TableMaps[1] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 2, Target: 3}}
	target.TableMaps[2] = []PERiftEntry{{Source: 0, Target: 0}, {Source: 2, Target: 5}}
	dst := bytes.Clone(source)
	if err := transformCLIMetadata(dst, source, m, target, riftTable{}); err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(source)
	put16(want, 34, 9)
	put16(want, 50, 9)
	put16(want, 36, 4)
	put16(want, 52, 4)
	put16(want, 48, 3<<3|1)
	want[132] = 5<<2 | 1 // signature uses TypeDef map, not MemberRefParent's TypeRef map
	if !bytes.Equal(dst, want) {
		t.Fatalf("metadata mismatch: got %x, want %x", dst, want)
	}
	if source[132] != 2<<2|1 {
		t.Fatal("source signature mutated")
	}
}

func TestCLICodedIndexesPreserveNullAndReservedTags(t *testing.T) {
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{1: {{Source: 0, Target: 10}}}})
	for _, value := range []uint32{0, 1, 3, 7} {
		if got := r.coded(cliTypeDefOrRef, value); got != value {
			t.Fatalf("%d became %d", value, got)
		}
	}
	if got := r.coded(cliTypeDefOrRef, 2<<2|1); got != 12<<2|1 {
		t.Fatalf("mapped coded index %d", got)
	}
}

func TestCLISignatureBoundsAndWidth(t *testing.T) {
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{2: {{Source: 0, Target: 0}, {Source: 1, Target: 40}}}})
	for _, test := range []struct{ source, want []byte }{
		{[]byte{0x12, 5}, []byte{0x12, 5}}, // mapped RID cannot fit this one-byte token
		{[]byte{0x12, 0x80, 5}, []byte{0x12, 0x80, 161}},
		{[]byte{0x12, 0xc0, 0, 0, 5}, []byte{0x12, 0x80, 161, 0, 5}},
		{[]byte{0x12, 0x80}, []byte{0x12, 0x80}},
		{[]byte{0x12, 0xe0}, []byte{0x12, 0xe0}},
	} {
		dst := bytes.Clone(test.source)
		w := cliSignature{source: test.source, dst: dst, remap: &r}
		w.typ(0)
		if !bytes.Equal(dst, test.want) {
			t.Fatalf("%x became %x, want %x", test.source, dst, test.want)
		}
	}
	source := append(bytes.Repeat([]byte{0x1d}, 1000), 0x12, 5)
	w := cliSignature{source: source, dst: bytes.Clone(source), remap: &r}
	if w.typ(0) || w.pos > 64 {
		t.Fatal("unbounded recursive signature")
	}
}

func TestCLISignatureNarrowingKeepsTrailingBytesAndSourceCursor(t *testing.T) {
	// AppX26100.9168 maps compressed TypeRef0x81 to0x79. Native writes
	// 79 over8081, leaving81; a four-byte source control becomes79000081.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{2: {{Source: 32, Target: 30}}}})
	for _, token := range [][]byte{{0x80, 0x81}, {0xc0, 0, 0, 0x81}} {
		source := append([]byte{0x12}, token...)
		source = append(source, 0x12, 0x80, 0x81)
		dst, want := bytes.Clone(source), bytes.Clone(source)
		want[1], want[len(token)+2] = 0x79, 0x79
		w := cliSignature{source: source, dst: dst, remap: &r}
		if !w.typ(0) || w.pos != len(token)+1 || !w.typ(0) || w.pos != len(source) {
			t.Fatalf("narrowing changed source cursor: %d", w.pos)
		}
		if !bytes.Equal(dst, want) {
			t.Fatalf("%x became %x, want %x", source, dst, want)
		}
	}
}

func TestCLIMetadataDoesNotRewriteInstructions(t *testing.T) {
	source, m := makeTestCLIImage(t)
	target := &CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{1: {{Source: 1, Target: 2}}}}
	dst := bytes.Clone(source)
	if err := transformCLIMetadata(dst, source, m, target, riftTable{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst[0x500:], source[0x500:]) {
		t.Fatal("metadata transform changed method instructions")
	}
}

func TestCLISignatureGenericMethodCursor(t *testing.T) {
	// Bounded native comparisons of Windows.Security.winmd 26100.1591
	// observe the outer TypeRef changing, but no writes to the generic
	// argument or the following method parameter. Both signatures occur
	// in MethodDef; the first is also shared with MemberRef.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		1: {{Source: 0, Target: 0}, {Source: 95, Target: 96}},
		2: {{Source: 0, Target: 0}, {Source: 95, Target: 105}},
	}})
	for _, test := range []struct {
		name         string
		source, want []byte
	}{
		{
			name:   "generic return",
			source: []byte{0x20, 0, 0x15, 0x12, 0x87, 0x8d, 1, 0x12, 0x81, 0x91},
			want:   []byte{0x20, 0, 0x15, 0x12, 0x87, 0xb5, 1, 0x12, 0x81, 0x91},
		},
		{
			name:   "parameter following generic return",
			source: []byte{0, 1, 0x15, 0x12, 0x87, 0x85, 1, 0x12, 0x85, 0x61, 0x12, 0x87, 0x99},
			want:   []byte{0, 1, 0x15, 0x12, 0x87, 0xad, 1, 0x12, 0x85, 0x61, 0x12, 0x87, 0x99},
		},
		{
			// Windows.Management.winmd continues through arity two and its
			// two arguments, then stops at a later arity-one constructor.
			name:   "arity two continues to later arity one",
			source: []byte{0x20, 7, 0x15, 0x12, 0x82, 0x81, 2, 0x12, 0x49, 0x11, 0x41, 0x12, 0x82, 0x65, 0x15, 0x12, 0x82, 0x85, 1, 0x12, 0x82, 0x65},
			want:   []byte{0x20, 7, 0x15, 0x12, 0x82, 0xa9, 2, 0x12, 0x49, 0x11, 0x41, 0x12, 0x82, 0x8d, 0x15, 0x12, 0x82, 0xad, 1, 0x12, 0x82, 0x65},
		},
		{
			name:   "void cursor does not advance to parameters",
			source: []byte{0, 1, 1, 0x12, 0x82, 0x65},
			want:   []byte{0, 1, 1, 0x12, 0x82, 0x65},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := bytes.Clone(test.source)
			dst := bytes.Clone(test.source)
			w := cliSignature{source: test.source, dst: dst, remap: &r}
			if !w.method(0) {
				t.Fatal("method normalization failed")
			}
			if !bytes.Equal(dst, test.want) {
				t.Fatalf("got %x, want %x", dst, test.want)
			}
			if !bytes.Equal(test.source, original) {
				t.Fatal("source signature mutated")
			}
		})
	}
}

func TestCLISignatureModifiedVoidAndStandaloneFields(t *testing.T) {
	// MMI native.dll26100.8972: native keeps a parameter following modopt
	// VOID unchanged, but changing VOID to I4 reaches that parameter. Its
	// StandAloneSig FIELD blobs map CLASS/PTR/SZARRAY, but stop at BYREF.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		2: {{Source: 0, Target: 0}, {Source: 256, Target: 264}},
	}})
	for _, test := range []struct{ source, want []byte }{
		{[]byte{0, 1, 0x20, 0x3d, 1, 0xf, 0x11, 0x84, 0xcc}, nil},
		{[]byte{0, 1, 0x20, 0x3d, 8, 0xf, 0x11, 0x84, 0xcc}, []byte{0, 1, 0x20, 0x3d, 8, 0xf, 0x11, 0x84, 0xec}},
		{[]byte{6, 0x12, 0x84, 0x10}, []byte{6, 0x12, 0x84, 0x30}},
		{[]byte{6, 0x10, 0x12, 0x84, 0x1c}, nil},
		{[]byte{6, 0xf, 0x12, 0x84, 0x1c}, []byte{6, 0xf, 0x12, 0x84, 0x3c}},
		{[]byte{6, 0x1d, 0x12, 0x84, 0x1c}, []byte{6, 0x1d, 0x12, 0x84, 0x3c}},
		{[]byte{0, 1, 0xf, 1, 0x10, 0x12, 0x84, 0x1c}, []byte{0, 1, 0xf, 1, 0x10, 0x12, 0x84, 0x3c}},
	} {
		want := test.want
		if want == nil {
			want = test.source
		}
		dst := bytes.Clone(test.source)
		w := cliSignature{source: test.source, dst: dst, remap: &r}
		w.method(0)
		if !bytes.Equal(dst, want) {
			t.Fatalf("signature %x became %x, want %x", test.source, dst, want)
		}
	}
}

func TestCLITypeSpecRootCustomModifierStopsNormalization(t *testing.T) {
	// System.Printing GDR KB5120708: TypeSpec row10/blob288 begins
	// 2081b1208291123d. Native's TypeSpec dispatch (kind5) enters its
	// bare type walker, which rejects a root CMOD rather than visiting it.
	// Modifiers at a method's outer type boundary remain supported.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		2: {{Source: 0, Target: 0}, {Source: 64, Target: 71}},
	}})
	for _, modifier := range []byte{0x1f, 0x20} {
		sig := []byte{modifier, 0x81, 0xb1, modifier, 0x82, 0x91, 0x12, 0x3d}
		source := append([]byte{0, byte(len(sig))}, sig...)
		dst := bytes.Clone(source)
		transformCLISignature(dst, source, CLIStreamInfo{Size: uint32(len(source))}, 1, 27, &r)
		if !bytes.Equal(dst, source) {
			t.Fatalf("TypeSpec root modifier transformed: %x -> %x", source, dst)
		}
		method := append([]byte{0, 0}, sig...)
		mapped := bytes.Clone(method)
		w := cliSignature{source: method, dst: mapped, remap: &r}
		w.method(0)
		if mapped[4] != 0xcd || mapped[7] != 0xad {
			t.Fatalf("method modifier control not mapped: %x", mapped)
		}
	}
	// A normal TypeSpec CLASS still remaps its operand.
	source := []byte{0, 3, 0x12, 0x81, 0xb1}
	dst := bytes.Clone(source)
	transformCLISignature(dst, source, CLIStreamInfo{Size: uint32(len(source))}, 1, 27, &r)
	if !bytes.Equal(dst, []byte{0, 3, 0x12, 0x81, 0xcd}) {
		t.Fatalf("ordinary TypeSpec control: %x", dst)
	}
}

func TestCLISignatureTypeRefTagUsesDefinitionMap(t *testing.T) {
	// Native ReFS dedup commands 26100.1591 changes source operands
	// 80a1 -> 8251 and 8095 -> 8245. The distinct TypeRef map would instead
	// produce 80ed and 80e1; a copied high byte affected seven target sites.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		1: {{Source: 0, Target: 0}, {Source: 25, Target: 44}, {Source: 41, Target: 23}},
		2: {{Source: 0, Target: 0}, {Source: 5, Target: 80}, {Source: 30, Target: 138}},
	}})
	for _, test := range []struct{ source, want []byte }{
		{[]byte{0x12, 0x80, 0xa1}, []byte{0x12, 0x82, 0x51}},
		{[]byte{0x11, 0x80, 0x95}, []byte{0x11, 0x82, 0x45}},
		{[]byte{0x15, 0x12, 0x80, 0xa1, 2, 0x0e, 0x1c}, []byte{0x15, 0x12, 0x82, 0x51, 2, 0x0e, 0x1c}},
	} {
		dst := bytes.Clone(test.source)
		w := cliSignature{source: test.source, dst: dst, remap: &r}
		if !w.typ(0) || !bytes.Equal(dst, test.want) {
			t.Fatalf("signature %x became %x, want %x", test.source, dst, test.want)
		}
	}
	if got := r.coded(cliTypeDefOrRef, 0xa1); got != 0xed {
		t.Fatalf("ordinary metadata TypeRef changed maps: got %x", got)
	}
}

func TestCLISignatureLocalVariablesVisitOnlyFirstType(t *testing.T) {
	// Native ReFS commands 26100.1591 leaves LocalVarSig blob154 entirely
	// unchanged. Replacing its first token7d with representable09 still does
	// not visit the later locals, rejecting a width-overflow-stop hypothesis.
	// Blob387 supplies the contrasting first-local write8095 ->8245.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		2: {{Source: 0, Target: 0}, {Source: 5, Target: 80}, {Source: 30, Target: 138}},
	}})
	for _, test := range []struct {
		name         string
		source, want []byte
	}{
		{"first token cannot widen", []byte{7, 8, 0x12, 0x7d, 0x12, 0x80, 0x81, 0x12, 0x80, 0x85, 0x11, 0x80, 0x89, 0x12, 0x5c, 0x11, 0x71, 0x11, 0x80, 0x8d, 0x12, 0x61}, nil},
		{"representable first token", []byte{7, 8, 0x12, 9, 0x12, 0x80, 0x81, 0x12, 0x80, 0x85, 0x11, 0x80, 0x89, 0x12, 0x5c, 0x11, 0x71, 0x11, 0x80, 0x8d, 0x12, 0x61}, nil},
		{"first token remaps", []byte{7, 3, 0x11, 0x80, 0x95, 0x11, 0x80, 0x91, 0x12, 0x61}, []byte{7, 3, 0x11, 0x82, 0x45, 0x11, 0x80, 0x91, 0x12, 0x61}},
		{"no locals", []byte{7, 0}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := test.want
			if want == nil {
				want = test.source
			}
			dst := bytes.Clone(test.source)
			w := cliSignature{source: test.source, dst: dst, remap: &r}
			if !w.method(0) || !bytes.Equal(dst, want) {
				t.Fatalf("local signature became %x, want %x", dst, want)
			}
		})
	}
}

func TestCLISignatureFunctionPointerStopsEnclosingWalk(t *testing.T) {
	// AppX commands26100.1591: native leaves tokens in FNPTR signatures
	// unchanged, while a separate ordinary method signature maps them.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		2: {{Source: 0, Target: 0}, {Source: 2, Target: 6}},
	}})
	for _, test := range []struct {
		name         string
		source, want []byte
		ok           bool
	}{
		{"function pointer return", []byte{0, 1, 0x1b, 0, 1, 0x12, 9, 0x12, 9, 0x12, 9}, nil, false},
		{"function pointer parameter", []byte{0, 2, 8, 0x1b, 0, 1, 0x12, 9, 0x12, 9, 0x12, 9}, nil, false},
		{"ordinary method", []byte{0, 1, 0x12, 9, 0x12, 9}, []byte{0, 1, 0x12, 25, 0x12, 25}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := test.want
			if want == nil {
				want = test.source
			}
			dst := bytes.Clone(test.source)
			w := cliSignature{source: test.source, dst: dst, remap: &r}
			if ok := w.method(0); ok != test.ok || !bytes.Equal(dst, want) {
				t.Fatalf("signature became %x (ok=%t), want %x (ok=%t)", dst, ok, want, test.ok)
			}
		})
	}
}

func TestCLISignatureGenericMethodArityIsParameterCount(t *testing.T) {
	// tzsync.exe26100.1591 MemberRef168: native leaves the signature
	// untouched. Changing the actual parameter count1 ->2 makes the native
	// walker consume a boolean and then rewrite80bd ->81d5. Thus the generic
	// flag is not a rejection condition: arity is consumed as parameter count.
	r := newCLIRemap(&CLIPreprocessInfo{TableMaps: [64][]PERiftEntry{
		2: {{Source: 0, Target: 0}, {Source: 12, Target: 20}, {Source: 17, Target: 87}, {Source: 59, Target: 162}},
	}})
	for _, test := range []struct{ source, want []byte }{
		{[]byte{0x10, 1, 1, 0x15, 0x12, 0x80, 0xbd, 1, 0x1e, 0, 0x15, 0x12, 0x80, 0xe5, 1, 0x1e, 0}, nil},
		{[]byte{0x10, 1, 2, 0x15, 0x12, 0x80, 0xbd, 1, 0x1e, 0, 0x15, 0x12, 0x80, 0xe5, 1, 0x1e, 0}, []byte{0x10, 1, 2, 0x15, 0x12, 0x81, 0xd5, 1, 0x1e, 0, 0x15, 0x12, 0x80, 0xe5, 1, 0x1e, 0}},
	} {
		want := test.want
		if want == nil {
			want = test.source
		}
		dst := bytes.Clone(test.source)
		w := cliSignature{source: test.source, dst: dst, remap: &r}
		if !w.method(0) || !bytes.Equal(dst, want) {
			t.Fatalf("generic method became %x, want %x", dst, want)
		}
	}
}
