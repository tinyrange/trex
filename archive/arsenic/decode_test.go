package arsenic

import "testing"

func TestObservedHeader(t *testing.T) {
	// A bounded header prefix independently decoded in the Starlark REPL.
	c := coder{input: []byte{0x42, 0xc1, 0xd4, 0x72, 0xa6, 0xfd, 0x21, 0xa8}, width: 1 << 25}
	for i := 0; i < 26; i++ {
		c.code = c.code*2 + c.next()
	}
	m := newModel(0, 1, 1, 256)
	if c.bits(m, 8) != 'A' || c.bits(m, 8) != 's' || c.bits(m, 4)+9 != 19 || c.symbol(m) != 0 || c.err != nil {
		t.Fatal("header disagreement", c.err)
	}
}
func TestRejectTruncationAndLimits(t *testing.T) {
	for _, data := range [][]byte{nil, {0}, {0x42, 0xc1, 0xd4, 0x72, 0xa6, 0xfd, 0x21, 0xa8}} {
		if _, err := Decode(data, 1024, 1024); err == nil {
			t.Fatal("accepted incomplete stream")
		}
	}
	if _, err := Decode(nil, -1, 1024); err == nil {
		t.Fatal("negative output limit")
	}
	if _, err := Decode(nil, 1024, 0); err == nil {
		t.Fatal("zero block limit")
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0x42, 0xc1, 0xd4, 0x72, 0xa6, 0xfd, 0x21, 0xa8})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := Decode(data, 65536, 65536)
		if err == nil && len(out) > 65536 {
			t.Fatal("output limit exceeded")
		}
	})
}
