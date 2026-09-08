package windows

import (
	"bytes"
	"io"
	"testing"
)

type memoryTestReader struct{ *bytes.Reader }

func (r memoryTestReader) Size() int64 { return r.Reader.Size() }
func TestMemoryViewReadOnly(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	v := &memoryViewFile{reader: memoryTestReader{bytes.NewReader(data)}, offset: 1, size: 2}
	if _, err := v.WriteAt([]byte{99}, 0); err == nil {
		t.Fatal("write accepted")
	}
	out := make([]byte, 3)
	n, err := v.ReadAt(out, 0)
	if n != 2 || err != io.EOF || !bytes.Equal(out[:n], []byte{2, 3}) || data[1] != 2 {
		t.Fatal(n, err, out, data)
	}
	if n, err := v.ReadAt(nil, 2); n != 0 || err != nil {
		t.Fatal(n, err)
	}
}
