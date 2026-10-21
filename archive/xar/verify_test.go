package xar

import (
	"bytes"
	"compress/zlib"
	"io"
	"testing"
)

func TestEmptyZlibVerification(t *testing.T) {
	for _, bad := range []bool{false, true} {
		var b bytes.Buffer
		z := zlib.NewWriter(&b)
		z.Close()
		if bad {
			b.Bytes()[b.Len()-1] ^= 1
		}
		e := Entry{Data: &zlibFile{source: bytes.NewReader(b.Bytes())}}
		err := e.Verify()
		if (err != nil) != bad {
			t.Fatalf("empty zlib bad=%v: %v", bad, err)
		}
	}
}
func TestNoChecksumStillReadsAllBytes(t *testing.T) {
	e := Entry{Data: io.NewSectionReader(bytes.NewReader([]byte("x")), 0, 3)}
	// SectionReader can end early: full declared-size validation must catch it.
	if err := e.Verify(); err == nil {
		t.Fatal("accepted truncated checksum-free member")
	}
}
