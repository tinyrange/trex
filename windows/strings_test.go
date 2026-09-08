package windows

import (
	"bytes"
	"reflect"
	"testing"
)

func TestScanUTF16Strings(t *testing.T) {
	data := append([]byte{0xff}, utf16Nul(`%systemroot%\system32\example.dll`)...)
	data = append(data, utf16Nul("no")...)
	got := scanUTF16Strings(data, 4)
	want := []string{`%systemroot%\system32\example.dll`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scanUTF16Strings() = %q, want %q", got, want)
	}
}

func TestScanUTF16StringsScratchOwnership(t *testing.T) {
	var data []byte
	for _, value := range []string{"first long string", "second", "first long string", "last"} {
		data = append(data, utf16Nul(value)...)
	}
	got := scanUTF16Strings(data, 4)
	want := []string{"first long string", "second", "last"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func BenchmarkScanUTF16RejectedCandidates(b *testing.B) {
	data := bytes.Repeat([]byte{0x41, 0, 0, 0}, 1<<16)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		scanUTF16Strings(data, 4)
	}
}
