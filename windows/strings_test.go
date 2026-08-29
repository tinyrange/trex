package windows

import (
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
