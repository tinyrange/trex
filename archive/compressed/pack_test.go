package compressed

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestPackCanonicalDirection(t *testing.T) {
	for _, item := range []struct {
		data []byte
		want string
	}{
		{[]byte{0x1f, 0x1e, 0, 0, 0, 3, 1, 0, 'A', 0x10}, "AAA"},
		{[]byte{0x1f, 0x1e, 0, 0, 0, 4, 2, 1, 0, 'A', 'B', 0x85}, "ABBA"},
	} {
		f, err := Open(&starfile.Bytes{Data: item.data}, "pack", 100)
		if err != nil {
			t.Fatal(err)
		}
		got, err := starfile.ReadAll(f)
		if err != nil || string(got) != item.want {
			t.Fatalf("%q %v", got, err)
		}
		for end := 0; end < len(item.data); end++ {
			if _, err := Open(&starfile.Bytes{Data: item.data[:end]}, "pack", 100); err == nil {
				t.Fatalf("accepted prefix %d", end)
			}
		}
	}
}
func TestPackRejectInvalid(t *testing.T) {
	valid := []byte{0x1f, 0x1e, 0, 0, 0, 3, 1, 0, 'A', 0x10}
	for _, index := range []int{0, 5, 6, 7, 9} {
		b := append([]byte(nil), valid...)
		b[index] ^= 1
		if _, err := Open(&starfile.Bytes{Data: b}, "pack", 100); err == nil {
			t.Fatalf("accepted mutation %d", index)
		}
	}
	if _, err := Open(&starfile.Bytes{Data: append(valid, 0)}, "pack", 100); err == nil {
		t.Fatal("accepted trailing byte")
	}
	if _, err := Open(&starfile.Bytes{Data: valid}, "pack", 2); err == nil {
		t.Fatal("ignored maximum")
	}
}
