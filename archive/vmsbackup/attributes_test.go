package vmsbackup

import "testing"

func TestAttributes(t *testing.T) {
	data := []byte{1, 1, 3, 0, 42, 0, 'A', ';', '1', 2, 0, 52, 0, 9, 8, 0, 0, 42, 0, 0, 0}
	a, err := ParseAttributes(data, 10)
	if err != nil || len(a) != 3 || a[0].Kind != 42 || string(a[0].Data) != "A;1" || a[1].Data[0] != 9 || a[2].Kind != 42 || len(a[2].Data) != 0 {
		t.Fatal(a, err)
	}
	data[6] = 'Z'
	if string(a[0].Data) != "A;1" {
		t.Fatal("mutable metadata alias")
	}
	for _, bad := range [][]byte{{1}, {1, 2}, {1, 1, 1}, {1, 1, 2, 0, 42, 0, 1}} {
		if _, err := ParseAttributes(bad, 10); err == nil {
			t.Fatal("accepted truncation/version", bad)
		}
	}
	if _, err := ParseAttributes(data, 1); err == nil {
		t.Fatal("limit")
	}
}

func FuzzAttributes(f *testing.F) {
	f.Add([]byte{1, 1, 3, 0, 42, 0, 'A', ';', '1'})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseAttributes(b, 100) })
}
