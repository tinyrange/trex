package dmr

import "testing"

func TestGlobalization(t *testing.T) {
	for _, name := range []string{"App", "Global.Taskbar", "A\U0001f600"} {
		for flags := 0; flags < 4; flags++ {
			want := Globalization{name, flags&1 != 0, flags&2 != 0}
			data, err := EncodeGlobalization(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseGlobalization(data)
			if err != nil || got != want {
				t.Fatalf("%+v: %+v %v", want, got, err)
			}
			if le.Uint32(data[8:]) != uint32(flags) || le.Uint32(data[4:]) != 20+le.Uint32(data[12:]) {
				t.Fatal("wire mapping")
			}
		}
	}
	for _, name := range []string{"", "A\x00B", "\xff"} {
		if _, err := EncodeGlobalization(Globalization{ApplicationID: name}); err == nil {
			t.Fatal("accepted invalid ID")
		}
	}
	for _, off := range []int{0, 4, 8, 12, 16} {
		data, _ := EncodeGlobalization(Globalization{ApplicationID: "App"})
		data[off] = 0xff
		if _, err := ParseGlobalization(data); err == nil {
			t.Fatalf("accepted malformed offset %d", off)
		}
	}
	data, _ := EncodeGlobalization(Globalization{ApplicationID: "AA"})
	data[len(data)-1] = 1
	if _, err := ParseGlobalization(data); err == nil {
		t.Fatal("accepted nonzero padding")
	}
}
