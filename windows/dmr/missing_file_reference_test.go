package dmr

import "testing"

func TestMissingFileResourceReference(t *testing.T) {
	for _, tc := range []struct{ root, name, want string }{
		{`C:\Package\`, `\Assets\logo.png`, `C:\Package\Assets\logo.png`},
		{`C:\Package`, `http://microsoft.com`, `C:\Package\http:\\microsoft.com`},
		{`C:/Package/`, `/logo.png`, `C:\Package\\\logo.png`},
		{`C:\Package`, `../logo.png`, `C:\Package\..\logo.png`},
		{"", `\logo.png`, `logo.png`},
	} {
		data, err := EncodeMissingFileResourceReference(tc.root, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseLiteralResourceReference(data)
		if err != nil || got != tc.want {
			t.Fatalf("(%q,%q): %q, %v; want %q", tc.root, tc.name, got, err, tc.want)
		}
	}
	for _, name := range []string{"", "bad\x00name", "\xff"} {
		if _, err := EncodeMissingFileResourceReference(`C:\Package`, name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
