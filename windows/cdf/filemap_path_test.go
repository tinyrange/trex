package cdf

import "testing"

func TestFileMapPathNative(t *testing.T) {
	// Independent AdjustMapParentDirectory b4d60 captures from WCP 26100.9441.
	for _, tc := range []struct {
		input, path string
		selector    uint32
	}{
		{"/", `\??\C:`, 0},
		{"/Windows", "", 1},
		{"/Windows/System32", "System32", 1},
		{"/Program Files", "Program Files", 2},
		{"/WINDOWS/System32", "System32", 1},
		{"/WindowsOther", "Other", 1},
	} {
		path, selector, err := FileMapPath(tc.input, "/Windows", "C:")
		if err != nil || path != tc.path || selector != tc.selector {
			t.Errorf("%s: (%q,%d,%v), want (%q,%d)", tc.input, path, selector, err, tc.path, tc.selector)
		}
	}
}

func TestFileMapPathRejectsAmbiguity(t *testing.T) {
	for _, tc := range [][3]string{
		{"relative", "/Windows", "C:"}, {"/Windows/../x", "/Windows", "C:"},
		{"/Windows/", "/Windows", "C:"}, {"/Wíndows", "/Windows", "C:"},
		{"/Windows", "/", "C:"}, {"/Windows", "/Windows/", "C:"},
		{"/", "/Windows", ""}, {"/", "/Windows", `C:\`},
		{"/", "/Windows", "1:"},
	} {
		if _, _, err := FileMapPath(tc[0], tc[1], tc[2]); err == nil {
			t.Errorf("accepted %q", tc)
		}
	}
}
