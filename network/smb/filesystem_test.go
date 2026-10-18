package smb

import "testing"

func TestSharePathNamespaces(t *testing.T) {
	for _, name := range []string{"../x", "x/../y", `\\server\share`, `C:\file`, "a:b", "a//b", "NUL.txt", "COM1", "LPT9.x", "bad.", "bad ", "x\x00y", "x?", "x*"} {
		if _, e := SharePath(name); e == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for name, want := range map[string]string{"": ".", `dir\file.txt`: "dir/file.txt", "normal.txt": "normal.txt", "日本語": "日本語"} {
		if got, e := SharePath(name); e != nil || got != want {
			t.Fatal(name, got, e)
		}
	}
}
