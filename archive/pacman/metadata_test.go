package pacman

import (
	"strings"
	"testing"
)

func TestInstalledRecordsFromSyncMetadata(t *testing.T) {
	fields, err := readRecord(strings.NewReader("%NAME%\nxfce4-panel\n\n%VERSION%\n4.20.8-1\n\n%ARCH%\nx86_64\n\n%ISIZE%\n1024\n\n%DEPENDS%\ngtk3\nlibxfce4ui\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	desc, files, err := installedRecords(fields, []string{"usr/bin/xfce4-panel"}, []string{"etc/example\tabcd"}, true)
	if err != nil || !strings.Contains(desc, "%SIZE%\n1024\n") || !strings.Contains(desc, "%REASON%\n0\n") || !strings.Contains(desc, "%DEPENDS%\ngtk3\nlibxfce4ui\n") {
		t.Fatalf("desc %q error %v", desc, err)
	}
	if want := "%FILES%\nusr/bin/xfce4-panel\n\n%BACKUP%\netc/example\tabcd\n\n"; files != want {
		t.Fatalf("files %q want %q", files, want)
	}
}

func TestVersionOrdering(t *testing.T) {
	for _, pair := range [][2]string{{"1.0a", "1.0b"}, {"1.0rc", "1.0"}, {"1.0", "1.0.a"}, {"1.0.a", "1.0.1"}, {"1.5-1", "1.5-2"}, {"1:3.6-1", "2:1.0-1"}} {
		if compareVersion(pair[0], pair[1]) >= 0 || compareVersion(pair[1], pair[0]) <= 0 {
			t.Fatalf("invalid ordering for %q and %q", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{{"1.5-1", "1.5"}, {"6.01", "6.1"}} {
		if compareVersion(pair[0], pair[1]) != 0 {
			t.Fatalf("expected equal ordering for %q and %q", pair[0], pair[1])
		}
	}
}
