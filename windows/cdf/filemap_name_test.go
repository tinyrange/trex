package cdf

import "testing"

func TestNativeFileMapNames(t *testing.T) {
	// Independent WCP b5948 captures with Windows root C:\Windows.
	cases := [][2]string{
		{"/a_b", "a_b_00006e8dffff62a4.cdf-ms"},
		{"/a__b", "a_b_00006ec7ffff61e1.cdf-ms"},
		{"/_abc", "_abc_0000abb9ffff03fb.cdf-ms"},
		{"/abc_", "abc__000072a3ffff59cd.cdf-ms"},
		{"/a b", "a_b_00007769ffff4eb5.cdf-ms"},
		{"/a!b", "a_b_00007745ffff4f06.cdf-ms"},
		{"/a(b)", "a_b__00007649ffff5166.cdf-ms"},
		{"/abc.", "abc..cdf-ms"},
		{"/.abc", ".abc.cdf-ms"},
		{"/a-b", "a-b.cdf-ms"},
		{"/a$b", "a$b.cdf-ms"},
		{"/a/b", "a_b_00006ef9ffff61b1.cdf-ms"},
		{"/axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.cdf-ms"},
		{"/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.cdf-ms"},
		{"/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_ba45f7d710506318.cdf-ms"},
		{"/WindowsOld/a", "windowsold_a_1ded901d6040ac09.cdf-ms"},
		{"/Windows/a", "$$_a_00003fffffffa1e5.cdf-ms"},
		{"/", "_0000000000000000.cdf-ms"},
		{"/Windows", "$$.cdf-ms"},
		{"/Windows/Globalization/Time Zone", "$$_globalization_time_zone_08f498d155d3913e.cdf-ms"},
		{"/Windows/System32/NarratorMCAT/Rules/Languages/de", "$$_system32_narratormcat_rules_languages_de_22a253410d8d9cb7.cdf-ms"},
	}
	for _, c := range cases {
		got, e := FileMapName(c[0], "/Windows")
		if e != nil || got != c[1] {
			t.Fatalf("%q: %q, %v; want %q", c[0], got, e, c[1])
		}
	}
	for _, p := range []string{"", "relative", "/Windows/", "/a//b", "/a/../b", "/a/./b", "/C:/a", "/a\\b", "/é", "/a\x00b"} {
		if _, e := FileMapName(p, "/Windows"); e == nil {
			t.Fatalf("accepted unsupported path %q", p)
		}
	}
	if _, e := FileMapName("/a", "/"); e == nil {
		t.Fatal("accepted drive root as Windows root")
	}
	got, e := FileMapName("/wInNt/a", "/WinNT")
	if e != nil || got != "$$_a_00003fffffffa1e5.cdf-ms" {
		t.Fatal(got, e)
	}
}
