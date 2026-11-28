package sharedmime

import (
	"bytes"
	"strings"
	"testing"
)

func TestCompileMatchesAndGlobs(t *testing.T) {
	source := `<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="image/png">
    <glob pattern="*.png"/>
    <glob pattern="*.PNG" weight="80" case-sensitive="true"/>
    <alias type="image/x-png"/>
    <generic-icon name="image-x-generic"/>
    <magic priority="70">
      <match type="string" offset="0" value="\x89PNG\r\n\032\n">
        <match type="host16" offset="8:10" value="0xa1b2" mask="0xfff0"/>
      </match>
    </magic>
  </mime-type>
</mime-info>`
	files, err := Compile(strings.NewReader(source))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("MIME-Magic\x00\n[70:image/png]\n>0=\x00\x08\x89PNG\r\n\x1a\n\n1>8=\x00\x02\xa1\xb2&\xff\xf0~2+3\n")
	if !bytes.Equal(files["magic"], want) {
		t.Fatalf("magic = %q, want %q", files["magic"], want)
	}
	for name, want := range map[string]string{
		"globs2":        "50:image/png:*.png\n80:image/png:*.PNG:cs\n",
		"aliases":       "image/x-png image/png\n",
		"generic-icons": "image/png:image-x-generic\n",
	} {
		if got := string(files[name]); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestStringMaskFillsUnspecifiedNibblesWithZero(t *testing.T) {
	_, mask, _, err := matchBytes(match{Type: "string", Value: "REM", Mask: "0x5f5f5"})
	if err != nil || !bytes.Equal(mask, []byte{0x5f, 0x5f, 0x50}) {
		t.Fatalf("mask = %x: %v", mask, err)
	}
}
