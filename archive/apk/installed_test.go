package apk

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestWriteInstalledOwnershipAndHardlinks(t *testing.T) {
	data := &starfile.Bytes{Data: []byte("program")}
	fields := map[string]string{
		"C": "Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "P": "demo", "V": "1.0-r0", "A": "x86_64",
		"S": "10", "I": "7", "D": "so:libc.musl-x86_64.so.1",
	}
	payload := []unixfs.Entry{
		{Path: "usr/bin/demo", Mode: unixfs.Regular | 0755, Data: data},
		{Path: "usr/bin/demo-link", Mode: unixfs.Regular | 0755, Target: "usr/bin/demo", Hardlink: true},
		{Path: "demo", Mode: unixfs.Symlink | 0777, Target: "usr/bin/demo"},
	}
	var output bytes.Buffer
	if err := WriteInstalled(&output, []InstalledPackage{{Fields: fields, Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	program := sha1.Sum(data.Data)
	checksum := base64.StdEncoding.EncodeToString(program[:])
	want := "D:so:libc.musl-x86_64.so.1\n"
	if !strings.Contains(output.String(), want) ||
		!strings.Contains(output.String(), "F:\nR:demo\na:0:0:777\nZ:Q1") ||
		!strings.Contains(output.String(), "F:usr/bin\nR:demo\na:0:0:755\nZ:Q1"+checksum+"\nR:demo-link\na:0:0:755\nZ:Q1"+checksum+"\n") {
		t.Fatalf("bad installed database:\n%s", output.String())
	}
	fields["D"] += "\nP:injected"
	output.Reset()
	if err := WriteInstalled(&output, []InstalledPackage{{Fields: fields, Payload: payload}}); err == nil || output.Len() != 0 {
		t.Fatal("invalid field was not rejected atomically")
	}
}
