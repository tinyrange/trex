package apk

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestScriptDatabaseRetainsHooksAndRegistersTriggers(t *testing.T) {
	var base bytes.Buffer
	writer := tar.NewWriter(&base)
	if err := writer.WriteHeader(&tar.Header{Name: "base.post-install", Mode: 0755, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "base"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	check := "Q1" + base64.StdEncoding.EncodeToString(make([]byte, 20))
	pkg := scriptRegistration{
		name: "example", version: "1-r0", checksum: check,
		scripts:  map[string]storage.Reader{".trigger": &starfile.Bytes{Data: []byte("trigger")}},
		triggers: []string{"/usr/share/example/*"},
	}
	archive, triggers, err := buildScriptDatabase(&starfile.Bytes{Data: base.Bytes()}, "base /bin\n", []scriptRegistration{pkg})
	if err != nil {
		t.Fatal(err)
	}
	if expected := "base /bin\n" + check + " /usr/share/example/*\n"; triggers != expected {
		t.Fatalf("triggers %q, want %q", triggers, expected)
	}
	reader := tar.NewReader(bytes.NewReader(archive))
	for _, want := range []struct{ name, body string }{{"base.post-install", "base"}, {"example-1-r0." + check + ".trigger", "trigger"}} {
		header, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil || header.Name != want.name || string(body) != want.body {
			t.Fatalf("hook %q body %q error %v", header.Name, body, err)
		}
	}
	pkg.triggers = []string{"/path with space"}
	if _, _, err := buildScriptDatabase(&starfile.Bytes{Data: base.Bytes()}, "", []scriptRegistration{pkg}); err == nil || !strings.Contains(err.Error(), "invalid trigger") {
		t.Fatalf("invalid trigger error: %v", err)
	}
}
