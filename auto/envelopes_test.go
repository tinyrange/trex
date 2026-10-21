package auto_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"testing"
)

func TestZIPExecutableEnvelope(t *testing.T) {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.Create("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("payload"))
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	stub := make([]byte, 130001)
	copy(stub, "MZ")
	data := append(stub, b.Bytes()...)
	n := auto.Open(&starfile.Bytes{Data: data}, "setup.exe", auto.Options{})
	child, err := n.Resolve("payload.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(child.Reader(), 0, child.Reader().Size()))
	if err != nil || string(got) != "payload" {
		t.Fatalf("%q %v", got, err)
	}
	for _, data := range [][]byte{stub, append(bytes.Clone(stub), []byte("PK\x03\x04not a ZIP")...)} {
		if _, err := auto.Identify(&starfile.Bytes{Data: data}, auto.Options{}); !errors.Is(err, auto.ErrNoMatch) {
			t.Fatalf("ordinary executable: %v", err)
		}
	}
}
func TestZeroSectorsAreNotTAR(t *testing.T) {
	data := &starfile.Bytes{Data: make([]byte, 4096)}
	if _, err := auto.Identify(data, auto.Options{}); !errors.Is(err, auto.ErrNoMatch) {
		t.Fatalf("zero partition: %v", err)
	}
	r, err := auto.Identify(data, auto.Options{Source: &auto.SourceContext{Path: "empty.tar"}})
	if err != nil || r.Format != "tar" {
		t.Fatalf("explicit empty tar: %v %v", r, err)
	}
}
