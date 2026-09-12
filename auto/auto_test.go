package auto_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"sync"
	"testing"

	"github.com/tinyrange/trex/auto"
	_ "github.com/tinyrange/trex/auto/imports"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func nested(t *testing.T) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	w, err := zw.Create("test.txt")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("hello nested world"))
	zw.Close()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "etc/blah.zip", Mode: 0644, Size: int64(z.Len())}); err != nil {
		t.Fatal(err)
	}
	tw.Write(z.Bytes())
	tw.Close()
	gz.Close()
	return b.Bytes()
}
func TestNestedContainersAndRawBytes(t *testing.T) {
	data := nested(t)
	root := auto.Open(&starfile.Bytes{Data: data}, "blah.tar.gz", auto.Options{})
	metadata, err := root.Metadata()
	if err != nil || metadata.Format != "gzip" {
		t.Fatalf("metadata=%+v %v", metadata, err)
	}
	file, err := root.Resolve("etc/blah.zip/test.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(file.Reader(), 0, file.Reader().Size()))
	if err != nil || string(got) != "hello nested world" {
		t.Fatalf("read=%q %v", got, err)
	}
	raw, err := starfile.ReadAll(root.Reader())
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatal("raw compressed file changed", err)
	}
	for _, p := range []string{"etc/../test", "../etc", "etc//blah", "etc\\blah", "etc/\x00"} {
		if _, err := root.Resolve(p); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("path %q: %v", p, err)
		}
	}
	if _, err := root.Resolve("etc/missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}
func TestUnknownMalformedAndLimits(t *testing.T) {
	ordinary := auto.Open(&starfile.Bytes{Data: []byte("ordinary text")}, "fake.zip", auto.Options{})
	m, err := ordinary.Metadata()
	if err != nil || m.Container {
		t.Fatalf("extension used as confirmation: %+v %v", m, err)
	}
	malformed := auto.Open(&starfile.Bytes{Data: []byte("PK\x03\x04truncated")}, "file", auto.Options{})
	if _, err := malformed.Metadata(); err == nil {
		t.Fatal("malformed zip accepted")
	}
	limited := auto.Open(&starfile.Bytes{Data: nested(t)}, "data", auto.Options{MaxExpandedBytes: 64})
	if _, err := limited.Metadata(); !errors.Is(err, auto.ErrLimit) {
		t.Fatalf("limit: %v", err)
	}
}
func TestEmptyDirectoriesAndLinks(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range []*tar.Header{{Name: "empty/", Typeflag: tar.TypeDir}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../../outside"}} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	root := auto.Open(&starfile.Bytes{Data: b.Bytes()}, "data", auto.Options{})
	empty, err := root.Resolve("empty")
	if err != nil {
		t.Fatal(err)
	}
	children, err := empty.Children()
	if err != nil || len(children) != 0 {
		t.Fatal(children, err)
	}
	link, err := root.Resolve("link")
	if err != nil || link.Reader() != nil {
		t.Fatal("symlink followed", err)
	}
}

// A consumer can link a detector without changing auto or auto/imports.
func init() {
	auto.Register("test-prefix", 0, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("AUTO-REGISTRY-TEST")) {
			return nil, auto.ErrNoMatch
		}
		return auto.ViewFunc(func() ([]auto.Entry, error) {
			return []auto.Entry{{Name: "prefix", Kind: "file", Reader: &starfile.Bytes{Data: prefix}}}, nil
		}), nil
	})
}

type observedReader struct {
	starfile.Bytes
	reads   int
	largest int
}

func (r *observedReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	if len(p) > r.largest {
		r.largest = len(p)
	}
	return r.Bytes.ReadAt(p, off)
}
func TestRegistryPrefixAndConsumerRegistration(t *testing.T) {
	source := &observedReader{Bytes: starfile.Bytes{Data: make([]byte, 100000)}}
	copy(source.Data, "AUTO-REGISTRY-TEST")
	result, err := auto.Identify(source, auto.Options{})
	if err != nil || result.Format != "test-prefix" {
		t.Fatal(result, err)
	}
	entries, err := result.View.Entries()
	if err != nil || entries[0].Reader.Size() != 64<<10 || source.reads != 1 || source.largest != 64<<10 {
		t.Fatalf("prefix reads=%d largest=%d entries=%v error=%v", source.reads, source.largest, entries, err)
	}
}

func TestConcurrentNestedViews(t *testing.T) {
	root := auto.Open(&starfile.Bytes{Data: nested(t)}, "nested", auto.Options{})
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			file, err := root.Resolve("etc/blah.zip/test.txt")
			if err != nil {
				t.Error(err)
				return
			}
			data, err := starfile.ReadAll(file.Reader())
			if err != nil || string(data) != "hello nested world" {
				t.Errorf("concurrent read %q %v", data, err)
			}
		}()
	}
	group.Wait()
}
