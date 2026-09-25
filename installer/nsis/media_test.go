package nsis_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/installer/installshield"
	"io"
	"os"
	"testing"

	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/filesystem/iso9660"
	"github.com/tinyrange/trex/installer/nsis"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

type mediaSource struct {
	*os.File
	size int64
}

func (f mediaSource) Size() int64 { return f.size }

type countedSource struct {
	storage.Reader
	reads int64
}

func (f *countedSource) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.Reader.ReadAt(p, off)
	f.reads += int64(n)
	return n, err
}

// Media is caller supplied, never downloaded or redistributed. This exercises
// the parser and native ISO reader together, without executing the PE program.
func TestNetscapeMedia(t *testing.T) {
	name := os.Getenv("TREX_NSIS_TEST_ISO")
	if name == "" {
		t.Skip("set TREX_NSIS_TEST_ISO to the PCWorld NZ September 2005 ISO")
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	image, err := iso9660.ISO9660Builtin(nil, nil, starlark.Tuple{adapter.File(mediaSource{f, info.Size()})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := image.(starlark.Mapping).Get(starlark.String("/browsers/Netscape 8.0.2/nsb-install-8-0.exe"))
	if err != nil || !found {
		t.Fatalf("installer not found: %v", err)
	}
	source := value.(storage.Reader)
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(source, 0, source.Size())); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", hash.Sum(nil)); got != "4defa5ecfc51442b26ddfb99c025b8e1c9b721a3059554f6e97b70eca3249bcd" {
		t.Fatalf("wrong installer digest: %s", got)
	}
	counted := &countedSource{Reader: source}
	listing, err := nsis.List(counted, nsis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if listing.HeaderOffset != 37888 || listing.HeaderSize != 110680 || listing.DataOffset != 68594 || listing.HeaderCompression != "deflate" || listing.Instructions != 1715 || len(listing.Entries) != 561 {
		t.Fatalf("unexpected listing: header=%d/%d/%s data=%d instructions=%d files=%d", listing.HeaderOffset, listing.HeaderSize, listing.HeaderCompression, listing.DataOffset, listing.Instructions, len(listing.Entries))
	}
	first := listing.Entries[0]
	if first.Instruction != 237 || first.Name != "netscape1.ico" || first.OutputDirectory != "$INSTDIR" || first.PackedSize != 12525 || !first.Compressed {
		t.Fatalf("first file: %+v", first)
	}
	empty := false
	for _, entry := range listing.Entries {
		if entry.Name == ".autoreg" && entry.Instruction == 247 && !entry.Compressed && entry.PackedSize == 0 {
			empty = true
		}
	}
	if !empty {
		t.Fatal("missing empty .autoreg file")
	}
	if counted.reads > 64<<10 {
		t.Fatalf("listing read %d bytes; metadata-only budget exceeded", counted.reads)
	}
	archive, err := nsis.Open(source, nsis.Options{}, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	total := int64(0)
	for _, entry := range archive.Listing.Entries {
		file, ok, err := archive.Get(starlark.String(nsis.MemberName(entry)))
		if err != nil || !ok {
			t.Fatalf("missing member %d: %v", entry.Instruction, err)
		}
		total += file.(storage.Reader).Size()
	}
	if total != 36483079 {
		t.Fatalf("decoded bytes %d", total)
	}
	plan, err := archive.Plan(map[string]string{"<TARGETDIR>": `C:\Program Files\Netscape\Netscape Browser`}, nil, []nsis.CodeRange{{236, 1163}})
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := plan.Get(starlark.String("files"))
	unknown, _, _ := plan.Get(starlark.String("unresolved"))
	if files.(*starlark.List).Len() != 540 || unknown.(*starlark.List).Len() != 0 {
		t.Fatalf("plan %s", plan)
	}
	// Shared dispatch must expose readable payload files and preserve recognition
	// when an expansion budget, rather than format detection, rejects the input.
	installer, err := installshield.InstallerBuiltin(nil, nil, starlark.Tuple{value}, nil)
	if err != nil {
		t.Fatal(err)
	}
	format, _ := installer.(starlark.HasAttrs).Attr("format")
	if format != starlark.String("nsis") {
		t.Fatalf("format %s", format)
	}
	probe, err := installshield.ProbeBuiltin(nil, nil, starlark.Tuple{value}, []starlark.Tuple{{starlark.String("maximum_bytes"), starlark.MakeInt(1 << 20)}})
	if err != nil {
		t.Fatal(err)
	}
	recognized, _, _ := probe.(*starlark.Dict).Get(starlark.String("recognized"))
	supported, _, _ := probe.(*starlark.Dict).Get(starlark.String("supported"))
	if recognized != starlark.True || supported != starlark.False {
		t.Fatalf("probe %s", probe)
	}
	detected, err := auto.Identify(source, auto.Options{})
	if err != nil || detected == nil {
		t.Fatalf("auto: %v", err)
	}
	if _, err := auto.Identify(source, auto.Options{MaxExpandedBytes: 1 << 20}); !errors.Is(err, nsis.ErrLimit) {
		t.Fatalf("auto expansion bound: %v", err)
	}
	t.Logf("listed %d entries with %d source bytes read", len(listing.Entries), counted.reads)
}
