package mds

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func fixture() ([]byte, []byte) {
	b := make([]byte, 320)
	copy(b, "MEDIA DESCRIPTOR")
	b[16], b[17] = 1, 5
	le := binary.LittleEndian
	le.PutUint16(b[20:], 1)
	le.PutUint32(b[80:], 88)
	s := b[88:112]
	le.PutUint32(s[4:], 3)
	le.PutUint16(s[8:], 1)
	s[10] = 2
	le.PutUint16(s[12:], 1)
	le.PutUint16(s[14:], 2)
	le.PutUint32(s[20:], 112)
	for j := 0; j < 2; j++ {
		t := b[112+j*80:]
		t[0], t[1], t[4] = 0xaa, 8, byte(j+1)
		le.PutUint32(t[12:], uint32(272+j*8))
		le.PutUint16(t[16:], 2448)
		le.PutUint32(t[48:], 1)
		le.PutUint32(t[52:], 288)
		le.PutUint32(b[272+j*8+4:], uint32(2-j))
	}
	b[192] = 0xa9
	le.PutUint32(b[192+36:], 2)
	le.PutUint64(b[192+40:], 4896)
	le.PutUint32(b[288:], 304)
	le.PutUint32(b[292:], 1)
	for j, c := range "*.mdf" {
		le.PutUint16(b[304+j*2:], uint16(c))
	}
	raw := make([]byte, 3*2448)
	for sector := 0; sector < 3; sector++ {
		for j := 0; j < 2352; j++ {
			raw[sector*2448+j] = byte('A' + sector)
		}
		for j := 2352; j < 2448; j++ {
			raw[sector*2448+j] = byte('a' + sector)
		}
	}
	return b, raw
}

func TestTrackPayloadAndSubchannels(t *testing.T) {
	b, raw := fixture()
	image, err := Open(&starfile.Bytes{Data: b})
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Sessions) != 1 || len(image.Sessions[0].Tracks) != 2 {
		t.Fatal(image)
	}
	b[114] = 0x14
	controlImage, err := Open(&starfile.Bytes{Data: b})
	if err != nil || controlImage.Sessions[0].Tracks[0].ADR != 1 || controlImage.Sessions[0].Tracks[0].Control != 4 {
		t.Fatal(controlImage, err)
	}
	resolve := func(name string) (storage.Reader, error) {
		if name != "*.mdf" {
			t.Fatal(name)
		}
		return &starfile.Bytes{Data: raw}, nil
	}
	r, err := image.Sessions[0].Tracks[0].Readers(resolve)
	if err != nil {
		t.Fatal(err)
	}
	var data [8]byte
	if n, e := r.Data.ReadAt(data[:], 2044); e != nil || n != 8 || string(data[:]) != "AAAABBBB" {
		t.Fatal(n, e, string(data[:]))
	}
	if _, e := r.Subchannel.ReadAt(data[:], 92); e != nil || string(data[:]) != "aaaabbbb" {
		t.Fatal(e, string(data[:]))
	}
	if n, e := r.Data.ReadAt(data[:], 4092); !errors.Is(e, io.EOF) || n != 4 {
		t.Fatal(n, e)
	}
	audio, err := image.Sessions[0].Tracks[1].Readers(resolve)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := audio.Data.ReadAt(data[:], 0); e != nil || string(data[:]) != "CCCCCCCC" {
		t.Fatal(e, string(data[:]))
	}
	if audio.Raw.Size() != 2448 || audio.Data.Size() != 2352 || audio.Subchannel.Size() != 96 {
		t.Fatal("wrong audio geometry")
	}
	// Split companion boundaries can fall inside a sector.
	track := image.Sessions[0].Tracks[0]
	track.Files = []string{"first", "second"}
	parts := map[string]storage.Reader{"first": &starfile.Bytes{Data: raw[:2000]}, "second": &starfile.Bytes{Data: raw[2000:]}}
	r, err = track.Readers(func(n string) (storage.Reader, error) { return parts[n], nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, e := r.Data.ReadAt(data[:], 1980); e != nil || string(data[:]) != "AAAAAAAA" {
		t.Fatal(e, string(data[:]))
	}
}

func TestAutomaticCompanionsAndMetadata(t *testing.T) {
	b, raw := fixture()
	descriptor := &starfile.Bytes{Data: b}
	data := &starfile.Bytes{Data: raw}
	tree := auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{{Name: "disc.mds", Kind: "file", Reader: descriptor}, {Name: "disc.mdf", Kind: "file", Reader: data}}, nil
	})
	result, err := auto.Identify(descriptor, auto.Options{Source: &auto.SourceContext{Tree: tree, Path: "disc.mds"}})
	if err != nil {
		t.Fatal(err)
	}
	root := auto.FromView(result.View, "", auto.Options{})
	n, err := root.Resolve("session-1/track-2/audio")
	if err != nil || n.Reader().Size() != 2352 {
		t.Fatal(n, err)
	}
	track, err := root.Resolve("session-1/track-2")
	if err != nil {
		t.Fatal(err)
	}
	if track.Summary().Attributes["mode"] != int(0xa9) {
		t.Fatal(track.Summary())
	}
	meta, err := auto.Open(descriptor, "disc.mds", auto.Options{}).Metadata()
	if err != nil || meta.Attributes["companions_available"] != false {
		t.Fatal(meta, err)
	}
	images := starlark.NewDict(1)
	if err := images.SetKey(starlark.String("*.mdf"), data); err != nil {
		t.Fatal(err)
	}
	v, err := Builtin(nil, nil, starlark.Tuple{descriptor}, []starlark.Tuple{{starlark.String("images"), images}})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := v.(starlark.HasAttrs).Attr("sessions")
	if err != nil || sessions.(*starlark.List).Len() != 1 {
		t.Fatal(sessions, err)
	}
}

func TestInvalidDescriptorsAndCompanions(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"session bounds", func(b []byte) { binary.LittleEndian.PutUint32(b[80:], 1000) }},
		{"unknown medium", func(b []byte) { binary.LittleEndian.PutUint16(b[18:], 0xffff) }},
		{"track count", func(b []byte) { b[98] = 3 }},
		{"sector size", func(b []byte) { binary.LittleEndian.PutUint16(b[128:], 1) }},
		{"duplicate track", func(b []byte) { b[196] = 1 }},
		{"extra bounds", func(b []byte) { binary.LittleEndian.PutUint32(b[124:], 1000) }},
		{"filename UTF16", func(b []byte) { binary.LittleEndian.PutUint16(b[304:], 0xdc00) }},
		{"filename bounds", func(b []byte) { binary.LittleEndian.PutUint32(b[288:], 1000) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, _ := fixture()
			test.mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
				t.Fatal("accepted malformed descriptor")
			}
		})
	}
	b, raw := fixture()
	image, err := Open(&starfile.Bytes{Data: b})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := image.Sessions[0].Tracks[1].Readers(func(string) (storage.Reader, error) { return &starfile.Bytes{Data: raw[:len(raw)-1]}, nil }); err == nil {
		t.Fatal("accepted truncated track")
	}
	for _, name := range []string{"../x", "/x", "a\\b", "C:x", ".."} {
		if safeCompanion(name) {
			t.Fatal("unsafe name", name)
		}
	}
	// A symbolic link in a companion tree must not grant access to its reader.
	desc := &starfile.Bytes{Data: b}
	tree := auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{{Name: "disc.mdf", Kind: "symlink", Reader: &starfile.Bytes{Data: raw}}}, nil
	})
	if _, err := auto.Identify(desc, auto.Options{Source: &auto.SourceContext{Tree: tree, Path: "disc.mds"}}); err == nil {
		t.Fatal("followed companion link")
	}
}

func TestRepeatedSessionTrackTable(t *testing.T) {
	b, _ := fixture()
	b = append(b, make([]byte, 48)...)
	copy(b[320:344], b[88:112])
	copy(b[344:368], b[88:112])
	binary.LittleEndian.PutUint16(b[20:], 2)
	binary.LittleEndian.PutUint32(b[80:], 320)
	binary.LittleEndian.PutUint16(b[344+8:], 2)
	if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
		t.Fatal("accepted repeated disc-wide track identities")
	}
}

func TestSectorLayouts(t *testing.T) {
	for _, x := range []struct {
		mode      byte
		stride    uint16
		off, size int64
	}{{0xaa, 2352, 16, 2048}, {0xaa, 2048, 0, 2048}, {0xac, 2352, 24, 2048}, {0xec, 2336, 8, 2048}, {0xad, 2352, 24, 2324}, {0xed, 2324, 0, 2324}, {0xab, 2352, 16, 2336}, {2, 2048, 0, 2048}, {0xe9, 2352, 0, 2352}} {
		o, n, e := (Track{Mode: x.mode, SectorSize: x.stride}).layout()
		if e != nil || o != x.off || n != x.size {
			t.Fatal(x, o, n, e)
		}
	}
}

func TestCorpusChicago(t *testing.T) {
	root := os.Getenv("TREX_ARCHIVE_CORPUS")
	if root == "" {
		t.Skip("set TREX_ARCHIVE_CORPUS")
	}
	base := filepath.Join(root, "microsoft/windows_95/chicago_build_collection/4.00.331/release/4.00.331_x86fre_client_en-us-WIN95_331")
	d, err := os.Open(base + ".mds")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st, err := d.Stat()
	if err != nil {
		t.Fatal(err)
	}
	image, err := Open(io.NewSectionReader(d, 0, st.Size()))
	if err != nil {
		t.Fatal(err)
	}
	if len(image.Sessions) != 1 || len(image.Sessions[0].Tracks) != 6 {
		t.Fatal(image)
	}
	m, err := os.Open(base + ".mdf")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ms, err := m.Stat()
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) (storage.Reader, error) {
		if name != "*.mdf" {
			t.Fatal(name)
		}
		return io.NewSectionReader(m, 0, ms.Size()), nil
	}
	var total int64
	for j, track := range image.Sessions[0].Tracks {
		readers, err := track.Readers(resolve)
		if err != nil {
			t.Fatal(err)
		}
		total += readers.Raw.Size()
		if readers.Subchannel == nil {
			t.Fatal("lost subchannel")
		}
		var sample [32]byte
		for _, r := range []storage.Reader{readers.Raw, readers.Data, readers.Subchannel} {
			if _, err := r.ReadAt(sample[:], r.Size()-32); err != nil {
				t.Fatal(j, err)
			}
		}
		if j == 0 {
			if _, err := readers.Data.ReadAt(sample[:], 16*2048); err != nil || !bytes.Equal(sample[1:6], []byte("CD001")) {
				t.Fatal(sample, err)
			}
		} else if track.Mode != 0xa9 {
			t.Fatal(track.Mode)
		}
	}
	if total != ms.Size() {
		t.Fatal("track extents do not cover MDF", total, ms.Size())
	}
}
