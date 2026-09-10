package ntfs

import (
	"encoding/binary"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestNTFSRecordInspectionIndependentOfAttributeListScan(t *testing.T) {
	image, err := NTFSBuiltin(nil, nil, starlark.Tuple{filesystemapi.New()}, []starlark.Tuple{{starlark.String("size"), starlark.MakeInt(64 << 20)}})
	if err != nil {
		t.Fatal(err)
	}
	source := image.(starfile.File)
	data := make([]byte, source.Size())
	if _, err := starfile.ReadFullAt(source, data, 0); err != nil {
		t.Fatal(err)
	}
	file := &starfile.Bytes{Name: "inspection-test", Data: data}
	v, err := openNTFSMFT(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []int64{0, 5} {
		if _, err := RecordBuiltin(nil, nil, starlark.Tuple{file, starlark.MakeInt64(number)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, number := range []int64{-1, v.mft.size / v.recordSize, 1 << 62} {
		if _, err := RecordBuiltin(nil, nil, starlark.Tuple{file, starlark.MakeInt64(number)}, nil); err == nil {
			t.Fatal("accepted out-of-range record")
		}
	}
	// The builder's small MFT is contiguous. Introduce an invalid list into
	// the root record: ordinary namespace loading must reject it, while the
	// bounded record probe must expose its actual bytes without repairing it.
	if len(v.mft.runs) != 1 || v.mft.runs[0].length*v.clusterSize < 6*v.recordSize {
		t.Fatal("unexpected fixture MFT mapping")
	}
	off := v.mft.runs[0].start*v.clusterSize + 5*v.recordSize
	raw := data[off : off+v.recordSize]
	if err := applyNTFSReadFixup(raw, v.sectorSize, "fixture"); err != nil {
		t.Fatal(err)
	}
	pos := int(binary.LittleEndian.Uint16(raw[20:]))
	for binary.LittleEndian.Uint32(raw[pos:]) != ntfsAttrEnd {
		pos += int(binary.LittleEndian.Uint32(raw[pos+4:]))
	}
	list := ntfsResidentAttr(ntfsAttrAttributeList, "", make([]byte, 32))
	copy(raw[pos:], list)
	pos += len(list)
	binary.LittleEndian.PutUint32(raw[pos:], ntfsAttrEnd)
	binary.LittleEndian.PutUint32(raw[24:], uint32(pos+8))
	applyNTFSFixup(raw, binary.LittleEndian.Uint16(raw[4:]), binary.LittleEndian.Uint16(raw[6:]))
	if _, err := newNTFSVolume(file); err == nil {
		t.Fatal("namespace scan accepted malformed list")
	}
	got, err := RecordBuiltin(nil, nil, starlark.Tuple{file, starlark.MakeInt(5)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := got.(starlark.HasAttrs).Attr("attributes")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i < attrs.(*starlark.List).Len(); i++ {
		a := attrs.(*starlark.List).Index(i).(starlark.HasAttrs)
		typ, _ := a.Attr("type")
		if typ.String() != "32" {
			continue
		}
		value, _ := a.Attr("value")
		if string(value.(starlark.Bytes)) != string(make([]byte, 32)) {
			t.Fatal("inspection altered invalid value")
		}
		found = true
	}
	if !found {
		t.Fatal("attribute list missing from inspection")
	}
	raw[510] ^= 1
	if _, err := RecordBuiltin(nil, nil, starlark.Tuple{file, starlark.MakeInt(5)}, nil); err == nil {
		t.Fatal("inspection accepted invalid sector fixup")
	}
}
