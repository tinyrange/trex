package androidboot

import (
	"bytes"
	"io"
	"testing"
)

type source []byte

func (s source) Size() int64                             { return int64(len(s)) }
func (s source) ReadAt(p []byte, off int64) (int, error) { return bytes.NewReader(s).ReadAt(p, off) }
func bootFixture(version uint32) source {
	b := make(source, 16384)
	copy(b, "ANDROID!")
	le.PutUint32(b[8:], 13)
	le.PutUint32(b[12:], 7)
	le.PutUint32(b[20:], 1580)
	le.PutUint32(b[40:], version)
	copy(b[44:], "console=ttyS0")
	if version == 4 {
		le.PutUint32(b[20:], 1584)
		le.PutUint32(b[1580:], 11)
		copy(b[12288:], "signature!!")
	}
	copy(b[4096:], "kernel bytes!")
	copy(b[8192:], "ramdisk")
	return b
}
func vendorFixture(version uint32) source {
	b := make(source, 16384)
	copy(b, "VNDRBOOT")
	le.PutUint32(b[8:], version)
	le.PutUint32(b[12:], 2048)
	le.PutUint32(b[24:], 9)
	copy(b[28:], "androidboot.hardware=test")
	copy(b[2080:], "board")
	le.PutUint32(b[2096:], 2112)
	le.PutUint32(b[2100:], 3)
	copy(b[4096:], "ramdisk!!")
	copy(b[6144:], "dtb")
	if version == 4 {
		le.PutUint32(b[2096:], 2128)
		le.PutUint32(b[2112:], 216)
		le.PutUint32(b[2116:], 2)
		le.PutUint32(b[2120:], 108)
		le.PutUint32(b[2124:], 6)
		for j := 0; j < 2; j++ {
			row := b[8192+j*108:]
			le.PutUint32(row, 4)
			le.PutUint32(row[4:], uint32(j*4))
			le.PutUint32(row[8:], uint32(j+1))
			row[12] = byte('a' + j)
			le.PutUint32(row[44:], 77)
		}
		copy(b[10240:], "config")
	}
	return b
}
func TestBootSections(t *testing.T) {
	for _, version := range []uint32{3, 4} {
		i, err := Open(bootFixture(version))
		if err != nil {
			t.Fatal(err)
		}
		if i.Version != version || i.PageSize != 4096 || i.CommandLine != "console=ttyS0" || i.Sections[0].Offset != 4096 || i.Sections[1].Offset != 8192 {
			t.Fatalf("bad layout: %+v", i)
		}
		data, err := io.ReadAll(io.NewSectionReader(i.Sections[0].Data, 0, i.Sections[0].Size))
		if err != nil || string(data) != "kernel bytes!" {
			t.Fatal(string(data), err)
		}
		if version == 4 && (i.Sections[2].Name != "signature" || i.Sections[2].Offset != 12288 || i.Sections[2].Size != 11) {
			t.Fatal(i.Sections)
		}
	}
	b := bootFixture(4)
	le.PutUint32(b[8:], 0)
	le.PutUint32(b[12:], 0)
	le.PutUint32(b[1580:], 0)
	if _, err := Open(b); err != nil {
		t.Fatal("init_boot can have no kernel", err)
	}
}
func TestVendorSectionsAndFragments(t *testing.T) {
	for _, version := range []uint32{3, 4} {
		i, err := Open(vendorFixture(version))
		if err != nil {
			t.Fatal(err)
		}
		if i.Kind != "vendor_boot" || i.Name != "board" || i.PageSize != 2048 || i.Sections[0].Offset != 4096 || i.Sections[1].Offset != 6144 {
			t.Fatalf("bad layout: %+v", i)
		}
		if version == 4 {
			if len(i.Fragments) != 2 || i.Fragments[1].Section.Offset != 4100 || i.Fragments[1].BoardID[0] != 77 {
				t.Fatal(i.Fragments)
			}
			data, err := io.ReadAll(io.NewSectionReader(i.Sections[3].Data, 0, i.Sections[3].Size))
			if err != nil || string(data) != "config" {
				t.Fatal(string(data), err)
			}
		}
	}
}
func TestRejectMalformedImages(t *testing.T) {
	for _, mutate := range []func(source){
		func(b source) { b[0] = 0 }, func(b source) { le.PutUint32(b[40:], 5) }, func(b source) { le.PutUint32(b[20:], 1) },
		func(b source) { le.PutUint32(b[8:], ^uint32(0)) }, func(b source) { le.PutUint32(b[12:], ^uint32(0)) }, func(b source) { le.PutUint32(b[1580:], ^uint32(0)) },
	} {
		b := bootFixture(4)
		mutate(b)
		if _, err := Open(b); err == nil {
			t.Fatal("accepted malformed boot")
		}
	}
	for _, mutate := range []func(source){
		func(b source) { le.PutUint32(b[12:], 1000) }, func(b source) { le.PutUint32(b[2096:], 100) },
		func(b source) { le.PutUint32(b[2116:], ^uint32(0)) }, func(b source) { le.PutUint32(b[2120:], 107) },
		func(b source) { le.PutUint32(b[2124:], ^uint32(0)) }, func(b source) { le.PutUint32(b[8192+4:], 10) },
		func(b source) { b[8192+108+12] = 'a' },
	} {
		b := vendorFixture(4)
		mutate(b)
		if _, err := Open(b); err == nil {
			t.Fatal("accepted malformed vendor boot")
		}
	}
	if _, err := Open(bootFixture(4)[:1500]); err == nil {
		t.Fatal("accepted truncated boot header")
	}
	if _, err := Open(vendorFixture(4)[:9000]); err == nil {
		t.Fatal("accepted truncated bootconfig")
	}
}
