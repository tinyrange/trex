package ckd

import (
	"bytes"
	"testing"
)

const (
	cpPerTrack  = 4
	cpHeads     = 2
	cpTrackSize = 5 + 16 + cpPerTrack*(8+4096) + 8
)

// cpImage builds a P370 image whose cylinder 1 is CP-formatted: records
// 1..8 continue across its two tracks. pages maps record numbers to data.
func cpImage(label []byte, pages map[int][]byte) []byte {
	tracks := make([][]Record, 2*cpHeads)
	tracks[0] = []Record{r(0, nil, make([]byte, 8)), r(1, nil, label)}
	tracks[1] = []Record{r(0, nil, make([]byte, 8))}
	for h := 0; h < cpHeads; h++ {
		rs := []Record{r(0, nil, make([]byte, 8))}
		for k := 1; k <= cpPerTrack; k++ {
			n := h*cpPerTrack + k
			data := pages[n]
			if data == nil {
				data = make([]byte, 4096)
			}
			rs = append(rs, r(byte(n), nil, data))
		}
		tracks[cpHeads+h] = rs
	}
	b := make([]byte, 512+cpTrackSize*len(tracks))
	copy(b, "CKD_P370")
	le.PutUint32(b[8:], cpHeads)
	le.PutUint32(b[12:], cpTrackSize)
	for t, rs := range tracks {
		p := 512 + t*cpTrackSize
		be.PutUint16(b[p+1:], uint16(t/cpHeads))
		be.PutUint16(b[p+3:], uint16(t%cpHeads))
		p += 5
		for _, rec := range rs {
			be.PutUint16(b[p:], uint16(t/cpHeads))
			be.PutUint16(b[p+2:], uint16(t%cpHeads))
			b[p+4] = rec.Number
			be.PutUint16(b[p+6:], uint16(len(rec.Data)))
			copy(b[p+8:], rec.Data)
			p += 8 + len(rec.Data)
		}
		copy(b[p:], bytes.Repeat([]byte{255}, 8))
	}
	return b
}

func cpPtr(rec int) uint32 { return 1<<16 | uint32(rec)<<8 }

func cpDevice(owner string, addr uint16, typ byte, fill func([]byte)) []byte {
	d := make([]byte, 80)
	be.PutUint16(d, addr)
	d[2] = typ
	copy(d[0x44:], cpDeviceMark)
	copy(d[0x48:], eb(owner, 8))
	if fill != nil {
		fill(d)
	}
	return d
}

type cpFixture struct {
	label []byte
	pages map[int][]byte
}

func newCPFixture() *cpFixture {
	label := make([]byte, 80)
	copy(label, []byte{0xe5, 0xd6, 0xd3, 0xf1})
	be.PutUint32(label[0x34:], cpPtr(1))
	pages := map[int][]byte{}
	page := func() []byte { return make([]byte, 4096) }
	// 1 root, 2 header, 3 leaf, 4 user blocks, 5 devices, 6 other owner and
	// chains, 7 devices continued, 8 GID index.
	root, header, leaf, users, dev1, other, dev2, gids := page(), page(), page(), page(), page(), page(), page(), page()
	copy(root[8:], cpIndexTitle)
	be.PutUint16(root[4:], 1)
	copy(root[0x18:], eb("BETA", 8))
	be.PutUint32(root[0x20:], cpPtr(3))
	copy(header[8:], cpHeaderTitle)
	be.PutUint32(header[0x18:], cpPtr(1))
	be.PutUint32(header[0x20:], cpPtr(8)) // GID index; also the first profile entry's leading word
	prof := header[0x20:]
	be.PutUint16(prof[4:], 2*cpUserBlock)
	be.PutUint32(prof[8:], cpPtr(4))
	copy(prof[16:], eb("PROF", 8))
	copy(gids[8:], []byte{0xd7, 0xd6, 0xe2, 0xc9, 0xe7, 0x40, 0xc7, 0xc9, 0xc4, 0x40, 0xc9, 0xd5, 0xc4, 0xc5, 0xe7, 0x40})
	be.PutUint16(gids[4:], 1)
	be.PutUint32(gids[0x18:], 7)
	copy(gids[0x1c:], eb("STAFF", 8))
	copy(leaf[8:], cpIndexTitle)
	be.PutUint16(leaf[4:], 2)
	for i, u := range []struct {
		name     string
		devOff   uint16
		count    uint16
		blockOff uint16
	}{{"ALPHA", 4000, 3, 0}, {"BETA", 0, 0, cpUserBlock}} {
		e := leaf[0x20+32*i:]
		be.PutUint16(e[4:], u.blockOff)
		be.PutUint16(e[6:], u.devOff)
		be.PutUint32(e[8:], cpPtr(4))
		if u.count > 0 {
			be.PutUint32(e[12:], cpPtr(5))
		}
		copy(e[16:], eb(u.name, 8))
		be.PutUint32(e[24:], 0x0c004000)
		be.PutUint32(e[28:], 0xffffffff)
		be.PutUint16(users[int(u.blockOff)+0x200:], u.count)
	}
	a := users[:cpUserBlock]
	a[3] = 0x0c // ESA
	a[2] = 0x02 // QUICKDSP
	be.PutUint32(a[0x1cc:], 32768)
	be.PutUint32(a[0x1d4:], 65536)
	be.PutUint32(a[0x12c:], 0xc2000000) // classes ABG
	copy(a[0x20:], eb("ACCT1", 8))
	copy(a[0x60:], eb("AUTOLOG1", 8))
	copy(a[0x1f8:], eb("PROF", 8))
	be.PutUint32(a[0x1a0:], 0xffffffff)
	be.PutUint32(a[0x1a4:], 0xffffffff)
	// IUCV chain: ANY MSGLIMIT 255, then *IDENT RES GLOBAL; NAMESAVE GCS.
	be.PutUint32(a[0xf0:], cpPtr(6))
	be.PutUint16(a[0xf6:], 2048)
	copy(other[2048:], eb("ANY", 8))
	be.PutUint32(other[2048+8:], cpPtr(6))
	be.PutUint16(other[2048+12:], 2080)
	be.PutUint16(other[2048+14:], 255)
	copy(other[2080:], []byte{0x5c, 0xc9, 0xc4, 0xc5, 0xd5, 0xe3, 0x40, 0x40})
	other[2080+17] = 0x41
	copy(other[2080+24:], eb("RES", 8))
	be.PutUint32(a[0xec:], cpPtr(6))
	be.PutUint16(a[0xf4:], 3000)
	copy(other[3000+8:], eb("GCS", 8))
	// ALPHA: an MDISK fits at the end of record 5; the stream continues on
	// record 7 (record 6 holds another owner's blocks). Each block points to
	// the next device of the configuration.
	copy(dev1[4000:], cpDevice("ALPHA", 0x191, 0x80, func(d []byte) {
		be.PutUint16(d[6:], 100)
		be.PutUint16(d[8:], 109)
		copy(d[10:], eb("VOL001", 6))
		d[16], d[17] = 0xe0, 0x20
		be.PutUint32(d[0x38:], cpPtr(7))
	}))
	copy(other, cpDevice("GAMMA", 0x9, 0x08, nil))
	copy(dev2, cpDevice("ALPHA", 0x190, 0x40, func(d []byte) {
		be.PutUint16(d[16:], 4)
		be.PutUint16(d[26:], 0x190)
		copy(d[32:], eb("MAINT", 8))
		be.PutUint32(d[0x38:], cpPtr(7))
		be.PutUint16(d[0x3c:], 80)
	}))
	copy(dev2[80:], cpDevice("ALPHA", 0x9, 0x08, func(d []byte) {
		be.PutUint16(d[4:], 0x8040)
		d[0x18] = 0xe3
	}))
	pages[1], pages[2], pages[3], pages[4], pages[5], pages[6], pages[7], pages[8] = root, header, leaf, users, dev1, other, dev2, gids
	return &cpFixture{label, pages}
}

func TestCPDirectory(t *testing.T) {
	f := newCPFixture()
	d := openTest(t, cpImage(f.label, f.pages))
	c, err := OpenCPDirectory(d, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if c.Root != cpPtr(1) || len(c.Users) != 2 || c.Users[1].Name != "BETA" || c.Users[1].DeviceCount != 0 {
		t.Fatalf("users %+v", c.Users)
	}
	a := c.Users[0]
	if a.Name != "ALPHA" || len(a.Devices) != 3 || a.Flags != 0x0c004000 {
		t.Fatalf("alpha %+v", a)
	}
	m, l := a.Devices[0], a.Devices[1]
	if m.Address != 0x191 || m.Start != 100 || m.End != 109 || m.Volume != "VOL001" || m.Mode != 0x20 || m.Owner != "ALPHA" {
		t.Fatalf("mdisk %+v", m)
	}
	if l.TargetUser != "MAINT" || l.TargetAddress != 0x190 || l.LinkMode != 4 || a.Devices[2].Type != 0x08 || l.ModeName() != "RR" || m.ModeName() != "MR" || m.PasswordFlags != 0xe0 {
		t.Fatalf("link %+v", l)
	}
	if a.Devices[2].DeviceType != 0x8040 || a.Devices[2].SpoolClass != "T" || len(a.Configuration) != 3 {
		t.Fatalf("console %+v configuration %d", a.Devices[2], len(a.Configuration))
	}
	f2 := a.Fields
	if f2.Machine != "ESA" || f2.StorageKB != 32768 || f2.MaximumStorageKB != 65536 || f2.Classes != 0xc2000000 || f2.Account != "ACCT1" ||
		len(f2.Autolog) != 1 || f2.Include != "PROF" || len(f2.Options) != 1 || f2.Options[0] != "QUICKDSP" || f2.POSIXUID != 0xffffffff {
		t.Fatalf("fields %+v", f2)
	}
	if len(a.IUCV) != 2 || a.IUCV[0].MessageLimit != 255 || a.IUCV[1].Resource != "RES" || a.IUCV[1].IdentFlags != 0x41 || len(a.NameSave) != 1 || a.NameSave[0] != "GCS" {
		t.Fatalf("iucv %+v namesave %v", a.IUCV, a.NameSave)
	}
	if c.Header != cpPtr(2) || len(c.Profiles) != 1 || c.Profiles[0].Name != "PROF" || len(c.Groups) != 1 || c.Groups[0].GID != 7 || c.Groups[0].Name != "STAFF" {
		t.Fatalf("header %+v %+v", c.Profiles, c.Groups)
	}
	cases := map[string]func(f *cpFixture){
		"no-label-pointer": func(f *cpFixture) { be.PutUint32(f.label[0x34:], 0) },
		"root-title":       func(f *cpFixture) { f.pages[1][8] = 0 },
		"root-high-key":    func(f *cpFixture) { copy(f.pages[1][0x18:], eb("ALPHA", 8)) },
		"chain-continues":  func(f *cpFixture) { be.PutUint32(f.pages[3], cpPtr(3)) },
		"owner":            func(f *cpFixture) { copy(f.pages[5][4000+0x48:], eb("OTHER", 8)) },
		"short-stream":     func(f *cpFixture) { be.PutUint16(f.pages[4][0x200:], 4) },
		"bad-pointer":      func(f *cpFixture) { be.PutUint32(f.pages[3][0x20+8:], 1<<16|200<<8) },
		"header":           func(f *cpFixture) { be.PutUint32(f.pages[2][0x18:], cpPtr(3)) },
		"iucv-loop": func(f *cpFixture) {
			be.PutUint16(f.pages[6][2080+12:], 2048)
			be.PutUint32(f.pages[6][2080+8:], cpPtr(6))
		},
		"config-order": func(f *cpFixture) { be.PutUint32(f.pages[5][4000+0x38:], cpPtr(6)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCPFixture()
			mutate(f)
			if _, err := OpenCPDirectory(openTest(t, cpImage(f.label, f.pages)), 0, 100); err == nil {
				t.Fatal("accepted malformed directory")
			}
		})
	}
	if _, err := OpenCPDirectory(d, 0, 1); err == nil {
		t.Fatal("ignored user limit")
	}
}

// FuzzCPDirectoryLeaf replaces the leaf index page with arbitrary bytes.
func FuzzCPDirectoryLeaf(f *testing.F) {
	f.Add(newCPFixture().pages[3][:256])
	f.Fuzz(func(t *testing.T, b []byte) {
		x := newCPFixture()
		copy(x.pages[3], b)
		_, _ = OpenCPDirectory(openTest(t, cpImage(x.label, x.pages)), 0, 1000)
	})
}
