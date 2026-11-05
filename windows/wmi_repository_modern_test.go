package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWMIModernMappingBounds(t *testing.T) {
	var data []byte
	for i := 0; i < 2; i++ {
		for _, v := range []uint32{wmiMappingStart, 7, 12, 11, 2, 2, 1, 0, 0, 1, 12, 3, 0xffffffff, 0, 0, 0, 0, 0, 1, 0, wmiMappingEnd} {
			data = binary.LittleEndian.AppendUint32(data, v)
		}
	}
	data = binary.LittleEndian.AppendUint32(data, 1)
	m, err := parseWMIModernMapping(data)
	if err != nil || m.clean != 1 || m.index.entries[0].used != 1 {
		t.Fatalf("parse: %#v %v", m, err)
	}
	// Every prefix shorter than the two complete sections must fail, without
	// trusting attacker-controlled entry/free counts for allocation or slicing.
	for n := 0; n < len(data)-4; n++ {
		if _, err := parseWMIModernMapping(data[:n]); err == nil {
			t.Fatalf("accepted truncated mapping at %d", n)
		}
	}
	bad := bytes.Clone(data)
	binary.LittleEndian.PutUint32(bad[20:], 0xffffffff)
	if _, err := parseWMIModernMapping(bad); err == nil {
		t.Fatal("accepted overflowing entry count")
	}
	bad = bytes.Clone(data)
	binary.LittleEndian.PutUint32(bad[24:], 2)
	if _, err := parseWMIModernMapping(bad); err == nil {
		t.Fatal("accepted out-of-store page")
	}
}

func TestWMIModernNoncontiguousRecord(t *testing.T) {
	data := make([]byte, 3*wmiRepositoryPageSize)
	// Logical page 0 lives in physical page 2; its continuation is physical 0.
	page := data[2*wmiRepositoryPageSize:]
	binary.LittleEndian.PutUint32(page, 0x90000001)
	binary.LittleEndian.PutUint32(page[4:], 8171)
	binary.LittleEndian.PutUint32(page[8:], 41)
	copy(page[8171:], bytes.Repeat([]byte{0x42}, 21))
	copy(data, bytes.Repeat([]byte{0x43}, 20))
	s := wmiModernSection{physical: 3, entries: []wmiModernEntry{{page: 2}, {page: 0}}}
	r, err := readWMIModernRecord(s, data, 0, 0x90000001, 41)
	if err != nil || !bytes.Equal(r.data, append(bytes.Repeat([]byte{0x42}, 21), bytes.Repeat([]byte{0x43}, 20)...)) {
		t.Fatalf("record: %x %v", r.data, err)
	}
	s.entries[1].page = 0xffffffff
	if _, err := readWMIModernRecord(s, data, 0, 0x90000001, 41); err == nil {
		t.Fatal("accepted unmapped continuation")
	}
	binary.LittleEndian.PutUint32(page[4:], 16)
	if _, err := readWMIModernRecord(s, data, 0, 0x90000001, 41); err == nil {
		t.Fatal("accepted overlapping descriptor")
	}
}

func TestWMIModernIndexFollowsOnlyLiveTree(t *testing.T) {
	leaf, err := buildWMIRepositoryIndexPage(1, []string{`NS_hash\CD_hash.0.1.4`}, []uint32{0xffffffff, 0xffffffff})
	if err != nil {
		t.Fatal(err)
	}
	// Deleted/unmapped slots are not traversed. The root comes from the map.
	data := append(make([]byte, wmiRepositoryPageSize), leaf...)
	s := wmiModernSection{physical: 2, entries: []wmiModernEntry{{page: 0xffffffff, used: 1}, {page: 1}, {page: 0xffffffff}}}
	pages, err := parseWMIModernIndex(s, data)
	if err != nil || len(pages) != 1 {
		t.Fatalf("live index: %v %v", pages, err)
	}
	binary.LittleEndian.PutUint32(data[wmiRepositoryPageSize+24:], 1)
	if _, err := parseWMIModernIndex(s, data); err == nil {
		t.Fatal("accepted cyclic child")
	}
}

func TestWMIModernIndexPageZeroIsLive(t *testing.T) {
	leaf, err := buildWMIRepositoryIndexPage(0, []string{"A"}, []uint32{0xffffffff, 0xffffffff})
	if err != nil {
		t.Fatal(err)
	}
	root, err := buildWMIRepositoryIndexPage(1, []string{"B"}, []uint32{0, 0xffffffff})
	if err != nil {
		t.Fatal(err)
	}
	data := append(leaf, root...)
	s := wmiModernSection{physical: 2, entries: []wmiModernEntry{{page: 0, used: 1}, {page: 1}}}
	pages, err := parseWMIModernIndex(s, data)
	if err != nil || len(pages) != 2 || pages[1].id != 0 || pages[1].keys[0] != "A" {
		t.Fatalf("lost live page zero: %#v %v", pages, err)
	}
}
