package ntfs

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestNTFSReaderUsesAttributeListAuthority(t *testing.T) {
	for _, mode := range []string{"no-list", "base-only", "extension-only", "referenced-overlap"} {
		t.Run(mode, func(t *testing.T) {
			mft := make([]byte, 8*ntfsRecordSize)
			put := func(id, base uint64, attrs ...[]byte) {
				r := mft[int64(id)*ntfsRecordSize : int64(id+1)*ntfsRecordSize]
				copy(r, "FILE")
				binary.LittleEndian.PutUint16(r[4:], 0x30)
				binary.LittleEndian.PutUint16(r[6:], 3)
				binary.LittleEndian.PutUint16(r[16:], ntfsSequenceNumber(id))
				binary.LittleEndian.PutUint16(r[20:], 0x38)
				binary.LittleEndian.PutUint16(r[22:], ntfsFileInUse)
				if base != 0 {
					binary.LittleEndian.PutUint64(r[32:], ntfsFileReference(base))
				}
				offset := 0x38
				for _, attr := range attrs {
					copy(r[offset:], attr)
					offset += len(attr)
				}
				binary.LittleEndian.PutUint32(r[offset:], ntfsAttrEnd)
				binary.LittleEndian.PutUint32(r[24:], uint32(offset+4))
				applyNTFSFixup(r, 0x30, 3)
			}
			put(5, 0)
			baseData := ntfsResidentAttr(ntfsAttrData, "", []byte("base"))
			extData := ntfsResidentAttr(ntfsAttrData, "", []byte("extension"))
			attrs := [][]byte{baseData}
			want := "base"
			if mode != "no-list" {
				owner := uint64(6)
				if mode == "extension-only" {
					owner = 7
					want = "extension"
				}
				list := ntfsAttributeListEntry(ntfsAttrData, 0, owner)
				if mode == "referenced-overlap" {
					list = append(list, ntfsAttributeListEntry(ntfsAttrData, 0, 7)...)
				}
				attrs = append(attrs, ntfsResidentAttr(ntfsAttrAttributeList, "", list))
			}
			put(6, 0, attrs...)
			put(7, 6, extData)
			file := &starfile.Bytes{Name: "mft", Data: mft}
			v := &ntfsVolume{file: file, clusterSize: 4096, recordSize: ntfsRecordSize, nodes: make(map[uint64]*ntfsReadNode), paths: make(map[string]*ntfsReadNode), securityDescriptors: make(map[uint32][]byte)}
			err := v.scanMFT(file, ntfsSectorSize)
			if mode == "referenced-overlap" {
				if err == nil {
					t.Fatal("accepted conflicting referenced extents")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := string(v.nodes[6].file.resident); got != want {
				t.Fatalf("data=%q want %q", got, want)
			}
		})
	}
}

func TestNTFSAttributeListEntryIdentity(t *testing.T) {
	data := ntfsNamedAttributeListEntry(ntfsAttrData, "stream", 9, 40)
	entries, err := parseNTFSReadAttributeList(data)
	if err != nil {
		t.Fatal(err)
	}
	node := &ntfsReadNode{id: 40, sequence: ntfsSequenceNumber(40)}
	attribute := ntfsReadAttribute{typ: ntfsAttrData, name: "stream", instance: 9}
	if !ntfsReadAttributeListed(entries, node, attribute) {
		t.Fatal("matching identity rejected")
	}
	for _, mutation := range []func(*ntfsReadAttributeListEntry){
		func(e *ntfsReadAttributeListEntry) { e.record++ },
		func(e *ntfsReadAttributeListEntry) { e.sequence++ },
		func(e *ntfsReadAttributeListEntry) { e.instance++ },
		func(e *ntfsReadAttributeListEntry) { e.firstVCN++ },
		func(e *ntfsReadAttributeListEntry) { e.typ++ },
		func(e *ntfsReadAttributeListEntry) { e.name = "other" },
	} {
		changed := append([]ntfsReadAttributeListEntry(nil), entries...)
		mutation(&changed[0])
		if ntfsReadAttributeListed(changed, node, attribute) {
			t.Fatal("mismatched identity accepted")
		}
	}
	for _, invalid := range [][]byte{data[:25], append([]byte(nil), data...)} {
		if len(invalid) > 25 {
			binary.LittleEndian.PutUint16(invalid[4:], 27)
		}
		if _, err := parseNTFSReadAttributeList(invalid); err == nil {
			t.Fatal("malformed list accepted")
		}
	}
}
