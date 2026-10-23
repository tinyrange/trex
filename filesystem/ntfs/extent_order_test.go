package ntfs

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestNTFSReaderExtensionVCNOrder(t *testing.T) {
	for _, stream := range []string{"", "$SDS"} {
		for _, overlap := range []bool{false, true} {
			name := stream
			if overlap {
				name += "-overlap"
			}
			t.Run(name, func(t *testing.T) {
				mft := make([]byte, 9*ntfsRecordSize)
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
					for _, a := range attrs {
						copy(r[offset:], a)
						offset += len(a)
					}
					binary.LittleEndian.PutUint32(r[offset:], ntfsAttrEnd)
					binary.LittleEndian.PutUint32(r[24:], uint32(offset+4))
					applyNTFSFixup(r, 0x30, 3)
				}
				// MFT order is VCN 0, 2, 1. Merging the first two early
				// fabricates a sparse gap that then rejects the middle extent.
				var list []byte
				for _, e := range []struct{ id, vcn uint64 }{{6, 0}, {7, 2}, {8, 1}} {
					entry := ntfsNamedAttributeListEntry(ntfsAttrData, stream, 0, e.id)
					binary.LittleEndian.PutUint64(entry[8:], e.vcn)
					list = append(list, entry...)
					a := ntfsNonResidentAttr(ntfsAttrData, stream, int64(e.vcn+1), ntfsCluster)
					binary.LittleEndian.PutUint64(a[16:], e.vcn)
					binary.LittleEndian.PutUint64(a[24:], e.vcn)
					binary.LittleEndian.PutUint64(a[48:], uint64(3*ntfsCluster))
					if overlap && e.id == 8 {
						// A genuine duplicate VCN must remain an error.
						binary.LittleEndian.PutUint64(list[len(list)-len(entry)+8:], 2)
						binary.LittleEndian.PutUint64(a[16:], 2)
						binary.LittleEndian.PutUint64(a[24:], 2)
					}
					if e.id != 6 {
						put(e.id, 6, a)
					}
				}
				base := ntfsNonResidentAttr(ntfsAttrData, stream, 1, ntfsCluster)
				binary.LittleEndian.PutUint64(base[48:], uint64(3*ntfsCluster))
				put(5, 0)
				put(6, 0, base, ntfsResidentAttr(ntfsAttrAttributeList, "", list))
				disk := make([]byte, 4*ntfsCluster)
				for i := 1; i <= 3; i++ {
					copy(disk[int64(i)*ntfsCluster:], bytes.Repeat([]byte{byte(i)}, int(ntfsCluster)))
				}
				volume := &starfile.Bytes{Name: "volume", Data: disk}
				v := &ntfsVolume{file: volume, clusterSize: ntfsCluster, recordSize: ntfsRecordSize, nodes: make(map[uint64]*ntfsReadNode), paths: make(map[string]*ntfsReadNode), securityDescriptors: make(map[uint32][]byte)}
				err := v.scanMFT(&starfile.Bytes{Name: "mft", Data: mft}, ntfsSectorSize)
				if overlap {
					if err == nil || !strings.Contains(err.Error(), "overlapping VCN") {
						t.Fatalf("expected overlap rejection, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				f := v.nodes[6].file
				if stream != "" {
					f = v.nodes[6].streams[stream]
				}
				got := make([]byte, uint64(3*ntfsCluster))
				if n, err := f.ReadAt(got, 0); n != len(got) || err != nil {
					t.Fatalf("read %d: %v", n, err)
				}
				if !bytes.Equal(got, disk[ntfsCluster:]) {
					t.Fatal("out-of-order extents changed stream contents")
				}
			})
		}
	}
}
