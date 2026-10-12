package ufs

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestUFS2VariantsAnd64BitPointers(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, magic := range []uint32{0x19540119, 0x19012038} {
			for _, offset := range []int{8192, 65536} {
				b := make([]byte, 128*4096)
				sb := b[offset:]
				for field, value := range map[int]uint32{16: 32, 44: 1, 48: 4096, 52: 4096, 56: 1, 116: 512, 120: 16, 184: 16, 188: 128, 1320: 120, 1372: magic} {
					order.PutUint32(sb[field:], value)
				}
				order.PutUint64(sb[1080:], 128)
				inode := b[32*4096+2*256:]
				order.PutUint16(inode, 0040755)
				order.PutUint16(inode[2:], 2)
				order.PutUint64(inode[16:], 512)
				order.PutUint64(inode[112:], 40)
				file := b[32*4096+3*256:]
				order.PutUint16(file, 0100644)
				order.PutUint16(file[2:], 1)
				order.PutUint32(file[4:], 70000)
				order.PutUint32(file[8:], 80000)
				order.PutUint64(file[16:], 12*4096+3)
				order.PutUint64(file[208:], 60)
				order.PutUint64(b[60*4096:], 61)
				copy(b[61*4096:], "xyz")
				order.PutUint64(file[112:], 50)
				link := b[32*4096+4*256:]
				order.PutUint16(link, 0120777)
				order.PutUint16(link[2:], 1)
				order.PutUint64(link[16:], 4)
				copy(link[112:], "file")
				directory := b[40*4096:]
				for _, item := range []struct {
					off, ino, len int
					name          string
					typ           byte
				}{{0, 2, 12, ".", 4}, {12, 2, 12, "..", 4}, {24, 3, 16, "file", 8}, {40, 4, 472, "link", 10}} {
					d := directory[item.off:]
					order.PutUint32(d, uint32(item.ino))
					order.PutUint16(d[4:], uint16(item.len))
					d[6], d[7] = item.typ, byte(len(item.name))
					copy(d[8:], item.name)
				}
				copy(b[50*4096:], "abc")
				volume, err := Open(&starfile.Bytes{Data: b}, 10, 100)
				if err != nil {
					t.Fatal(err)
				}
				if len(volume.Entries) != 3 || volume.Entries[1].UID != 70000 || volume.Entries[1].GID != 80000 {
					t.Fatalf("metadata: %+v", volume)
				}
				data, err := starfile.ReadAll(volume.Entries[1].Data)
				if err != nil || len(data) != 12*4096+3 || string(data[:3]) != "abc" || string(data[12*4096:]) != "xyz" {
					t.Fatalf("indirect payload: %d bytes %v", len(data), err)
				}
				for _, value := range data[4096 : 12*4096] {
					if value != 0 {
						t.Fatal("nonzero sparse hole")
					}
				}
				target, err := starfile.ReadAll(volume.Entries[2].Data)
				if err != nil || string(target) != "file" {
					t.Fatalf("inline symlink: %s %v", target, err)
				}
				// A hostile 64-bit pointer must be rejected, not multiplied with overflow.
				order.PutUint64(file[112:], 1<<63)
				if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil {
					t.Fatal("accepted overflowing block pointer")
				}
			}
		}
	}
}
