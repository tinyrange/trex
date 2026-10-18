package ntfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestNTFSEAGolden(t *testing.T) {
	info, data, err := ntfsEncodeEAs([]filesystemapi.ExtendedAttribute{{Name: "A", Flags: 0x80, Value: []byte{1, 2, 3}}, {Name: "B"}})
	want := []byte{16, 0, 0, 0, 0x80, 1, 3, 0, 'A', 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 'B', 0, 0, 0}
	if err != nil || !bytes.Equal(data, want) || !bytes.Equal(info, []byte{15, 0, 1, 0, 28, 0, 0, 0}) {
		t.Fatalf("info %x data %x err %v", info, data, err)
	}
}
func TestNTFSEARoundTrip(t *testing.T) {
	for _, size := range []int{100, 9000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			root := filesystemapi.New()
			value := bytes.Repeat([]byte{0x31}, size)
			ea := []filesystemapi.ExtendedAttribute{{Name: "$CI.CATALOGHINT", Value: value}}
			for i := 0; i < 12; i++ {
				root.Mkdir(fmt.Sprintf("/link%02d", i))
				name := fmt.Sprintf("/link%02d/long-file-name-for-hard-link.dll", i)
				root.PutFile(name, filesystemapi.FileRecord{Data: []byte("main"), Size: 4})
				root.SetMetadata(name, filesystemapi.Metadata{ExtendedAttributes: ea, HardLink: 5})
			}
			root.Mkdir("/directory")
			root.SetMetadata("/directory", filesystemapi.Metadata{ExtendedAttributes: ea})
			image, err := buildNTFSImageWithOptions(root, 64<<20, nil, 0, "EA", 3, 1)
			if err != nil {
				t.Fatal(err)
			}
			volume, err := newNTFSVolume(image)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"/link00/long-file-name-for-hard-link.dll", "/link11/long-file-name-for-hard-link.dll", "/directory"} {
				node := volume.lookup(name)
				if node == nil || node.eaData == nil {
					t.Fatalf("missing EA %s", name)
				}
				if size > 192 {
					bitmap, err := starfile.ReadAll(volume.lookup("/$Bitmap").file)
					if err != nil {
						t.Fatal(err)
					}
					for _, run := range node.eaData.runs {
						for c := run.start; c < run.start+run.length; c++ {
							if bitmap[c/8]&(1<<uint(c%8)) == 0 {
								t.Fatal("EA extent unallocated in bitmap")
							}
						}
					}
				}
				data, err := starfile.ReadAll(node.eaData)
				if err != nil {
					t.Fatal(err)
				}
				if len(node.eaInfo) != 8 || int(binary.LittleEndian.Uint32(node.eaInfo[4:])) != len(data) {
					t.Fatalf("invalid info %x", node.eaInfo)
				}
				if data[5] != 15 || string(data[8:23]) != "$CI.CATALOGHINT" || !bytes.Equal(data[24:24+size], value) {
					t.Fatal("EA changed")
				}
				if name != "/directory" {
					if !node.hasAttributeList {
						t.Fatal("fixture did not exercise extension records")
					}
					found := 0
					for _, a := range node.attributeList {
						if a.typ == ntfsAttrEA || a.typ == ntfsAttrEAInformation {
							found++
						}
					}
					if found != 2 {
						t.Fatalf("EA list entries %d", found)
					}
				}
			}
		})
	}
}
func TestNTFSEARejectsInvalid(t *testing.T) {
	for _, eas := range [][]filesystemapi.ExtendedAttribute{
		{{Name: ""}}, {{Name: "A", Flags: 1}}, {{Name: "A"}, {Name: "a"}}, {{Name: "A", Value: make([]byte, 65535)}}, {{Name: "a\x00b"}},
	} {
		if _, _, err := ntfsEncodeEAs(eas); err == nil {
			t.Fatalf("accepted invalid EAs")
		}
	}
}
