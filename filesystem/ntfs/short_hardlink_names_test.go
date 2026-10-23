package ntfs

import (
	"encoding/binary"
	"strings"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
)

// Combined Win32/DOS names must obey the same one-DOS-identity rule as
// separate aliases. The two-cli.mfl layout reproduces the WMIC TxF failure.
func TestNTFSShortHardLinksHaveOneDOSIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		want  [4]int
	}{
		{"short-short", []string{"cli.mfl", "cli.mfl"}, [4]int{1, 0, 0, 1}},
		{"long-short", []string{"long-file-name.mfl", "cli.mfl"}, [4]int{1, 1, 1, 0}},
		{"short-long", []string{"cli.mfl", "long-file-name.mfl"}, [4]int{1, 0, 0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filesystemapi.New()
			paths := []string{"/one/" + tc.names[0], "/two/" + tc.names[1]}
			for i, p := range paths {
				root.Mkdir([]string{"/one", "/two"}[i])
				root.PutFile(p, filesystemapi.FileRecord{Data: []byte("shared"), Size: 6})
				root.SetMetadata(p, filesystemapi.Metadata{HardLink: 99})
			}
			image, err := buildNTFSImageWithOptions(root, 64<<20, nil, 0, "LINKS", 3, 1)
			if err != nil {
				t.Fatal(err)
			}
			volume, err := newNTFSVolume(image)
			if err != nil {
				t.Fatal(err)
			}
			one, two := volume.paths[strings.ToLower(paths[0])], volume.paths[strings.ToLower(paths[1])]
			if one == nil || two == nil || one.id != two.id {
				t.Fatal("hard links lost their shared record")
			}
			record := make([]byte, ntfsRecordSize)
			if _, err := volume.mft.ReadAt(record, int64(one.id)*ntfsRecordSize); err != nil {
				t.Fatal(err)
			}
			if err := applyNTFSReadFixup(record, ntfsSectorSize, "hard links"); err != nil {
				t.Fatal(err)
			}
			attrs, err := parseNTFSReadAttributes(record, ntfsCluster)
			if err != nil {
				t.Fatal(err)
			}
			counts := [4]int{}
			for _, a := range attrs {
				if a.typ != ntfsAttrFileName {
					continue
				}
				if len(a.value) < 66 || a.value[65] > 3 {
					t.Fatal("invalid FILE_NAME")
				}
				counts[a.value[65]]++
			}
			if counts != tc.want {
				t.Fatalf("namespaces = %v, want %v", counts, tc.want)
			}
			total := 0
			for _, n := range counts {
				total += n
			}
			if got := int(binary.LittleEndian.Uint16(record[18:20])); got != total {
				t.Fatalf("link count = %d, want %d", got, total)
			}
		})
	}
}
