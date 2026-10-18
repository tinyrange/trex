package ntfs

import (
	"encoding/binary"
	"strings"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
)

// Reproduce the differing imported aliases that caused Windows to request
// startup repair while updating TrustedInstaller's duplicate information.
func TestNTFSHardLinksHaveUnambiguousDOSPair(t *testing.T) {
	root := filesystemapi.New()
	paths := []string{"/one/TrustedInstaller.exe", "/two/TrustedInstaller.exe"}
	for i, path := range paths {
		root.Mkdir([]string{"/one", "/two"}[i])
		root.PutFile(path, filesystemapi.FileRecord{Data: []byte("shared"), Size: 6})
		root.SetMetadata(path, filesystemapi.Metadata{HardLink: 99, ShortName: []string{"TRUSTE~1.EX", "TRUSTE~1.EXE"}[i]})
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
		t.Fatal("hard links did not retain a shared record")
	}
	boot := make([]byte, ntfsSectorSize)
	if _, err := image.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	record := make([]byte, ntfsRecordSize)
	offset := int64(binary.LittleEndian.Uint64(boot[48:56])) * ntfsCluster
	if _, err := image.ReadAt(record, offset+int64(one.id)*ntfsRecordSize); err != nil {
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
	parents := [4]uint64{}
	for _, attr := range attrs {
		if attr.typ != ntfsAttrFileName {
			continue
		}
		if len(attr.value) < 66 || attr.value[65] > 3 {
			t.Fatal("invalid FILE_NAME")
		}
		ns := attr.value[65]
		counts[ns]++
		parents[ns] = binary.LittleEndian.Uint64(attr.value[:8])
	}
	if counts != [4]int{1, 1, 1, 0} {
		t.Fatalf("namespaces = %v; want one unpaired hard link and one Win32/DOS pair", counts)
	}
	if parents[1] != parents[2] || parents[0] == parents[1] {
		t.Fatalf("incorrect name parents: %v", parents)
	}
	if got := binary.LittleEndian.Uint16(record[18:20]); got != 3 {
		t.Fatalf("MFT link count = %d, want all three directory entries", got)
	}
}
