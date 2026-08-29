package fat

import (
	"encoding/binary"
	"strings"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
)

func TestFAT32LFNCaseDecisions(t *testing.T) {
	tests := []struct {
		name     string
		wantLFN  bool
		wantCase byte
	}{
		{name: "notepad.exe", wantLFN: false, wantCase: 0x18},
		{name: "README.TXT", wantLFN: false, wantCase: 0x00},
		{name: "WineMine.lnk", wantLFN: true, wantCase: 0x00},
		{name: "ReactOS", wantLFN: true, wantCase: 0x00},
	}
	for _, tt := range tests {
		base, ext := fat32ShortParts(tt.name)
		short := fat32ShortName(base, ext)
		if got := fat32NeedsLFN(tt.name, short); got != tt.wantLFN {
			t.Fatalf("fat32NeedsLFN(%q) = %t, want %t", tt.name, got, tt.wantLFN)
		}
		entry := fat32DirEntry(tt.name, 3, 0, fatAttrArchive, short)
		if got := entry[12]; got != tt.wantCase {
			t.Fatalf("NTRes case flags for %q = %#x, want %#x", tt.name, got, tt.wantCase)
		}
	}
}

func TestFAT32LargeImageFATSizeConverges(t *testing.T) {
	dir := filesystemapi.New()
	image, err := buildFAT32Image(dir, 3*1024*1024*1024, nil, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if image.Size() != 3*1024*1024*1024 {
		t.Fatalf("image size = %d, want %d", image.Size(), int64(3*1024*1024*1024))
	}
}

func TestFAT32UsesCanonicalFATSize(t *testing.T) {
	image, err := buildFAT32Image(filesystemapi.New(), 960*1024*1024, nil, 63)
	if err != nil {
		t.Fatal(err)
	}
	boot := make([]byte, fat32SectorSize)
	if _, err := image.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	sectorsPerFAT := int64(binary.LittleEndian.Uint32(boot[36:40]))
	if got, want := sectorsPerFAT, int64(1919); got != want {
		t.Fatalf("sectors per FAT = %d, want canonical Windows-compatible size %d", got, want)
	}
	fat := make([]byte, 8)
	if _, err := image.ReadAt(fat, fat32ReservedSectors*fat32SectorSize); err != nil {
		t.Fatal(err)
	}
	if got, want := binary.LittleEndian.Uint32(fat[0:4]), uint32(0x0ffffff8); got != want {
		t.Fatalf("FAT media entry = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(fat[4:8]), uint32(0x0fffffff); got != want {
		t.Fatalf("FAT dirty-state entry = %#x, want %#x", got, want)
	}
}

func TestFAT32SmallEFIImageSelectsValidClusterSize(t *testing.T) {
	image, err := buildFAT32Image(filesystemapi.New(), 128*1024*1024, nil, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, fat32SectorSize)
	if _, err := image.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if got := sector[13]; got != 2 {
		t.Fatalf("sectors per cluster = %d, want 2", got)
	}
}

func TestFAT32PreservesVirtualDirectoryAttributes(t *testing.T) {
	dir := filesystemapi.New()
	dir.Mkdir("/profile/My Pictures")
	dir.PutFile("/profile/My Pictures/desktop.ini", filesystemapi.FileRecord{Data: []byte("test"), Size: 4})
	if err := dir.SetAttributes("/profile/My Pictures", filesystemapi.Attributes{ReadOnly: true, System: true}); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetAttributes("/profile/My Pictures/desktop.ini", filesystemapi.Attributes{Hidden: true, System: true, Archive: true}); err != nil {
		t.Fatal(err)
	}

	b := &fat32Build{}
	if err := b.importDirectory(dir); err != nil {
		t.Fatal(err)
	}
	var folder, desktop *fat32Node
	for _, node := range b.nodes {
		switch node.fullPath {
		case "/profile/My Pictures":
			folder = node
		case "/profile/My Pictures/desktop.ini":
			desktop = node
		}
	}
	if folder == nil || folder.attr != fatAttrReadOnly|fatAttrSystem {
		t.Fatalf("folder = %#v, want read-only and system attributes", folder)
	}
	if desktop == nil || desktop.attr != fatAttrHidden|fatAttrSystem|fatAttrArchive {
		t.Fatalf("desktop.ini = %#v, want hidden, system, and archive attributes", desktop)
	}
}

func TestFAT32CaseInsensitiveCollisionKeepsLatestWrite(t *testing.T) {
	dir := filesystemapi.New()
	dir.PutFile("/WINDOWS/System32/XPSP2RES.DLL", filesystemapi.FileRecord{Data: []byte("stale"), Size: 5})
	dir.PutFile("/WINDOWS/system32/xpsp2res.dll", filesystemapi.FileRecord{Data: []byte("current"), Size: 7})

	b := &fat32Build{}
	if err := b.importDirectory(dir); err != nil {
		t.Fatal(err)
	}
	var found *fat32Node
	for _, node := range b.nodes {
		if strings.EqualFold(node.fullPath, "/WINDOWS/system32/xpsp2res.dll") {
			found = node
			break
		}
	}
	if found == nil {
		t.Fatal("case-insensitive file was not imported")
	}
	if got, want := string(found.data), "current"; got != want {
		t.Fatalf("file data = %q, want latest write %q", got, want)
	}
	if got, want := found.fullPath, "/WINDOWS/system32/xpsp2res.dll"; got != want {
		t.Fatalf("file path = %q, want latest spelling %q", got, want)
	}
}

func TestFAT32VolumeLabel(t *testing.T) {
	label, err := fat32VolumeLabel("Windows XP")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(label[:]), "WINDOWS XP "; got != want {
		t.Fatalf("label = %q, want %q", got, want)
	}
	if _, err := fat32VolumeLabel("invalid/name"); err == nil {
		t.Fatal("invalid label was accepted")
	}
}

func TestFAT32RootDirectoryUsesConfiguredVolumeLabel(t *testing.T) {
	label, _ := fat32VolumeLabel("Windows XP")
	b := &fat32Build{volumeLabel: label, directoryLabel: true}
	b.root = &fat32Node{name: "/", fullPath: "/", dir: true}

	data := b.directoryData(b.root)
	if got, want := string(data[:11]), "WINDOWS XP "; got != want {
		t.Fatalf("root volume label = %q, want %q", got, want)
	}
	if got := data[11]; got != fatAttrVolumeID {
		t.Fatalf("root volume label attributes = %#x, want %#x", got, fatAttrVolumeID)
	}
}

func TestFAT32CanSuppressRootDirectoryVolumeLabel(t *testing.T) {
	b := &fat32Build{directoryLabel: false}
	b.root = &fat32Node{name: "/", fullPath: "/", dir: true}
	b.root.children = []*fat32Node{{name: "IO.SYS", short: fat32ShortName("IO", "SYS")}}

	data := b.directoryData(b.root)
	if got, want := string(data[:11]), "IO      SYS"; got != want {
		t.Fatalf("first root entry = %q, want %q", got, want)
	}
}

func TestFAT32PlacesSecondaryBootCodeAtConfiguredSector(t *testing.T) {
	dir := filesystemapi.New()
	label, _ := fat32VolumeLabel("TEST")
	bootCode := make([]byte, 2*fat32SectorSize)
	bootCode[fat32SectorSize] = 0xa5
	image, err := buildFAT32ImageWithOptions(dir, 512*1024*1024, bootCode, 2048, label, 12)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1)
	if _, err := image.ReadAt(data, 12*fat32SectorSize); err != nil {
		t.Fatal(err)
	}
	if data[0] != 0xa5 {
		t.Fatalf("secondary boot byte = %#x, want 0xa5", data[0])
	}
}

func TestFAT32RejectsOverlappingSecondaryBootCode(t *testing.T) {
	bootCode := make([]byte, 2*fat32SectorSize)
	if err := validateFAT32BootStage(bootCode, fat32BackupBoot); err == nil {
		t.Fatal("secondary boot code overlapping the backup boot sector was accepted")
	}
	if err := validateFAT32BootStage(make([]byte, 4*fat32SectorSize), fat32ReservedSectors-2); err == nil {
		t.Fatal("secondary boot code extending into the FAT was accepted")
	}
}
