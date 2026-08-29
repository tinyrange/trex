package windows

import (
	"encoding/binary"
	"testing"
)

func TestParseMSFTTypeLib(t *testing.T) {
	data := testMSFTTypeLib(t)
	library, err := parseMSFTTypeLib(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := library.guid, "{A5064420-D541-11D4-9523-00B0D022CA64}"; got != want {
		t.Fatalf("library GUID = %q, want %q", got, want)
	}
	if library.name != "NUSRMGRLib" || library.description != "User Accounts 2.3 Type Library" || library.major != 2 || library.minor != 3 || library.language != 0x409 || library.lcid != 0 || library.flags != 1 || library.syskind != 1 {
		t.Fatalf("library metadata = %#v", library)
	}
	if got, want := len(library.typeInfo), 1; got != want {
		t.Fatalf("type count = %d, want %d", got, want)
	}
	info := library.typeInfo[0]
	if info.guid != "{A5064425-D541-11D4-9523-00B0D022CA64}" || info.name != "IToolbar" || info.kind != msftTypeKindDispatch || info.flags != msftTypeFlagDual|msftTypeFlagAutomation {
		t.Fatalf("type metadata = %#v", info)
	}
}

func TestParseMSFTTypeLibRejectsInvalidSegments(t *testing.T) {
	data := testMSFTTypeLib(t)
	segmentDirectory := msftTypeLibHeaderSize + 4
	binary.LittleEndian.PutUint32(data[segmentDirectory+msftGUIDSegment*16:], uint32(len(data)+1))
	if _, err := parseMSFTTypeLib(data); err == nil {
		t.Fatal("invalid GUID segment was accepted")
	}
}

func testMSFTTypeLib(t *testing.T) []byte {
	t.Helper()
	const (
		typeCount        = 1
		segmentDirectory = msftTypeLibHeaderSize + typeCount*4
		typeOffset       = segmentDirectory + msftTypeLibSegmentCount*16
		guidOffset       = typeOffset + msftTypeInfoSize
		guidLength       = 48
		nameOffset       = guidOffset + guidLength
	)
	nameEntry := func(value string) []byte {
		entry := make([]byte, 12+len(value))
		binary.LittleEndian.PutUint32(entry[8:], uint32(len(value)))
		copy(entry[12:], value)
		return entry
	}
	libraryName := nameEntry("NUSRMGRLib")
	interfaceName := nameEntry("IToolbar")
	nameLength := len(libraryName) + len(interfaceName)
	description := []byte("User Accounts 2.3 Type Library")
	stringEntry := make([]byte, 2+len(description))
	binary.LittleEndian.PutUint16(stringEntry, uint16(len(description)))
	copy(stringEntry[2:], description)
	stringOffset := nameOffset + nameLength
	data := make([]byte, stringOffset+len(stringEntry))
	copy(data, "MSFT")
	binary.LittleEndian.PutUint32(data[0x08:], 0)
	binary.LittleEndian.PutUint32(data[0x0c:], 0x409)
	binary.LittleEndian.PutUint32(data[0x10:], 0)
	binary.LittleEndian.PutUint32(data[0x14:], 1)
	binary.LittleEndian.PutUint32(data[0x18:], 2|(3<<16))
	binary.LittleEndian.PutUint32(data[0x1c:], 1)
	binary.LittleEndian.PutUint32(data[0x20:], typeCount)
	binary.LittleEndian.PutUint32(data[0x38:], 0)
	for index := 0; index < msftTypeLibSegmentCount; index++ {
		entry := segmentDirectory + index*16
		binary.LittleEndian.PutUint32(data[entry:], ^uint32(0))
	}
	setSegment := func(index, offset, length int) {
		entry := segmentDirectory + index*16
		binary.LittleEndian.PutUint32(data[entry:], uint32(offset))
		binary.LittleEndian.PutUint32(data[entry+4:], uint32(length))
	}
	setSegment(msftTypeInfoSegment, typeOffset, msftTypeInfoSize)
	setSegment(msftGUIDSegment, guidOffset, guidLength)
	setSegment(msftNameSegment, nameOffset, nameLength)
	setSegment(msftStringSegment, stringOffset, len(stringEntry))

	libraryGUID, ok := parseWindowsGUID("{A5064420-D541-11D4-9523-00B0D022CA64}")
	if !ok {
		t.Fatal("could not parse test library GUID")
	}
	interfaceGUID, ok := parseWindowsGUID("{A5064425-D541-11D4-9523-00B0D022CA64}")
	if !ok {
		t.Fatal("could not parse test interface GUID")
	}
	copy(data[guidOffset:], libraryGUID[:])
	copy(data[guidOffset+24:], interfaceGUID[:])
	typeInfo := data[typeOffset : typeOffset+msftTypeInfoSize]
	binary.LittleEndian.PutUint32(typeInfo, msftTypeKindDispatch)
	binary.LittleEndian.PutUint32(typeInfo[0x2c:], 24)
	binary.LittleEndian.PutUint32(typeInfo[0x30:], msftTypeFlagDual|msftTypeFlagAutomation)
	binary.LittleEndian.PutUint32(typeInfo[0x34:], uint32(len(libraryName)))
	copy(data[nameOffset:], libraryName)
	copy(data[nameOffset+len(libraryName):], interfaceName)
	copy(data[stringOffset:], stringEntry)
	return data
}
