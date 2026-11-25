package fat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func timestampFiletime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600)*10000000 + uint64(t.Nanosecond()/100)
}

func timestampImage(t *testing.T, bits int, dir *filesystemapi.Directory) (starfile.File, error) {
	t.Helper()
	builtin, size := FAT12Builtin, 1440<<10
	if bits == 16 {
		builtin, size = FAT16Builtin, 64<<20
	}
	if bits == 32 {
		builtin, size = FAT32Builtin, 64<<20
	}
	value, err := builtin(nil, nil, starlark.Tuple{dir, starlark.MakeInt(size)}, nil)
	if err != nil {
		return nil, err
	}
	return value.(starfile.File), nil
}

func timestampEntry(t *testing.T, image starfile.File, offset int64, name string) []byte {
	t.Helper()
	raw := make([]byte, 512)
	if _, err := image.ReadAt(raw, offset); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(raw); n += 32 {
		if bytes.Equal(raw[n:n+11], []byte(name)) {
			return raw[n : n+32]
		}
	}
	t.Fatalf("missing short entry %q at %d", name, offset)
	return nil
}

func TestFATMetadataTimesOnDisk(t *testing.T) {
	// Leap day, odd seconds/centiseconds, the 1980 minimum, and a year beyond
	// time.Time.UnixNano's range exercise actual DOS format limits.
	creation := timestampFiletime(time.Date(2000, 2, 29, 23, 59, 59, 990000000, time.UTC))
	access := timestampFiletime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	write := timestampFiletime(time.Date(2107, 12, 31, 23, 59, 59, 0, time.UTC))
	for _, bits := range []int{12, 16, 32} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			dir := filesystemapi.New()
			dir.Mkdir("/SUB")
			for _, name := range []string{"/TEST.BIN", "/UNSET.BIN", "/SUB/NEST.BIN"} {
				dir.PutFile(name, filesystemapi.FileRecord{Data: []byte("payload"), Size: 7})
			}
			for _, name := range []string{"/TEST.BIN", "/SUB", "/SUB/NEST.BIN"} {
				if err := dir.SetTimes(name, creation, write, access); err != nil {
					t.Fatal(err)
				}
			}
			image, err := timestampImage(t, bits, dir)
			if err != nil {
				t.Fatal(err)
			}
			volume, err := newFATImage(image)
			if err != nil {
				t.Fatal(err)
			}
			root := volume.rootDirOffset
			if bits == 32 {
				root = volume.dataOffset + int64(volume.rootCluster-2)*volume.sectorsPerCluster*512
			}
			check := func(entry []byte) {
				t.Helper()
				if entry[13] != 199 || binary.LittleEndian.Uint16(entry[14:]) != 0xbf7d || binary.LittleEndian.Uint16(entry[16:]) != 0x285d || binary.LittleEndian.Uint16(entry[18:]) != 0x21 || binary.LittleEndian.Uint16(entry[22:]) != 0xbf7d || binary.LittleEndian.Uint16(entry[24:]) != 0xff9f {
					t.Fatalf("incorrect DOS timestamp fields: %x", entry)
				}
			}
			entry := timestampEntry(t, image, root, "TEST    BIN")
			check(entry)
			parsed, err := volume.lookup("/test.bin")
			if err != nil {
				t.Fatal(err)
			}
			if parsed.times.creationDate != 0x285d || parsed.times.creationTime != 0xbf7d || parsed.times.creationHundredths != 199 || parsed.times.accessDate != 0x21 || parsed.times.writeDate != 0xff9f || parsed.times.writeTime != 0xbf7d {
				t.Fatalf("reader lost original DOS date/time words: %+v", parsed.times)
			}
			metadata, err := volume.metadataBuiltin(nil, nil, starlark.Tuple{starlark.String("/TEST.BIN")}, nil)
			if err != nil {
				t.Fatal(err)
			}
			date, err := metadata.(starlark.HasAttrs).Attr("last_write_date")
			if err != nil || date.String() != "65439" {
				t.Fatalf("metadata date=%v error=%v", date, err)
			}
			unset := timestampEntry(t, image, root, "UNSET   BIN")
			if !bytes.Equal(unset[13:20], make([]byte, 7)) || !bytes.Equal(unset[22:26], make([]byte, 4)) {
				t.Fatalf("unspecified times changed: %x", unset)
			}
			sub := timestampEntry(t, image, root, "SUB        ")
			check(sub)
			cluster := uint32(binary.LittleEndian.Uint16(sub[26:]))
			if bits == 32 {
				cluster |= uint32(binary.LittleEndian.Uint16(sub[20:])) << 16
			}
			nested := volume.dataOffset + int64(cluster-2)*volume.sectorsPerCluster*512
			check(timestampEntry(t, image, nested, "NEST    BIN"))
			value, found, err := volume.Get(starlark.String("/SUB/NEST.BIN"))
			if err != nil || !found {
				t.Fatal("timestamp data corrupted cluster linkage", err)
			}
			content, err := starfile.ReadAll(value.(starfile.File))
			if err != nil || string(content) != "payload" {
				t.Fatalf("payload mismatch %q %v", content, err)
			}
		})
	}
}

func TestFATMetadataTimeBounds(t *testing.T) {
	for _, bits := range []int{12, 16, 32} {
		for _, date := range []time.Time{time.Date(1979, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(2108, 1, 1, 0, 0, 0, 0, time.UTC)} {
			for _, field := range []string{"creation", "access", "write"} {
				dir := filesystemapi.New()
				dir.PutFile("/BAD.TXT", filesystemapi.FileRecord{Data: []byte("x"), Size: 1})
				stamp := timestampFiletime(date)
				var c, w, a uint64
				switch field {
				case "creation":
					c = stamp
				case "access":
					a = stamp
				case "write":
					w = stamp
				}
				if err := dir.SetTimes("/BAD.TXT", c, w, a); err != nil {
					t.Fatal(err)
				}
				if _, err := timestampImage(t, bits, dir); err == nil {
					t.Fatalf("FAT%d accepted %s outside format range: %v", bits, field, date)
				}
			}
		}
	}
}

func TestFATLocalCalendarMetadataRejectsMalformedDates(t *testing.T) {
	for _, fields := range [][2]uint16{{0, 0}, {0x20, 0}, {0x285e, 0}, {0x21, 0xc000}, {0x21, 0x780}, {0x21, 31}} {
		if value := fatLocalFiletime(fields[0], fields[1]); value != starlark.None {
			t.Fatalf("invalid DOS calendar %04x/%04x became %s", fields[0], fields[1], value)
		}
	}
	if got := fatLocalFiletime(0x21, 0).String(); got != "119600064000000000" {
		t.Fatalf("epoch local FILETIME=%s", got)
	}
	if got := fatLocalFiletime(0x1eeb, 0x4e40).String(); got != "124499298000000000" {
		t.Fatalf("RTM source calendar local FILETIME=%s", got)
	}
}
