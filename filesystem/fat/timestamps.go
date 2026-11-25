package fat

import (
	"encoding/binary"
	"fmt"
	"time"

	filesystemapi "github.com/tinyrange/trex/filesystem"
)

// FAT stores calendar fields, not a timezone. Construction metadata is encoded
// using its UTC calendar, never the host's location. A recipe that intends a
// different local wall time must normalize its input explicitly. Zero means
// unspecified and preserves the historical all-zero directory fields.
type fatTimestamps struct {
	creationDate, creationTime uint16
	creationHundredths         byte
	accessDate                 uint16
	writeDate, writeTime       uint16
}

func fatCalendar(value uint64) (uint16, uint16, byte, error) {
	if value == 0 {
		return 0, 0, 0, nil
	}
	t := time.Unix(int64(value/10000000)-11644473600, int64(value%10000000)*100).UTC()
	if t.Year() < 1980 || t.Year() > 2107 {
		return 0, 0, 0, fmt.Errorf("FAT timestamp year %d outside 1980..2107", t.Year())
	}
	date := uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day())
	clock := uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)
	hundredths := byte(t.Second()%2*100 + t.Nanosecond()/10000000)
	return date, clock, hundredths, nil
}

func fatTimes(metadata filesystemapi.Metadata) (fatTimestamps, error) {
	var out fatTimestamps
	var err error
	out.creationDate, out.creationTime, out.creationHundredths, err = fatCalendar(metadata.CreationTime)
	if err != nil {
		return out, fmt.Errorf("creation time: %w", err)
	}
	out.accessDate, _, _, err = fatCalendar(metadata.LastAccessTime)
	if err != nil {
		return out, fmt.Errorf("access time: %w", err)
	}
	out.writeDate, out.writeTime, _, err = fatCalendar(metadata.LastWriteTime)
	if err != nil {
		return out, fmt.Errorf("write time: %w", err)
	}
	return out, nil
}

func (t fatTimestamps) apply(entry []byte) {
	entry[13] = t.creationHundredths
	binary.LittleEndian.PutUint16(entry[14:16], t.creationTime)
	binary.LittleEndian.PutUint16(entry[16:18], t.creationDate)
	binary.LittleEndian.PutUint16(entry[18:20], t.accessDate)
	binary.LittleEndian.PutUint16(entry[22:24], t.writeTime)
	binary.LittleEndian.PutUint16(entry[24:26], t.writeDate)
}

func (node *fat32Node) directoryEntry(attr byte) []byte {
	entry := fat32DirEntry(node.name, node.cluster, uint32(node.size), attr, node.short)
	node.times.apply(entry)
	return entry
}
