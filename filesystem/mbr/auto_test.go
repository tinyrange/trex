package mbr

import (
	"encoding/binary"
	"errors"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestBootCodeIsNotPartitionTable(t *testing.T) {
	for _, active := range []byte{0x42, 0x80} {
		b := make([]byte, 512)
		b[510] = 0x55
		b[511] = 0xaa
		b[446] = active
		b[450] = 0x83
		binary.LittleEndian.PutUint32(b[458:], 100)
		if active == 0x42 {
			binary.LittleEndian.PutUint32(b[454:], 1)
		}
		if _, err := auto.Identify(&starfile.Bytes{Data: b}, auto.Options{}); !errors.Is(err, auto.ErrNoMatch) {
			t.Fatalf("boot code: %v", err)
		}
	}
	// Plausible table, but missing partition bytes: retain the MBR diagnostic.
	b := make([]byte, 512)
	b[510] = 0x55
	b[511] = 0xaa
	b[450] = 0x83
	binary.LittleEndian.PutUint32(b[454:], 1)
	binary.LittleEndian.PutUint32(b[458:], 100)
	if _, err := auto.Identify(&starfile.Bytes{Data: b}, auto.Options{}); err == nil || errors.Is(err, auto.ErrNoMatch) || !strings.Contains(err.Error(), "mbr") {
		t.Fatalf("corrupt table: %v", err)
	}
}
