package auto_test

import (
	"bytes"
	"errors"
	"github.com/tinyrange/trex/auto"
	_ "github.com/tinyrange/trex/auto/imports"
	"testing"
)

func TestLegacyRegistrations(t *testing.T) {
	formats := map[string]bool{}
	for _, name := range auto.Formats() {
		formats[name] = true
	}
	for _, name := range []string{"compress", "pack", "lha", "stuffit", "compactpro", "tome", "mac_resource", "bsd_dump", "bru", "irix_tape", "vmsbackup", "hunk_objects", "hunk_load", "aws", "apm", "sgi", "ultrix_label", "hfs", "efs", "ufs", "xfs", "ods2"} {
		if !formats[name] {
			t.Error("missing detector", name)
		}
	}
	for _, data := range [][]byte{nil, []byte("ordinary text"), []byte{1, 1, 0, 0, 0, 0, 0, 0}, bytes.Repeat([]byte{0x7f}, 65536)} {
		if _, err := auto.Identify(bytes.NewReader(data), auto.Options{}); !errors.Is(err, auto.ErrNoMatch) {
			t.Fatalf("unknown data: %v", err)
		}
	}
	for _, data := range [][]byte{[]byte("SIT!broken"), []byte("StuffIt broken"), []byte("XFSBbroken"), {0xac, 0xed, 0x12, 0x34}, {0x1f, 0x9d, 0}, {0x1f, 0x1e, 0}, {0x6b, 0x63, 0, 1}} {
		if _, err := auto.Identify(bytes.NewReader(data), auto.Options{}); err == nil || errors.Is(err, auto.ErrNoMatch) {
			t.Fatalf("confirmed malformed input became raw: %x %v", data, err)
		}
	}
}
