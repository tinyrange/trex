package vmm

import (
	"io"
	"strings"
	"testing"
)

type bootSizeOnly int64

func (s bootSizeOnly) Size() int64                       { return int64(s) }
func (s bootSizeOnly) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }

func TestLinuxBootLimitsWithoutReadingPayload(t *testing.T) {
	for _, tc := range []struct {
		name  string
		boot  LinuxBoot
		valid bool
	}{
		{"maximum", LinuxBoot{Kernel: bootSizeOnly(256 << 20), Initramfs: bootSizeOnly(512 << 20), CommandLine: strings.Repeat("x", 64<<10)}, true},
		{"oversize-kernel", LinuxBoot{Kernel: bootSizeOnly((256 << 20) + 1)}, false},
		{"negative-kernel", LinuxBoot{Kernel: bootSizeOnly(-1)}, false},
		{"oversize-initramfs", LinuxBoot{Kernel: bootSizeOnly(1), Initramfs: bootSizeOnly((512 << 20) + 1)}, false},
		{"oversize-command", LinuxBoot{Kernel: bootSizeOnly(1), CommandLine: strings.Repeat("x", (64<<10)+1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.boot.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate = %v, valid = %v", err, tc.valid)
			}
		})
	}
}
