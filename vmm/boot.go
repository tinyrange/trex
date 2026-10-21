package vmm

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/storage"
)

// LinuxBoot is direct Linux boot intent. Sources are borrowed immutable files,
// independent of OS filenames, sockets, or emulator command-line options.
// Firmware/partition boot remains the default when Machine.Boot is nil.
type LinuxBoot struct {
	Kernel      storage.Reader
	Initramfs   storage.Reader
	CommandLine string
}

func (b *LinuxBoot) Validate() error {
	if b == nil {
		return nil
	}
	if b.Kernel == nil || b.Kernel.Size() <= 0 || b.Kernel.Size() > 256<<20 {
		return fmt.Errorf("Linux boot kernel must be a nonempty file up to 256 MiB")
	}
	if b.Initramfs != nil && (b.Initramfs.Size() <= 0 || b.Initramfs.Size() > 512<<20) {
		return fmt.Errorf("Linux boot initramfs must be a nonempty file up to 512 MiB")
	}
	if strings.ContainsRune(b.CommandLine, 0) || len(b.CommandLine) > 64<<10 {
		return fmt.Errorf("Linux boot command line contains NUL or exceeds 64 KiB")
	}
	return nil
}
