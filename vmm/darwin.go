package vmm

import (
	"fmt"
	"github.com/tinyrange/trex/boot/darwin"
	"github.com/tinyrange/trex/storage"
	"strings"
)

// DarwinBoot requests the unslid amd64 XNU v2 handoff, not UEFI image execution.
type DarwinBoot struct {
	Kernel      storage.Reader
	CommandLine string
	// SMCOSK is optional caller-supplied 64-byte SMC key material. Nil leaves
	// OSK0/OSK1 absent; the platform never manufactures these keys.
	SMCOSK []byte
}

func (b DarwinBoot) Validate() error {
	if b.Kernel == nil || b.Kernel.Size() < 4 || b.Kernel.Size() > darwin.MaxKernelSize {
		return fmt.Errorf("darwin_boot: kernel size outside bounds")
	}
	if len(b.CommandLine) > 1023 || strings.ContainsRune(b.CommandLine, 0) {
		return fmt.Errorf("darwin_boot: invalid command line")
	}
	if len(b.SMCOSK) != 0 && len(b.SMCOSK) != 64 {
		return fmt.Errorf("darwin_boot: smc_osk must be empty or exactly 64 bytes")
	}
	return nil
}
