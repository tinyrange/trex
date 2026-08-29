//go:build windows

package qemu

import (
	"fmt"
	"os"
)

// Go's os/exec does not support ExtraFiles on Windows. Keep the backend out of
// the native registry until its QMP, GDB, channel, firmware, ACPI, and capture
// transports can all be expressed without inherited POSIX descriptors.
func qemuNativeAvailable() bool { return false }

func qemuCreateAnonymousFile(name string) (*os.File, error) {
	return nil, fmt.Errorf("create anonymous QEMU file %q: inherited QEMU files are unavailable on Windows", name)
}

func qemuCreateCaptureFiles(name string) (*os.File, *os.File, error) {
	return nil, nil, fmt.Errorf("create QEMU capture transport %q: inherited QEMU files are unavailable on Windows", name)
}

func qemuCaptureUsesStream() bool { return false }

func qemuSocketpair() ([2]int, error) {
	return [2]int{}, fmt.Errorf("create QEMU byte channel: inherited QEMU sockets are unavailable on Windows")
}

// startQEMU rejects this platform before constructing inherited-file arguments.
func qemuInheritedFDPath(int) string { return "" }
