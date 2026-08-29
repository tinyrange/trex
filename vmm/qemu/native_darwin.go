//go:build darwin

package qemu

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func qemuNativeAvailable() bool { return true }

func qemuCreateAnonymousFile(label string) (*os.File, error) {
	return nil, fmt.Errorf("create anonymous QEMU file %q: Darwin has no seekable anonymous-file primitive", label)
}

func qemuDuplicateFile(file *os.File, name string) (*os.File, error) {
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		return nil, fmt.Errorf("duplicate anonymous QEMU file %q: %w", name, err)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), name), nil
}

func qemuCreateCaptureFiles(name string) (*os.File, *os.File, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create QEMU capture pipe %q: %w", name, err)
	}
	return reader, writer, nil
}

func qemuCaptureUsesStream() bool { return true }

func qemuSocketpair() ([2]int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	return fds, err
}

func qemuInheritedFDPath(fd int) string {
	return fmt.Sprintf("/dev/fd/%d", fd)
}
