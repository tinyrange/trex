//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/storage"
	"golang.org/x/sys/unix"
	"j5.nz/cc/hypervisor"
)

type privateRAMImage struct {
	*os.File
	size     int64
	workers  *hypervisor.DirectWorkers
	template []byte
}

func (p *privateRAMImage) Size() int64 { return p.size }

func prepareRAM(source storage.Reader, sharedWorkers bool) (_ preparedRAM, err error) {
	fd, err := unix.MemfdCreate("trex-cc-ram", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "trex-cc-ram")
	defer func() {
		if err != nil {
			_ = file.Close()
		}
	}()
	size := source.Size()
	if err = file.Truncate(size); err != nil {
		return nil, err
	}
	extents := []block.Extent{{Length: size, Allocated: true}}
	if sparse, ok := source.(block.Extenter); ok {
		extents, err = sparse.Extents(0, size)
		if err != nil {
			return nil, err
		}
	}
	var position int64
	for _, extent := range extents {
		if extent.Offset != position || extent.Length <= 0 || extent.Length > size-position {
			return nil, fmt.Errorf("invalid extent in prepared RAM image")
		}
		position += extent.Length
		if !extent.Allocated {
			continue
		}
		n, err := io.Copy(io.NewOffsetWriter(file, extent.Offset), io.NewSectionReader(source, extent.Offset, extent.Length))
		if err != nil {
			return nil, err
		}
		if n != extent.Length {
			return nil, io.ErrUnexpectedEOF
		}
	}
	if position != size {
		return nil, io.ErrUnexpectedEOF
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	image := &privateRAMImage{File: file, size: size}
	if sharedWorkers {
		image.template, err = unix.Mmap(fd, 0, int(size), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil {
			return nil, err
		}
		image.workers, err = hypervisor.NewDirectWorkers(min(runtime.GOMAXPROCS(0), 64))
		if err != nil {
			_ = unix.Munmap(image.template)
			return nil, err
		}
	}
	return image, nil
}

func (p *privateRAMImage) mapPrivate(ram []byte) error {
	if int64(len(ram)) != p.size {
		return fmt.Errorf("prepared RAM mapping size is %d, expected %d", len(ram), p.size)
	}
	conn, err := p.SyscallConn()
	if err != nil {
		return err
	}
	var mapErr error
	err = conn.Control(func(fd uintptr) {
		// Replace just the prepared range of the accelerator's owned mapping.
		// KVM still sees the same host addresses, and its owner unmaps the
		// whole original span at teardown. No vCPU has executed yet.
		_, mapErr = unix.MmapPtr(int(fd), 0, unsafe.Pointer(&ram[0]), uintptr(p.size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_FIXED)
	})
	if err != nil {
		return err
	}
	return mapErr
}

func sampleRAM(ram []byte) ([]byte, error) {
	// Read through the kernel so simultaneous device writes do not race a
	// Go load. The owning driver holds the RAM mapping live for this call.
	data := make([]byte, len(ram))
	local := unix.Iovec{Base: &data[0]}
	local.SetLen(len(data))
	remote := unix.RemoteIovec{Base: uintptr(unsafe.Pointer(&ram[0])), Len: len(ram)}
	n, err := unix.ProcessVMReadv(os.Getpid(), []unix.Iovec{local}, []unix.RemoteIovec{remote}, 0)
	if err != nil {
		return nil, err
	}
	if n != len(ram) {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func (p *privateRAMImage) newDirectCPU(ctx context.Context) (hypervisor.X86, error) {
	return p.workers.NewCPU(ctx)
}

func (p *privateRAMImage) Close() error {
	var err error
	if p.workers != nil {
		if err := p.workers.Close(); err != nil {
			return err
		}
		err = unix.Munmap(p.template)
		p.template = nil
		p.workers = nil
	}
	return errors.Join(err, p.File.Close())
}

func (p *privateRAMImage) rewindTemplate() []byte { return p.template }

// privateResidentRAM counts present, exclusive anonymous pages without
// reading PFNs. The caller keeps the inspected mapping alive.
func privateResidentRAM(ram []byte) (int, error) {
	const page, entrySize = 4096, 8
	const exclusiveAnonymous = uint64(1<<63 | 1<<56)
	const mask = exclusiveAnonymous | 1<<61
	file, err := os.Open("/proc/self/pagemap")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	offset := int64(uintptr(unsafe.Pointer(&ram[0])) / page * entrySize)
	buffer := make([]byte, 16<<10)
	privatePages := 0
	for remaining := len(ram) / page * entrySize; remaining > 0; {
		count := min(remaining, len(buffer))
		if _, err := file.ReadAt(buffer[:count], offset); err != nil {
			return 0, err
		}
		for index := 0; index < count; index += entrySize {
			if binary.LittleEndian.Uint64(buffer[index:])&mask == exclusiveAnonymous {
				privatePages++
			}
		}
		offset += int64(count)
		remaining -= count
	}
	return privatePages * page, nil
}
