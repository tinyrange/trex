package linux

import (
	"errors"
	"fmt"
	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/emulator/cpu"
	"io"
	"io/fs"
	"path"
)

// OpenFlags are portable guest file operations, not host OS constants.
type OpenFlags uint8

const (
	Read OpenFlags = 1 << iota
	Write
	Create
	Truncate
	Append
	Exclusive
)

// FileSystem receives normalized absolute guest paths and masked creation modes.
// Returned channels belong to the emulated process and are closed on every exit.
type FileSystem interface {
	Open(name string, flags OpenFlags, mode fs.FileMode) (channel.ByteChannel, error)
}
type descriptor struct {
	status uint64
	file   channel.ByteChannel
	flags  OpenFlags
	reader io.Reader
	writer io.Writer
}

// Errno is an explicit guest I/O error returned by portable filesystem or
// stdio providers. Unknown Go errors remain emulator failures, never errno.
type Errno int

func (e Errno) Error() string { return fmt.Sprintf("linux errno %d", int(e)) }

func fileErrno(err error) int {
	if errors.Is(err, channel.ErrNoSpace) {
		return 28
	}
	var errno Errno
	if errors.As(err, &errno) && errno > 0 && errno < 4096 {
		return int(errno)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 2
	case errors.Is(err, fs.ErrExist):
		return 17
	case errors.Is(err, fs.ErrPermission):
		return 13
	case errors.Is(err, fs.ErrClosed):
		return 9
	case errors.Is(err, fs.ErrInvalid):
		return 22
	}
	return 0 // An unknown backend failure is not a guest feature-probe result.
}
func (p *process) openFile(address, flags, mode uint64) error {
	if p.cfg.Files == nil {
		return fmt.Errorf("linux: guest filesystem is not configured")
	}
	// Access, create, exclusive, truncate, append, largefile, close-on-exec.
	// There is no exec yet, so close-on-exec needs no extra state.
	if flags & ^uint64(3|64|128|512|1024|32768|524288) != 0 {
		return fmt.Errorf("linux: unsupported open flags %#x", flags)
	}
	if flags&3 == 3 {
		p.errno(22)
		return nil
	}
	var name []byte
	for i := uint64(0); i < 4096; i++ {
		var ch [1]byte
		if err := p.memory.ReadMemory(address+i, ch[:], cpu.Read); err != nil {
			p.errno(14)
			return nil
		}
		if ch[0] == 0 {
			break
		}
		name = append(name, ch[0])
	}
	if len(name) == 4096 {
		p.errno(36)
		return nil
	}
	if len(name) == 0 {
		p.errno(2)
		return nil
	}
	filename := string(name)
	if !path.IsAbs(filename) {
		filename = path.Join(p.cfg.Dir, filename)
	}
	filename = path.Clean(filename)
	access := Read
	if flags&3 == 1 {
		access = Write
	} else if flags&3 == 2 {
		access = Read | Write
	}
	if flags&64 != 0 {
		access |= Create
	}
	if flags&128 != 0 {
		access |= Exclusive
	}
	if flags&512 != 0 {
		access |= Truncate
	}
	if flags&1024 != 0 {
		access |= Append
	}
	fd := uint64(0)
	for ; fd < 1024; fd++ {
		if fd < 3 && !p.closed[fd] {
			continue
		}
		if _, ok := p.files[fd]; !ok {
			break
		}
	}
	if fd == 1024 {
		p.errno(24)
		return nil
	}
	file, err := p.cfg.Files.Open(filename, access, fs.FileMode(mode&0777)&^p.umask)
	if err != nil {
		if n := fileErrno(err); n != 0 {
			p.errno(n)
			return nil
		}
		return err
	}
	p.files[fd] = &descriptor{file: file, flags: access, reader: file, writer: file, status: flags&^(64|128|256|512|524288) | 32768}
	p.setCloseOnExec(fd, flags&524288 != 0)
	p.ret(fd)
	return nil
}
func (p *process) closeFiles() {
	for fd := range p.files {
		_ = p.closeDescriptor(fd)
	}
}
func (p *process) fileIO(number, fd, address, size uint64) error {
	var reader io.Reader
	var writer io.Writer
	if d, ok := p.files[fd]; ok {
		if d.flags&Read != 0 {
			reader = d.reader
		}
		if d.flags&Write != 0 {
			writer = d.writer
		}
	} else if fd < 3 && !p.closed[fd] {
		if fd == 0 {
			reader = p.cfg.Stdin
		} else if fd == 1 {
			writer = p.cfg.Stdout
		} else {
			writer = p.cfg.Stderr
		}
	}
	if number == 0 && reader == nil || number == 1 && writer == nil {
		p.errno(9)
		return nil
	}
	if size > 8<<20 {
		return fmt.Errorf("linux: syscall I/O budget exceeded")
	}
	access := cpu.Read
	if number == 0 {
		access = cpu.Write
	}
	if err := p.memory.CheckMemory(address, int(size), access); err != nil {
		p.errno(14)
		return nil
	}
	data := make([]byte, int(size))
	var n int
	var err error
	if number == 0 {
		n, err = reader.Read(data)
	} else {
		if err := p.memory.ReadMemory(address, data, cpu.Read); err != nil {
			return err
		}
		n, err = writer.Write(data)
	}
	if n < 0 || n > len(data) {
		return fmt.Errorf("linux: invalid I/O result")
	}
	if err != nil && !errors.Is(err, io.EOF) && n == 0 {
		if eno := fileErrno(err); eno != 0 {
			p.errno(eno)
			return nil
		}
		return err
	}
	if number == 0 {
		if err := p.memory.WriteMemory(address, data[:n]); err != nil {
			return err
		}
	}
	p.ret(uint64(n))
	return nil
}

// Descriptors alias an open-file description, sharing its offset and lifetime.
func (p *process) closeDescriptor(fd uint64) error {
	delete(p.closeOnExec, fd)
	if d, ok := p.files[fd]; ok {
		delete(p.files, fd)
		if fd < 3 {
			p.closed[fd] = true
		}
		for _, other := range p.files {
			if other == d {
				return nil
			}
		}
		if d.file != nil {
			return d.file.Close()
		}
		return nil
	}
	if fd < 3 && !p.closed[fd] {
		p.closed[fd] = true
		return nil
	}
	return Errno(9)
}
func (p *process) duplicateDescriptor(oldfd, newfd uint64) error {
	d, ok := p.descriptor(oldfd)
	if !ok || newfd >= 1024 {
		p.errno(9)
		return nil
	}
	if oldfd == newfd {
		p.ret(newfd)
		return nil
	}
	// dup2 discards errors closing the destination, but host/backend failures
	// are not guest errno and must remain visible.
	if err := p.closeDescriptor(newfd); err != nil && fileErrno(err) == 0 {
		return err
	}
	p.files[newfd] = d
	p.setCloseOnExec(newfd, false)
	p.ret(newfd)
	return nil
}
