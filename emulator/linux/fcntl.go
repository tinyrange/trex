package linux

import "fmt"

// AppendSetter changes the shared open-file description's append behavior.
// Providers that cannot change it must not silently claim success.
type AppendSetter interface{ SetAppend(bool) error }

func (p *process) descriptor(fd uint64) (*descriptor, bool) {
	d, ok := p.files[fd]
	if !ok && fd < 3 && !p.closed[fd] {
		d = &descriptor{}
		if fd == 0 {
			d.flags = Read
			d.reader = p.cfg.Stdin
		} else {
			d.flags = Write
			d.status = 1
			if fd == 1 {
				d.writer = p.cfg.Stdout
			} else {
				d.writer = p.cfg.Stderr
			}
		}
		p.files[fd] = d
	}

	return d, d != nil
}
func (p *process) setCloseOnExec(fd uint64, enabled bool) {
	if p.closeOnExec == nil {
		p.closeOnExec = make(map[uint64]bool)
	}
	if enabled {
		p.closeOnExec[fd] = true
	} else {
		delete(p.closeOnExec, fd)
	}
}
func (p *process) fileControl(fd, action, arg uint64) error {
	d, ok := p.descriptor(fd)
	if !ok {
		p.errno(9)
		return nil
	}
	switch action {
	case 0, 1030: // F_DUPFD, F_DUPFD_CLOEXEC
		if arg >= 1024 {
			p.errno(22)
			return nil
		}
		candidate := arg
		for ; candidate < 1024; candidate++ {
			if _, used := p.descriptor(candidate); !used {
				break
			}
		}
		if candidate == 1024 {
			p.errno(24)
			return nil
		}
		p.files[candidate] = d
		p.setCloseOnExec(candidate, action == 1030)
		p.ret(candidate)
	case 1: // F_GETFD: descriptor flag, not shared across aliases
		if p.closeOnExec[fd] {
			p.ret(1)
		} else {
			p.ret(0)
		}
	case 2:
		p.setCloseOnExec(fd, arg&1 != 0)
		p.ret(0)
	case 3: // F_GETFL: shared open status flags
		p.ret(d.status)
	case 4:
		// Access mode and creation flags are ignored by F_SETFL. Other mutable
		// flags require their own provider semantics, not synthetic success.
		if arg&(2048|8192|16384|262144) != 0 {
			return fmt.Errorf("linux: unsupported F_SETFL status flags %#x", arg)
		}
		if (arg^d.status)&1024 != 0 {
			setter, ok := d.file.(AppendSetter)
			if !ok {
				return fmt.Errorf("linux: file provider cannot change append mode")
			}
			if err := setter.SetAppend(arg&1024 != 0); err != nil {
				if n := fileErrno(err); n != 0 {
					p.errno(n)
					return nil
				}
				return err
			}
			d.status = d.status&^1024 | arg&1024
		}
		p.ret(0)
	default:
		return fmt.Errorf("linux: unsupported fcntl command %d", action)
	}
	return nil
}
