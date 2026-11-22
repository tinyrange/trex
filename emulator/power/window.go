package power

import "fmt"

// TranslationWindow is a backend-owned linear mapping, independent of the
// guest's hashed page table. It can represent a firmware real-memory alias.
type TranslationWindow struct {
	Effective, Real, Size uint64
	Write, Execute, User  bool
}

// MapWindow installs a page-aligned, non-overlapping translation window.
// Windows apply only with translation enabled and take precedence over HPT
// entries. They occupy no guest HPT slots and survive guest HPT invalidation.
func (m *Machine) MapWindow(w TranslationWindow) error {
	if w.Size == 0 || (w.Effective|w.Real|w.Size)&4095 != 0 || w.Effective+w.Size < w.Effective || w.Real > uint64(len(m.Mem)) || w.Size > uint64(len(m.Mem))-w.Real {
		return fmt.Errorf("power: invalid translation window %x/%x+%x", w.Effective, w.Real, w.Size)
	}
	for _, old := range m.windows {
		if w.Effective < old.Effective+old.Size && old.Effective < w.Effective+w.Size {
			return fmt.Errorf("power: overlapping translation windows")
		}
	}
	m.windows = append(m.windows, w)
	m.hptGen++
	return nil
}

func (c *CPU) translateWindow(ea uint64, access int) (uint64, bool, error) {
	for _, w := range c.m.windows {
		if ea < w.Effective || ea-w.Effective >= w.Size {
			continue
		}
		if access&accessWrite != 0 && !w.Write || access&accessExec != 0 && !w.Execute || c.MSR&MSRPR != 0 && !w.User {
			return 0, true, &TranslateError{EA: ea, Protect: true}
		}
		return w.Real + ea - w.Effective, true, nil
	}
	return 0, false, nil
}
