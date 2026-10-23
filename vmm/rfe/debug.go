package rfe

func (c *cpu) SetBreakpoint(address uint64) error { c.breakpoint = &address; return nil }
