package power

import (
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type cpuValue struct {
	c *CPU
	// methods caches bound method builtins; they depend only on c.
	methods map[string]starlark.Value
}

func (v *cpuValue) String() string        { return v.c.String() }
func (v *cpuValue) Type() string          { return "power_cpu" }
func (v *cpuValue) Freeze()               {}
func (v *cpuValue) Truth() starlark.Bool  { return starlark.True }
func (v *cpuValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: power cpu") }

var cpuFields = []string{"index", "pc", "msr", "cr", "lr", "ctr", "xer", "srr0", "srr1", "dar", "dsisr", "dec", "fpscr", "instructions", "running", "waiting"}
var cpuMethods = []string{"copy_real_page", "crbit", "fpr", "gpr", "hpte", "hpte_slot", "load", "read", "registers", "reservation", "set", "set_crbit", "set_external_interrupt", "set_gpr", "set_running", "set_spr", "slb", "slbmte", "spr", "stop", "store", "translate", "vsr", "wait_for_interrupt", "wake", "write", "yield_quantum"}

func (v *cpuValue) AttrNames() []string {
	return append(append(append([]string{}, cpuFields...), cpuMethods...), "encode_issi", "decode_issi", "capture_page_tags", "restore_page_tags", "copy_real_tagged")
}

func (v *cpuValue) field(name string) (uint64, bool) {
	c := v.c
	switch name {
	case "index":
		return uint64(c.Index), true
	case "pc":
		return c.PC, true
	case "msr":
		return c.MSR, true
	case "cr":
		return uint64(c.CR), true
	case "lr":
		return c.LR, true
	case "ctr":
		return c.CTR, true
	case "xer":
		return c.XER, true
	case "srr0":
		return c.SRR0, true
	case "srr1":
		return c.SRR1, true
	case "dar":
		return c.DAR, true
	case "dsisr":
		return uint64(c.DSISR), true
	case "dec":
		return c.DEC(), true
	case "fpscr":
		return c.FPSCR, true
	case "instructions":
		return c.Instructions, true
	}
	return 0, false
}

func (v *cpuValue) setField(name string, x uint64) error {
	c := v.c
	switch name {
	case "pc":
		c.PC = x
	case "msr":
		// Translation does not depend on the MSR; interrupt state may.
		c.MSR = x
		c.sync = true
	case "cr":
		c.CR = uint32(x)
	case "lr":
		c.LR = x
	case "ctr":
		c.CTR = x
	case "xer":
		c.XER = x
	case "srr0":
		c.SRR0 = x
	case "srr1":
		c.SRR1 = x
	case "dar":
		c.DAR = x
	case "dsisr":
		c.DSISR = uint32(x)
	case "dec":
		c.SetDEC(x)
	case "fpscr":
		c.FPSCR = x
	default:
		return fmt.Errorf("set: unknown register %q", name)
	}
	return nil
}

func (v *cpuValue) Attr(name string) (starlark.Value, error) {
	if m, ok := v.methods[name]; ok {
		return m, nil
	}
	x, err := v.attr(name)
	if b, ok := x.(*starlark.Builtin); ok && err == nil {
		if v.methods == nil {
			v.methods = map[string]starlark.Value{}
		}
		v.methods[name] = b
	}
	return x, err
}

func (v *cpuValue) attr(name string) (starlark.Value, error) {
	if name == "running" {
		return starlark.Bool(!v.c.Parked), nil
	}
	if name == "waiting" {
		return starlark.Bool(v.c.Waiting), nil
	}
	if x, ok := v.field(name); ok {
		return starlark.MakeUint64(x), nil
	}
	c := v.c
	b := func(f func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)) starlark.Value {
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return f(args, kwargs)
		})
	}
	reg := func(args starlark.Tuple, kwargs []starlark.Tuple, limit int) (int, error) {
		var i int
		if err := starlark.UnpackArgs(name, args, kwargs, "index", &i); err != nil {
			return 0, err
		}
		if i < 0 || i >= limit {
			return 0, fmt.Errorf("%s: index %d out of range", name, i)
		}
		return i, nil
	}
	switch name {
	case "encode_issi":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var sidecar, headers, page, stamp uint64
			var flags uint32
			if err := starlark.UnpackArgs(name, args, kwargs, "sidecar", &sidecar, "headers", &headers, "page", &page, "stamp", &stamp, "flags", &flags); err != nil {
				return nil, err
			}
			return starlark.None, c.EncodeISSI(sidecar, headers, page, stamp, flags)
		}), nil
	case "capture_page_tags":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var headers, page uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "headers", &headers, "page", &page); err != nil {
				return nil, err
			}
			return starlark.None, c.CapturePageTags(headers, page)
		}), nil
	case "restore_page_tags":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var page uint64
			var tags [4]uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "page", &page, "tags0", &tags[0], "tags1", &tags[1], "tags2", &tags[2], "tags3", &tags[3]); err != nil {
				return nil, err
			}
			return starlark.None, c.RestorePageTags(page, tags)
		}), nil
	case "decode_issi":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var sidecar, headers, page uint64
			var flags uint32
			if err := starlark.UnpackArgs(name, args, kwargs, "sidecar", &sidecar, "headers", &headers, "page", &page, "flags", &flags); err != nil {
				return nil, err
			}
			return starlark.None, c.DecodeISSI(sidecar, headers, page, flags)
		}), nil
	case "set_external_interrupt":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var asserted bool
			if err := starlark.UnpackArgs(name, args, kwargs, "asserted", &asserted); err != nil {
				return nil, err
			}
			c.SetExternalInterrupt(asserted)
			return starlark.None, nil
		}), nil
	case "yield_quantum":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			c.Yield()
			return starlark.None, nil
		}), nil
	case "wait_for_interrupt", "wake":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			if name == "wake" {
				c.Wake()
			} else {
				c.WaitForInterrupt()
			}
			return starlark.None, nil
		}), nil
	case "set_running":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var running bool
			if err := starlark.UnpackArgs(name, args, kwargs, "running", &running); err != nil {
				return nil, err
			}
			c.Parked = !running
			return starlark.None, nil
		}), nil
	case "gpr":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i, err := reg(args, kwargs, 32)
			if err != nil {
				return nil, err
			}
			return starlark.MakeUint64(c.GPR[i]), nil
		}), nil
	case "fpr":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i, err := reg(args, kwargs, 32)
			if err != nil {
				return nil, err
			}
			return starlark.MakeUint64(c.FPR[i]), nil
		}), nil
	case "vsr":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i, err := reg(args, kwargs, 64)
			if err != nil {
				return nil, err
			}
			value := c.readVSR(uint32(i))
			return starlark.Tuple{starlark.MakeUint64(value[0]), starlark.MakeUint64(value[1])}, nil
		}), nil
	case "crbit":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i, err := reg(args, kwargs, 32)
			if err != nil {
				return nil, err
			}
			return starlark.Bool(c.CRBit(uint(i))), nil
		}), nil
	case "set_crbit":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var i int
			var on bool
			if err := starlark.UnpackArgs(name, args, kwargs, "index", &i, "value", &on); err != nil {
				return nil, err
			}
			if i < 0 || i > 31 {
				return nil, fmt.Errorf("set_crbit: index")
			}
			c.SetCRBit(uint(i), on)
			return starlark.None, nil
		}), nil
	case "set_gpr", "set_spr":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var i int
			var x starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "index", &i, "value", &x); err != nil {
				return nil, err
			}
			u, err := U64(x)
			if err != nil {
				return nil, err
			}
			if name == "set_gpr" {
				if i < 0 || i > 31 {
					return nil, fmt.Errorf("set_gpr: index")
				}
				c.GPR[i] = u
				return starlark.None, nil
			}
			if i < 0 || i > 1023 {
				return nil, fmt.Errorf("set_spr: index")
			}
			saved := c.MSR
			c.MSR &^= MSRPR
			c.mtspr(i, u)
			c.MSR = saved
			return starlark.None, nil
		}), nil
	case "spr":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i, err := reg(args, kwargs, 1024)
			if err != nil {
				return nil, err
			}
			saved := c.MSR
			c.MSR &^= MSRPR
			x, _ := c.mfspr(i)
			c.MSR = saved
			return starlark.MakeUint64(x), nil
		}), nil
	case "set":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if len(args) != 0 {
				return nil, fmt.Errorf("set: keyword arguments only")
			}
			for _, kv := range kwargs {
				k := string(kv[0].(starlark.String))
				if k == "gpr" {
					d, ok := kv[1].(*starlark.Dict)
					if !ok {
						return nil, fmt.Errorf("set: gpr must be a dict of index to value")
					}
					for _, item := range d.Items() {
						i, err := starlark.AsInt32(item[0])
						if err != nil || i < 0 || i > 31 {
							return nil, fmt.Errorf("set: gpr index")
						}
						u, err := U64(item[1])
						if err != nil {
							return nil, err
						}
						c.GPR[i] = u
					}
					continue
				}
				u, err := U64(kv[1])
				if err != nil {
					return nil, fmt.Errorf("set: %s: %w", k, err)
				}
				if err := v.setField(k, u); err != nil {
					return nil, err
				}
			}
			return starlark.None, nil
		}), nil
	case "registers":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			d := starlark.StringDict{}
			for _, f := range cpuFields {
				if f == "running" || f == "waiting" {
					d[f], _ = v.Attr(f)
					continue
				}
				x, _ := v.field(f)
				d[f] = starlark.MakeUint64(x)
			}
			g := make([]starlark.Value, 32)
			for i := range g {
				g[i] = starlark.MakeUint64(c.GPR[i])
			}
			d["gpr"] = starlark.NewList(g)
			s := make([]starlark.Value, 4)
			for i := range s {
				s[i] = starlark.MakeUint64(c.SPRG[i])
			}
			d["sprg"] = starlark.NewList(s)
			return starfile.NewRecord(d), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "read":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var a starlark.Value
			var n int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &a, "size", &n); err != nil {
				return nil, err
			}
			ea, err := U64(a)
			if err != nil {
				return nil, err
			}
			if n < 0 || n > 64<<20 {
				return nil, fmt.Errorf("read: size")
			}
			d, err := c.ReadEffective(ea, n)
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(d), nil
		}), nil
	case "write":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var a, data starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &a, "data", &data); err != nil {
				return nil, err
			}
			ea, err := U64(a)
			if err != nil {
				return nil, err
			}
			d, err := bytesOf(data)
			if err != nil {
				return nil, err
			}
			return starlark.None, c.WriteEffective(ea, d)
		}), nil
	case "load":
		// load(address, size): an architected load; None after raising an interrupt.
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var a starlark.Value
			var n int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &a, "size", &n); err != nil {
				return nil, err
			}
			ea, err := U64(a)
			if err != nil {
				return nil, err
			}
			if n != 1 && n != 2 && n != 4 && n != 8 {
				return nil, fmt.Errorf("load: size must be 1, 2, 4 or 8")
			}
			x, ok := c.Load(ea, n)
			if !ok {
				return starlark.None, nil
			}
			return starlark.MakeUint64(x), nil
		}), nil
	case "store":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var a, x starlark.Value
			var n int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &a, "size", &n, "value", &x); err != nil {
				return nil, err
			}
			ea, err := U64(a)
			if err != nil {
				return nil, err
			}
			u, err := U64(x)
			if err != nil {
				return nil, err
			}
			if n != 1 && n != 2 && n != 4 && n != 8 {
				return nil, fmt.Errorf("store: size must be 1, 2, 4 or 8")
			}
			return starlark.Bool(c.Store(ea, n, u)), nil
		}), nil
	case "translate":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var a starlark.Value
			instruction := false
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &a, "instruction?", &instruction); err != nil {
				return nil, err
			}
			ea, err := U64(a)
			if err != nil {
				return nil, err
			}
			r, err := c.Translate(ea, instruction, accessRead)
			if err != nil {
				return starlark.None, nil
			}
			return starlark.MakeUint64(r), nil
		}), nil
	case "copy_real_tagged":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var dstV, srcV, sizeV starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "destination", &dstV, "source", &srcV, "size", &sizeV); err != nil {
				return nil, err
			}
			dst, err := U64(dstV)
			if err != nil {
				return nil, err
			}
			src, err := U64(srcV)
			if err != nil {
				return nil, err
			}
			size, err := U64(sizeV)
			if err != nil {
				return nil, err
			}
			return starlark.None, c.CopyRealTagged(dst, src, size)
		}), nil
	case "copy_real_page":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var dstV, srcV starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "destination", &dstV, "source", &srcV); err != nil {
				return nil, err
			}
			dst, err := U64(dstV)
			if err != nil {
				return nil, err
			}
			src, err := U64(srcV)
			if err != nil {
				return nil, err
			}
			return starlark.None, c.CopyRealPage(dst, src)
		}), nil
	case "hpte", "hpte_slot":
		// hpte(address): (dword0, dword1) of the page table entry translating
		// the effective address, or None if unmapped.
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var a starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &a); err != nil {
				return nil, err
			}
			ea, err := U64(a)
			if err != nil {
				return nil, err
			}
			if name == "hpte_slot" {
				slot, ok := c.HPTESlot(ea)
				if !ok {
					return starlark.None, nil
				}
				return starlark.MakeUint64(slot), nil
			}
			d0, d1, ok := c.HPTE(ea)
			if !ok {
				return starlark.None, nil
			}
			return starlark.Tuple{starlark.MakeUint64(d0), starlark.MakeUint64(d1)}, nil
		}), nil
	case "slbmte":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var rs, rb starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "rs", &rs, "rb", &rb); err != nil {
				return nil, err
			}
			s, err := U64(rs)
			if err != nil {
				return nil, err
			}
			r, err := U64(rb)
			if err != nil {
				return nil, err
			}
			return starlark.None, c.SLBMTE(s, r)
		}), nil
	case "slb":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var out []starlark.Value
			for i, e := range c.SLB {
				if !e.Valid {
					continue
				}
				out = append(out, starfile.NewRecord(starlark.StringDict{"index": starlark.MakeInt(i), "esid": starlark.MakeUint64(e.ESID),
					"vsid": starlark.MakeUint64(e.VSID), "segment_1t": starlark.Bool(e.B == 1), "flags": starlark.MakeUint64(e.Flags),
					"page_shift": starlark.MakeInt(int(e.PageShift()))}))
			}
			return starlark.NewList(out), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "reservation":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			a, ok := c.Reservation()
			if !ok {
				return starlark.None, starlark.UnpackArgs(name, args, kwargs)
			}
			return starlark.MakeUint64(a), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "stop":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			kind, detail := "stopped", ""
			if err := starlark.UnpackArgs(name, args, kwargs, "kind?", &kind, "detail?", &detail); err != nil {
				return nil, err
			}
			c.Stop(kind, detail)
			return starlark.None, nil
		}), nil
	}
	return nil, nil
}
