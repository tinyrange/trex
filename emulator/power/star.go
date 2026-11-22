package power

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/block"
	blockstar "github.com/tinyrange/trex/block/star"
	"github.com/tinyrange/trex/scsi"
	"io"
	"math/big"
	"sort"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"golang.org/x/arch/ppc64/ppc64asm"
)

// Builtin creates a partition: emulator.power(memory=, cpus=, mips=, pvr=).
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	memory, cpus, mips, pvr := 256<<20, 1, 100, 0
	var extensions *starlark.List
	if err := starlark.UnpackArgs("power", args, kwargs, "memory?", &memory, "cpus?", &cpus, "mips?", &mips, "pvr?", &pvr, "extensions?", &extensions); err != nil {
		return nil, err
	}
	var ext []string
	if extensions != nil {
		for i := 0; i < extensions.Len(); i++ {
			e, ok := starlark.AsString(extensions.Index(i))
			if !ok || e != "as" {
				return nil, fmt.Errorf("power: extensions may contain only \"as\"")
			}
			ext = append(ext, e)
		}
	}
	if memory < 1<<20 || memory > 64<<30 || memory%4096 != 0 || cpus < 1 || cpus > 64 || mips < 1 {
		return nil, fmt.Errorf("power: memory 1M..64G in pages, cpus 1..64 and positive mips required")
	}
	return &machineValue{m: NewMachine(Config{Memory: memory, CPUs: cpus, MIPS: mips, PVR: uint32(pvr), Extensions: ext})}, nil
}

type machineValue struct {
	m       *Machine
	cpus    []*cpuValue // reused for callbacks
	thread  *starlark.Thread
	hcall   starlark.Callable
	illegal starlark.Callable
}

func (v *machineValue) String() string        { return "<power machine>" }
func (v *machineValue) Type() string          { return "power_machine" }
func (v *machineValue) Freeze()               {}
func (v *machineValue) Truth() starlark.Bool  { return starlark.True }
func (v *machineValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: power machine") }

var machineMethods = []string{"crq_attach_disk", "crq_attach_optical", "crq_change_optical_media", "crq_request", "crq_register", "crq_post", "crq_unregister", "create_tce_table", "tce_read", "tce_write", "tce_write_many", "dma_read", "dma_write", "break_at", "checkpoint", "clear_breaks", "cpu", "disassemble", "events", "history", "hpte_find", "hpte_probe", "hpte_read", "hpte_write", "identity_segments", "instructions", "interrupts",
	"map_page", "map_window", "set_hashed_page_table", "on_hcall", "on_illegal", "pages", "pointer_tags", "read", "read_effective", "restore", "run", "step", "state_digest", "stop_on_interrupts", "time_base", "hcall_native", "hcall_counts", "jit_stats", "set_jit", "unmap_page",
	"watch", "write", "write_effective", "register_hash_process_table", "hash_process_table", "rpa_block_list"}

func (v *machineValue) AttrNames() []string { return machineMethods }

// U64 converts a Starlark integer, accepting negative values as two's complement.
func U64(x starlark.Value) (uint64, error) {
	i, ok := x.(starlark.Int)
	if !ok {
		return 0, fmt.Errorf("got %s, want int", x.Type())
	}
	if u, ok := i.Uint64(); ok {
		return u, nil
	}
	b := i.BigInt()
	if b.Sign() < 0 {
		b.Add(b, new(big.Int).Lsh(big.NewInt(1), 64))
	}
	if b.Sign() < 0 || b.BitLen() > 64 {
		return 0, fmt.Errorf("integer %s out of 64-bit range", i)
	}
	return b.Uint64(), nil
}

func bytesOf(x starlark.Value) ([]byte, error) {
	switch d := x.(type) {
	case starlark.Bytes:
		return []byte(d), nil
	case starlark.String:
		return []byte(d), nil
	case storage.Reader:
		if d.Size() > 1<<34 {
			return nil, fmt.Errorf("file too large")
		}
		buf := make([]byte, d.Size())
		if _, err := d.ReadAt(buf, 0); err != nil && err != io.EOF {
			return nil, err
		}
		return buf, nil
	}
	return nil, fmt.Errorf("got %s, want bytes or file", x.Type())
}

func (v *machineValue) cpuArg(i int) (*CPU, error) {
	if i < 0 || i >= len(v.m.CPUs) {
		return nil, fmt.Errorf("power: no cpu %d", i)
	}
	return v.m.CPUs[i], nil
}

func stopRecord(r StopReason, c *CPU, ran uint64, began time.Time) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{
		"kind": starlark.String(r.Kind), "detail": starlark.String(r.Detail), "cpu": starlark.MakeInt(r.CPU),
		"pc": starlark.MakeUint64(c.PC), "instructions": starlark.MakeUint64(ran), "seconds": starlark.Float(time.Since(began).Seconds()),
	})
}

// Disassemble formats one word for display.
func Disassemble(word uint32, pc uint64) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], word)
	inst, err := ppc64asm.Decode(b[:], binary.BigEndian)
	if err != nil || inst.Op == 0 {
		return fmt.Sprintf(".long 0x%08x", word)
	}
	return ppc64asm.GNUSyntax(inst, pc)
}

func (v *machineValue) Attr(name string) (starlark.Value, error) {
	b := func(f func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)) starlark.Value {
		return starlark.NewBuiltin(name, func(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return f(thread, args, kwargs)
		})
	}
	m := v.m
	switch name {
	case "register_hash_process_table":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var procTable, pageSize, tableSize uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "process_table", &procTable, "page_size", &pageSize, "table_size", &tableSize); err != nil {
				return nil, err
			}
			return starlark.None, m.RegisterHashProcessTable(procTable, pageSize, tableSize)
		}), nil
	case "hash_process_table":
		entry, registered := m.HashProcessTable()
		if !registered {
			return starlark.None, nil
		}
		return starlark.MakeUint64(entry), nil
	case "pointer_tags":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var address, size uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &address, "size", &size); err != nil {
				return nil, err
			}
			bits, err := m.PointerTags(address, size)
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(bits), nil
		}), nil
	case "crq_attach_disk":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var unit uint64
			lun := uint64(0x0001000000000000)
			var value starlark.Value
			identity := scsi.DiskIdentity{Vendor: "TINYRNGX", Product: "Virtual Disk", Revision: "0001", Serial: "1"}
			if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit, "device", &value, "lun?", &lun, "vendor?", &identity.Vendor, "product?", &identity.Product, "revision?", &identity.Revision, "serial?", &identity.Serial); err != nil {
				return nil, err
			}
			device, err := blockstar.AsDevice(value)
			if err != nil {
				return nil, err
			}
			return starlark.None, m.AttachCRQDisk(unit, device, RPAOpticalConfig{LUN: lun, UnsupportedMADs: []uint64{3<<32 | 0x8001}}, identity)
		}), nil
	case "crq_change_optical_media":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var unit uint64
			var device starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit, "device", &device); err != nil {
				return nil, err
			}
			media, err := blockstar.AsDevice(device)
			if err != nil {
				return nil, err
			}
			return starlark.None, m.ChangeCRQOpticalMedia(unit, media)
		}), nil
	case "crq_attach_optical":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var unit uint64
			lun := uint64(0x8000000000000000)
			var device starlark.Value
			var unsupported *starlark.List
			if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit, "device", &device, "unsupported_mads?", &unsupported, "lun?", &lun); err != nil {
				return nil, err
			}
			var media block.Device
			if device != starlark.None {
				d, err := blockstar.AsDevice(device)
				if err != nil {
					return nil, err
				}
				media = d
			}
			var keys []uint64
			if unsupported != nil {
				for i := 0; i < unsupported.Len(); i++ {
					pair, ok := unsupported.Index(i).(starlark.Tuple)
					if !ok || len(pair) != 2 {
						return nil, fmt.Errorf("unsupported_mads requires (format, type) pairs")
					}
					f, err := U64(pair[0])
					if err != nil {
						return nil, err
					}
					typ, err := U64(pair[1])
					if err != nil {
						return nil, err
					}
					if f > 255 || typ > 0xffffffff {
						return nil, fmt.Errorf("MAD format/type out of range")
					}
					keys = append(keys, f<<32|typ)
				}
			}
			return starlark.None, m.AttachCRQOptical(unit, media, RPAOpticalConfig{LUN: lun, UnsupportedMADs: keys})
		}), nil
	case "crq_request":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var unit, high, low uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit, "high", &high, "low", &low); err != nil {
				return nil, err
			}
			posted, err := m.ProcessCRQ(unit, high, low)
			detail := starlark.Value(starlark.None)
			if err != nil {
				detail = starlark.String(err.Error())
			}
			return starfile.NewRecord(starlark.StringDict{"posted": starlark.Bool(posted), "error": detail}), nil
		}), nil

	case "crq_register":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var unit, table, address, size uint64
			if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit, "table", &table, "address", &address, "size", &size); err != nil {
				return nil, err
			}
			return starlark.Bool(m.RegisterCRQ(unit, table, address, size) == nil), nil
		}), nil
	case "crq_post", "crq_unregister":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var unit uint64
			if name == "crq_unregister" {
				if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit); err != nil {
					return nil, err
				}
				return starlark.Bool(m.UnregisterCRQ(unit) == nil), nil
			}
			var entry starlark.Bytes
			if err := starlark.UnpackArgs(name, args, kwargs, "unit", &unit, "entry", &entry); err != nil {
				return nil, err
			}
			return starlark.Bool(m.PostCRQ(unit, []byte(entry)) == nil), nil
		}), nil

	case "create_tce_table", "tce_read", "tce_write":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var index, slot, word uint64
			if name == "create_tce_table" {
				if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "entries", &slot); err != nil {
					return nil, err
				}
				return starlark.None, m.CreateTCETable(index, slot)
			}
			if name == "tce_read" {
				if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "slot", &slot); err != nil {
					return nil, err
				}
				w, err := m.ReadTCE(index, slot)
				if err != nil {
					return starlark.None, nil
				}
				return starlark.MakeUint64(w), nil
			}
			if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "slot", &slot, "word", &word); err != nil {
				return nil, err
			}
			return starlark.Bool(m.WriteTCE(index, slot, word) == nil), nil
		}), nil
	case "tce_write_many":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var index, slot uint64
			var values *starlark.List
			if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "slot", &slot, "words", &values); err != nil {
				return nil, err
			}
			words := make([]uint64, values.Len())
			for i := range words {
				w, err := U64(values.Index(i))
				if err != nil {
					return nil, err
				}
				words[i] = w
			}
			return starlark.Bool(m.WriteTCEs(index, slot, words) == nil), nil
		}), nil

	case "dma_read", "dma_write":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var index, address uint64
			var lp uint8
			if name == "dma_read" {
				var size int
				if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "address", &address, "size", &size, "lp?", &lp); err != nil {
					return nil, err
				}
				if size < 0 || size > 64<<20 {
					return nil, fmt.Errorf("dma_read: size must be 0..64MiB")
				}
				if _, err := m.dmaTable(index, address, size, lp, false); err != nil {
					return starlark.None, nil
				}
				data := make([]byte, size)
				if err := m.ReadDMA(index, address, data, lp); err != nil {
					return starlark.None, nil
				}
				return starlark.Bytes(data), nil
			}
			var value starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "address", &address, "data", &value, "lp?", &lp); err != nil {
				return nil, err
			}
			data, err := bytesOf(value)
			if err != nil {
				return nil, err
			}
			return starlark.Bool(m.WriteDMA(index, address, data, lp) == nil), nil
		}), nil

	case "map_window":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var effective, real, size starlark.Value
			w := TranslationWindow{Write: true}
			if err := starlark.UnpackArgs(name, args, kwargs, "effective", &effective, "real", &real, "size", &size, "write?", &w.Write, "execute?", &w.Execute, "user?", &w.User); err != nil {
				return nil, err
			}
			var err error
			if w.Effective, err = U64(effective); err != nil {
				return nil, err
			}
			if w.Real, err = U64(real); err != nil {
				return nil, err
			}
			if w.Size, err = U64(size); err != nil {
				return nil, err
			}
			return starlark.None, m.MapWindow(w)
		}), nil
	case "write":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr, data starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "data", &data); err != nil {
				return nil, err
			}
			a, err := U64(addr)
			if err != nil {
				return nil, err
			}
			d, err := bytesOf(data)
			if err != nil {
				return nil, err
			}
			if a+uint64(len(d)) > uint64(len(m.Mem)) || a+uint64(len(d)) < a {
				return nil, fmt.Errorf("write: real range %x+%x outside memory", a, len(d))
			}
			return starlark.None, m.WriteReal(a, d)
		}), nil
	case "read":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr starlark.Value
			var size int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "size", &size); err != nil {
				return nil, err
			}
			a, err := U64(addr)
			if err != nil {
				return nil, err
			}
			if size < 0 || size > 64<<20 || a+uint64(size) > uint64(len(m.Mem)) || a+uint64(size) < a {
				return nil, fmt.Errorf("read: real range %x+%x outside memory", a, size)
			}
			return starlark.Bytes(m.Mem[a : a+uint64(size)]), nil
		}), nil
	case "read_effective", "write_effective":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr, data starlark.Value
			cpu := 0
			if name == "read_effective" {
				var size int
				if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "size", &size, "cpu?", &cpu); err != nil {
					return nil, err
				}
				c, err := v.cpuArg(cpu)
				if err != nil {
					return nil, err
				}
				a, err := U64(addr)
				if err != nil {
					return nil, err
				}
				if size < 0 || size > 64<<20 {
					return nil, fmt.Errorf("read_effective: size")
				}
				d, err := c.ReadEffective(a, size)
				if err != nil {
					return nil, err
				}
				return starlark.Bytes(d), nil
			}
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "data", &data, "cpu?", &cpu); err != nil {
				return nil, err
			}
			c, err := v.cpuArg(cpu)
			if err != nil {
				return nil, err
			}
			a, err := U64(addr)
			if err != nil {
				return nil, err
			}
			d, err := bytesOf(data)
			if err != nil {
				return nil, err
			}
			return starlark.None, c.WriteEffective(a, d)
		}), nil
	case "cpu":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i := 0
			if err := starlark.UnpackArgs(name, args, kwargs, "index?", &i); err != nil {
				return nil, err
			}
			c, err := v.cpuArg(i)
			if err != nil {
				return nil, err
			}
			return v.cpuValue(c), nil
		}), nil
	case "identity_segments":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			on := true
			var ranges *starlark.List
			if err := starlark.UnpackArgs(name, args, kwargs, "enabled?", &on, "guest_ranges?", &ranges); err != nil {
				return nil, err
			}
			var guest []SegmentRange
			if ranges != nil {
				for i := 0; i < ranges.Len(); i++ {
					pair, ok := ranges.Index(i).(starlark.Tuple)
					if !ok || len(pair) != 2 {
						return nil, fmt.Errorf("power: guest_ranges requires (first_esid, end_esid) pairs")
					}
					var r SegmentRange
					if err := starlark.UnpackPositionalArgs("guest segment range", pair, nil, 2, &r.First, &r.End); err != nil {
						return nil, err
					}
					guest = append(guest, r)
				}
			}
			return starlark.None, m.SetIdentitySegments(on, guest)
		}), nil
	case "set_hashed_page_table":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var groups starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "groups", &groups); err != nil {
				return nil, err
			}
			g, err := U64(groups)
			if err != nil {
				return nil, err
			}
			return starlark.None, m.SetHashedPageTable(g)
		}), nil
	case "hpte_find":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var vsidV, offsetV starlark.Value
			shift, tera := 12, false
			if err := starlark.UnpackArgs(name, args, kwargs, "vsid", &vsidV, "offset", &offsetV, "shift?", &shift, "segment_1t?", &tera); err != nil {
				return nil, err
			}
			vsid, err := U64(vsidV)
			if err != nil {
				return nil, err
			}
			offset, err := U64(offsetV)
			if err != nil {
				return nil, err
			}
			seg, size := uint8(0), uint(28)
			if tera {
				seg, size = 1, 40
			}
			if (shift != 12 && shift != 16 && shift != 24 && shift != 34) || uint(shift) > size || offset>>size != 0 {
				return nil, fmt.Errorf("power: invalid page shift or segment offset")
			}
			slot, ok := m.HPTESlot(PageKey{VSID: vsid, B: seg, Shift: uint8(shift), Page: offset >> uint(shift)})
			if !ok {
				return starlark.None, nil
			}
			dw0, dw1, err := m.HPTERead(slot)
			if err != nil {
				return nil, err
			}
			return starlark.Tuple{starlark.MakeUint64(slot), starlark.MakeUint64(dw0), starlark.MakeUint64(dw1)}, nil
		}), nil
	case "hpte_probe":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var vsid, offset uint64
			base, actual, tera := 12, 12, false
			if err := starlark.UnpackArgs(name, args, kwargs, "vsid", &vsid, "offset", &offset, "base_shift?", &base, "page_shift?", &actual, "segment_1t?", &tera); err != nil {
				return nil, err
			}
			if m.HTAB == nil {
				return nil, fmt.Errorf("power: hpte_probe requires a hashed page table")
			}
			slot, secondary, words, err := m.HTAB.ProbeHPTE(vsid, offset, tera, base, actual)
			if err != nil {
				return nil, err
			}
			return starlark.Tuple{starlark.MakeInt(slot), starlark.Bool(secondary), starlark.MakeUint64(words[0]), starlark.MakeUint64(words[1])}, nil
		}), nil
	case "hpte_read":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var slotV starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "slot", &slotV); err != nil {
				return nil, err
			}
			slot, err := U64(slotV)
			if err != nil {
				return nil, err
			}
			dw0, dw1, err := m.HPTERead(slot)
			if err != nil {
				return nil, err
			}
			return starlark.Tuple{starlark.MakeUint64(dw0), starlark.MakeUint64(dw1)}, nil
		}), nil
	case "hpte_write":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var slotV, dw0V, dw1V starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "slot", &slotV, "dw0", &dw0V, "dw1", &dw1V); err != nil {
				return nil, err
			}
			var w [3]uint64
			for i, x := range []starlark.Value{slotV, dw0V, dw1V} {
				u, err := U64(x)
				if err != nil {
					return nil, err
				}
				w[i] = u
			}
			return starlark.None, m.HPTEWrite(w[0], w[1], w[2])
		}), nil
	case "map_page", "unmap_page":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var vsidV, offV, realV starlark.Value = nil, nil, starlark.None
			shift := 12
			tera, write, execute := false, true, true
			key := 0
			var sizeV starlark.Value = starlark.None
			var err error
			if name == "map_page" {
				err = starlark.UnpackArgs(name, args, kwargs, "vsid", &vsidV, "offset", &offV, "real", &realV, "shift?", &shift, "segment_1t?", &tera, "write?", &write, "execute?", &execute, "key?", &key, "size?", &sizeV)
			} else {
				err = starlark.UnpackArgs(name, args, kwargs, "vsid", &vsidV, "offset", &offV, "shift?", &shift, "segment_1t?", &tera)
			}
			if err != nil {
				return nil, err
			}
			vsid, err := U64(vsidV)
			if err != nil {
				return nil, err
			}
			off, err := U64(offV)
			if err != nil {
				return nil, err
			}
			seg := uint8(0)
			if tera {
				seg = 1
			}
			if name == "unmap_page" {
				return starlark.Bool(m.UnmapPage(vsid, seg, off, uint(shift))), nil
			}
			r, err := U64(realV)
			if err != nil {
				return nil, err
			}
			size := uint64(1) << shift
			if sizeV != starlark.None {
				if size, err = U64(sizeV); err != nil {
					return nil, err
				}
			}
			if shift < 12 || shift > 34 || size == 0 || size&(1<<shift-1) != 0 || size > 1<<40 {
				return nil, fmt.Errorf("map_page: size must be a positive multiple of the page size")
			}
			for done := uint64(0); done < size; done += 1 << shift {
				if err := m.MapPage(vsid, seg, off+done, uint(shift), PTE{Real: r + done, Write: write, Execute: execute, Key: uint8(key)}); err != nil {
					return nil, err
				}
			}
			return starlark.None, nil
		}), nil
	case "pages":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.MakeInt(len(m.HPT)), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "rpa_block_list":
		return starlark.NewBuiltin(name, v.rpaBlockListBuiltin), nil
	case "on_hcall", "on_illegal":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var fn starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "handler", &fn); err != nil {
				return nil, err
			}
			callable, _ := fn.(starlark.Callable)
			if fn != starlark.None && callable == nil {
				return nil, fmt.Errorf("%s: handler must be callable or None", name)
			}
			if name == "on_hcall" {
				v.hcall = callable
				m.Hypercall = nil
				if callable != nil {
					m.Hypercall = v.runHypercall
				}
			} else {
				v.illegal = callable
				m.Extension = nil
				if callable != nil {
					m.Extension = v.runExtension
				}
			}
			return starlark.None, nil
		}), nil
	case "break_at":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if len(kwargs) != 0 {
				return nil, fmt.Errorf("break_at: addresses only")
			}
			for _, a := range args {
				x, err := U64(a)
				if err != nil {
					return nil, err
				}
				m.Breakpoints[x] = true
			}
			return starlark.None, nil
		}), nil
	case "clear_breaks":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			m.Breakpoints = map[uint64]bool{}
			m.Watch(0, 0)
			return starlark.None, starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "watch":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var lo, hi starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "low", &lo, "high", &hi); err != nil {
				return nil, err
			}
			l, err := U64(lo)
			if err != nil {
				return nil, err
			}
			h, err := U64(hi)
			if err != nil {
				return nil, err
			}
			m.Watch(l, h)
			return starlark.None, nil
		}), nil
	case "stop_on_interrupts":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var vectors *starlark.List
			all := false
			if err := starlark.UnpackArgs(name, args, kwargs, "vectors?", &vectors, "all?", &all); err != nil {
				return nil, err
			}
			m.StopAllInterrupts = all
			m.StopInterrupts = map[uint64]bool{}
			if vectors != nil {
				for i := 0; i < vectors.Len(); i++ {
					x, err := U64(vectors.Index(i))
					if err != nil {
						return nil, err
					}
					m.StopInterrupts[x] = true
				}
			}
			return starlark.None, nil
		}), nil
	case "run":
		return b(func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			n := 1000000
			if err := starlark.UnpackArgs(name, args, kwargs, "instructions?", &n); err != nil {
				return nil, err
			}
			v.thread = thread
			before, began := m.Instructions(), time.Now()
			r, err := m.Run(uint64(n))
			if err != nil {
				return nil, err
			}
			return stopRecord(r, m.CPUs[r.CPU], m.Instructions()-before, began), nil
		}), nil
	case "step":
		return b(func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			cpu := 0
			if err := starlark.UnpackArgs(name, args, kwargs, "cpu?", &cpu); err != nil {
				return nil, err
			}
			c, err := v.cpuArg(cpu)
			if err != nil {
				return nil, err
			}
			v.thread = thread
			began := time.Now()
			r := c.Step()
			if m.err != nil {
				err := m.err
				m.err = nil
				return nil, err
			}
			if r == nil {
				r = &StopReason{Kind: "step", CPU: cpu}
			}
			return stopRecord(*r, c, 1, began), nil
		}), nil
	case "events":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			clear := false
			if err := starlark.UnpackArgs(name, args, kwargs, "clear?", &clear); err != nil {
				return nil, err
			}
			out := make([]starlark.Value, len(m.Events))
			for i, e := range m.Events {
				out[i] = starfile.NewRecord(starlark.StringDict{"kind": starlark.String(e.Kind), "cpu": starlark.MakeInt(e.CPU),
					"pc": starlark.MakeUint64(e.PC), "detail": starlark.String(e.Detail), "instructions": starlark.MakeUint64(e.Instructions)})
			}
			if clear {
				m.Events = nil
			}
			return starlark.NewList(out), nil
		}), nil
	case "interrupts":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			d := starlark.NewDict(len(m.Interrupts))
			keys := make([]uint64, 0, len(m.Interrupts))
			for k := range m.Interrupts {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, k := range keys {
				d.SetKey(starlark.MakeUint64(k), starlark.MakeUint64(m.Interrupts[k]))
			}
			return d, starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "history":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			keep := -1
			if err := starlark.UnpackArgs(name, args, kwargs, "keep?", &keep); err != nil {
				return nil, err
			}
			if keep >= 0 {
				if keep > 1<<20 {
					return nil, fmt.Errorf("history: keep at most 1048576")
				}
				m.EnableHistory(keep)
				return starlark.None, nil
			}
			h := m.History()
			out := make([]starlark.Value, len(h))
			for i, e := range h {
				out[i] = starlark.String(fmt.Sprintf("%016x %08x %s", e.PC, e.Word, Disassemble(e.Word, e.PC)))
			}
			return starlark.NewList(out), nil
		}), nil
	case "disassemble":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr starlark.Value
			count, cpu := 16, 0
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "count?", &count, "cpu?", &cpu); err != nil {
				return nil, err
			}
			c, err := v.cpuArg(cpu)
			if err != nil {
				return nil, err
			}
			a, err := U64(addr)
			if err != nil {
				return nil, err
			}
			if count < 1 || count > 4096 {
				return nil, fmt.Errorf("disassemble: count 1..4096")
			}
			var out []starlark.Value
			for i := 0; i < count; i++ {
				pc := a + uint64(4*i)
				r, err := c.Translate(pc, true, accessRead)
				if err != nil || r+4 > uint64(len(m.Mem)) {
					out = append(out, starlark.String(fmt.Sprintf("%016x (untranslated)", pc)))
					continue
				}
				w := binary.BigEndian.Uint32(m.Mem[r:])
				out = append(out, starlark.String(fmt.Sprintf("%016x %08x %s", pc, w, Disassemble(w, pc))))
			}
			return starlark.NewList(out), nil
		}), nil
	case "checkpoint":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var state starlark.Value = starlark.None
			if err := starlark.UnpackArgs(name, args, kwargs, "state?", &state); err != nil {
				return nil, err
			}
			cp := &checkpointValue{}
			if state != starlark.None {
				saved, err := starvalue.CaptureGraph([]starlark.Value{state}, nil)
				if err != nil {
					return nil, err
				}
				cp.state, cp.owner = saved, m
			}
			cp.cp = m.Checkpoint()
			return cp, nil
		}), nil
	case "restore":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var cp *checkpointValue
			if err := starlark.UnpackArgs(name, args, kwargs, "checkpoint", &cp); err != nil {
				return nil, err
			}
			if cp.state != nil {
				if cp.owner != m {
					return nil, fmt.Errorf("power: checkpoint state belongs to a different partition")
				}
				if err := cp.state.Restore(); err != nil {
					return nil, err
				}
			}
			return starlark.None, m.Restore(cp.cp)
		}), nil
	case "hcall_native":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var token starlark.Value
			var gprs *starlark.Dict
			var fill, wake *starlark.Dict
			callName := ""
			remove, yield, wait := false, false, false
			scriptEvery := 0
			var msrSet starlark.Value = starlark.MakeInt(0)
			if err := starlark.UnpackArgs(name, args, kwargs, "token", &token, "name?", &callName, "gprs?", &gprs, "zero_fill?", &fill,
				"yield_quantum?", &yield, "script_every?", &scriptEvery, "msr_set?", &msrSet, "wait?", &wait, "wake?", &wake, "remove?", &remove); err != nil {
				return nil, err
			}
			msrBits, err := U64(msrSet)
			if err != nil {
				return nil, fmt.Errorf("hcall_native: msr_set: %w", err)
			}
			if scriptEvery < 0 {
				return nil, fmt.Errorf("hcall_native: script_every must be non-negative")
			}
			t, err := U64(token)
			if err != nil {
				return nil, err
			}
			if remove {
				return starlark.None, m.SetNativeHypercall(t, nil)
			}
			n := &NativeHypercall{Name: callName, Yield: yield, ScriptEvery: uint64(scriptEvery), MSRSet: msrBits, Wait: wait}
			if wake != nil {
				n.Wake = &WakeCPU{Index: -1, Limit: ^uint64(0)}
				for _, kv := range wake.Items() {
					k, _ := starlark.AsString(kv[0])
					u, err := U64(kv[1])
					if err != nil {
						return nil, fmt.Errorf("hcall_native: wake %s: %w", k, err)
					}
					switch k {
					case "index":
						n.Wake.Index = int(min(u, 32))
					case "limit":
						n.Wake.Limit = u
					default:
						return nil, fmt.Errorf("hcall_native: wake has index and limit, not %q", k)
					}
				}
				if n.Wake.Index < 0 {
					return nil, fmt.Errorf("hcall_native: wake needs an index register")
				}
			}
			if gprs != nil {
				items := gprs.Items()
				sort.Slice(items, func(i, j int) bool { return items[i][0].String() < items[j][0].String() })
				for _, kv := range items {
					r, err := starlark.AsInt32(kv[0])
					if err != nil {
						return nil, fmt.Errorf("hcall_native: gprs keys must be register numbers")
					}
					u, err := U64(kv[1])
					if err != nil {
						return nil, err
					}
					n.GPRs = append(n.GPRs, RegisterValue{Register: r, Value: u})
				}
			}
			if fill != nil {
				f := &ZeroFill{AddressMask: ^uint64(0), Align: 1, Limit: ^uint64(0), Length: -1}
				for _, kv := range fill.Items() {
					k, _ := starlark.AsString(kv[0])
					u, err := U64(kv[1])
					if err != nil {
						return nil, fmt.Errorf("hcall_native: zero_fill %s: %w", k, err)
					}
					switch k {
					case "address":
						f.Address = int(u)
					case "length":
						f.Length = int(u)
					case "mask":
						f.AddressMask = u
					case "align":
						f.Align = u
					case "limit":
						f.Limit = u
					case "size":
						f.Size = u
					case "address_align":
						f.AddressAlign = u
					case "end":
						f.End = u
					default:
						return nil, fmt.Errorf("hcall_native: zero_fill has address, length, size, mask, align, address_align, limit and end, not %q", k)
					}
				}
				n.ZeroFill = f
			}
			return starlark.None, m.SetNativeHypercall(t, n)
		}), nil
	case "hcall_counts":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			counts := m.HypercallCounts()
			keys := make([]uint64, 0, len(counts))
			for k := range counts {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			d := starlark.NewDict(len(keys))
			for _, k := range keys {
				d.SetKey(starlark.MakeUint64(k), starlark.MakeUint64(counts[k]))
			}
			return d, starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "jit_stats":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			st := m.JITStats()
			interpreted := make([]starlark.Value, 0, 32)
			for _, o := range st.Interpreted[:min(32, len(st.Interpreted))] {
				interpreted = append(interpreted, starfile.NewRecord(starlark.StringDict{"primary": starlark.MakeUint64(uint64(o.Primary)),
					"extended": starlark.MakeUint64(uint64(o.Extended)), "spr": starlark.MakeInt(o.SPR), "side_exit": starlark.Bool(o.SideExit), "budget": starlark.Bool(o.Budget), "count": starlark.MakeUint64(o.Count)}))
			}
			returns := starlark.NewDict(len(st.Returns))
			for k, n := range st.Returns {
				returns.SetKey(starlark.String(k), starlark.MakeUint64(n))
			}
			reasons := starlark.NewDict(len(st.ExitReasons))
			for k, n := range st.ExitReasons {
				reasons.SetKey(starlark.String(k), starlark.MakeUint64(n))
			}
			return starfile.NewRecord(starlark.StringDict{
				"interpreted":  starlark.NewList(interpreted),
				"exit_reasons": reasons,
				"returns":      returns,
				"enabled":      starlark.Bool(m.jit != nil), "blocks": starlark.MakeUint64(st.Blocks), "compiled": starlark.MakeUint64(st.Compiled),
				"invalidated": starlark.MakeUint64(st.Invalidated), "flushes": starlark.MakeUint64(st.Flushes),
				"native_runs": starlark.MakeUint64(st.Native), "native_instructions": starlark.MakeUint64(st.NativeInstructions),
				"side_exits": starlark.MakeUint64(st.SideExits),
			}), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "set_jit":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var enabled bool
			if err := starlark.UnpackArgs(name, args, kwargs, "enabled", &enabled); err != nil {
				return nil, err
			}
			return starlark.Bool(m.SetJIT(enabled)), nil
		}), nil
	case "state_digest":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.String(m.StateDigest()), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "time_base":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.MakeUint64(m.TB()), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	case "instructions":
		return b(func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.MakeUint64(m.Instructions()), starlark.UnpackArgs(name, args, kwargs)
		}), nil
	}
	return nil, nil
}

// cpuValue returns the machine's Starlark value for c.
func (v *machineValue) cpuValue(c *CPU) *cpuValue {
	if v.cpus == nil {
		v.cpus = make([]*cpuValue, len(v.m.CPUs))
	}
	if v.cpus[c.Index] == nil {
		v.cpus[c.Index] = &cpuValue{c: c}
	}
	return v.cpus[c.Index]
}

func (v *machineValue) runHypercall(c *CPU) error {
	if v.thread == nil {
		return fmt.Errorf("power: hypercall outside run")
	}
	r, err := starlark.Call(v.thread, v.hcall, starlark.Tuple{v.cpuValue(c)}, nil)
	if err != nil {
		return err
	}
	if s, ok := r.(starlark.String); ok {
		c.Stop("hcall", string(s))
	}
	return nil
}

func (v *machineValue) runExtension(c *CPU, word uint32) (bool, error) {
	if v.thread == nil {
		return false, fmt.Errorf("power: extension outside run")
	}
	r, err := starlark.Call(v.thread, v.illegal, starlark.Tuple{v.cpuValue(c), starlark.MakeUint64(uint64(word))}, nil)
	if err != nil {
		return false, err
	}
	if s, ok := r.(starlark.String); ok {
		// Stop before the instruction: PC stays on it.
		c.Stop("illegal", string(s))
		c.fault = true
		return true, nil
	}
	return bool(r.Truth()), nil
}

type checkpointValue struct {
	cp    *Checkpoint
	state *starvalue.GraphCheckpoint
	owner *Machine
}

func (v *checkpointValue) String() string       { return "<power checkpoint>" }
func (v *checkpointValue) Type() string         { return "power_checkpoint" }
func (v *checkpointValue) Freeze()              {}
func (v *checkpointValue) Truth() starlark.Bool { return starlark.True }
func (v *checkpointValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: power checkpoint")
}
