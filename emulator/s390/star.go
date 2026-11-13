package s390

import (
	"bytes"
	"fmt"
	"image/png"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tinyrange/trex/filesystem/ckd"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Builtin creates an ESA/390 machine: emulator.s390(memory=, cpus=, mips=, start=).
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	memory, cpus, mips := 64<<20, 1, 50
	start := ""
	idleSkip := true
	arch := "esa390"
	if err := starlark.UnpackArgs("s390", args, kwargs, "memory?", &memory, "cpus?", &cpus, "mips?", &mips, "start?", &start, "idle_skip?", &idleSkip, "architecture?", &arch); err != nil {
		return nil, err
	}
	if memory < 1<<20 || memory > 2<<30 || cpus < 1 || cpus > 16 || mips < 1 {
		return nil, fmt.Errorf("s390: memory 1M..2G, cpus 1..16 and positive mips required")
	}
	if arch != "esa390" && arch != "s370" {
		return nil, fmt.Errorf("s390: architecture must be \"esa390\" or \"s370\"")
	}
	if arch == "s370" && memory > 64<<20 {
		return nil, fmt.Errorf("s390: System/370 storage is at most 64M")
	}
	cfg := Config{Memory: memory, CPUs: cpus, MIPS: mips, NoIdleSkip: !idleSkip, S370: arch == "s370"}
	if start != "" {
		t, err := time.Parse(time.RFC3339, start)
		if err != nil {
			return nil, fmt.Errorf("s390: start: %w", err)
		}
		cfg.Start = t
	}
	return &machineValue{m: NewMachine(cfg), dasd: map[uint16]*DASD3390{}, consoles: map[uint16]*Console3270{},
		lineConsoles: map[uint16]*Console3215{}, units: map[uint16]*UnitRecord{}, ctcs: map[uint16]*CTCI{}}, nil
}

type machineValue struct {
	m            *Machine
	dasd         map[uint16]*DASD3390
	consoles     map[uint16]*Console3270
	lineConsoles map[uint16]*Console3215
	units        map[uint16]*UnitRecord
	ctcs         map[uint16]*CTCI
}

func devArg(name string, args starlark.Tuple, kwargs []starlark.Tuple) (uint16, error) {
	var devno int
	if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno); err != nil {
		return 0, err
	}
	return uint16(devno), nil
}

func (v *machineValue) String() string        { return "<s390 machine>" }
func (v *machineValue) Type() string          { return "s390_machine" }
func (v *machineValue) Freeze()               {}
func (v *machineValue) Truth() starlark.Bool  { return starlark.True }
func (v *machineValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: s390 machine") }

var machineMethods = []string{"dasd", "console", "ipl", "storage_load", "command", "messages", "unit_record", "cards", "output", "tape", "dasd_track", "subchannel", "translate", "run", "psw", "registers", "screen", "type", "key", "cursor",
	"read", "unknown", "program_counts", "dasd_errors", "screens", "time", "break_at", "break_program", "clear_breaks", "events", "instructions", "restart", "trace_io", "event_limit", "history", "watch", "disassemble", "find", "scp_config", "profile", "interrupts", "screenshot", "web_terminals", "checkpoint", "restore", "disk_changes", "transfer", "transfer_result", "ctc", "ctc_send", "ctc_packets"}

func (v *machineValue) AttrNames() []string { return machineMethods }

func (v *machineValue) Attr(name string) (starlark.Value, error) {
	b := func(f func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error)) starlark.Value {
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return f(args, kwargs)
		})
	}
	switch name {
	case "dasd":
		return b(v.addDASD), nil
	case "console":
		return b(v.addConsole), nil
	case "ipl":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			clear := true
			loadparm := ""
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "clear?", &clear, "loadparm?", &loadparm); err != nil {
				return nil, err
			}
			if len(loadparm) > 8 {
				return nil, fmt.Errorf("ipl: loadparm longer than 8 characters")
			}
			v.m.LoadParm = strings.ToUpper(loadparm)
			return starlark.None, v.m.IPL(uint16(devno), clear)
		}), nil
	case "storage_load":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var list *starlark.List
			clear := true
			if err := starlark.UnpackArgs(name, args, kwargs, "images", &list, "clear?", &clear); err != nil {
				return nil, err
			}
			var images []Image
			for i := 0; i < list.Len(); i++ {
				t, ok := list.Index(i).(starlark.Tuple)
				if !ok || len(t) != 2 {
					return nil, fmt.Errorf("storage_load: images must be (address, data) pairs")
				}
				addr, err := starlark.AsInt32(t[0])
				if err != nil {
					return nil, fmt.Errorf("storage_load: %v", err)
				}
				data, err := dataOf(t[1])
				if err != nil {
					return nil, fmt.Errorf("storage_load: %v", err)
				}
				images = append(images, Image{Address: uint32(addr), Data: data})
			}
			return starlark.None, v.m.Load(images, clear)
		}), nil
	case "unit_record":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var typ string
			var cards *starlark.List
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "type", &typ, "cards?", &cards); err != nil {
				return nil, err
			}
			t := map[string]uint16{"2540R": 0x2540, "3505": 0x3505, "2501": 0x2501, "2540P": 0x2541, "3525": 0x3525, "1403": 0x1403, "3211": 0x3211}[typ]
			if t == 0 {
				return nil, fmt.Errorf("unit_record: type must be 2540R, 3505, 2501, 2540P, 3525, 1403 or 3211")
			}
			u := &UnitRecord{Type: t}
			if cards != nil {
				var lines []string
				for i := 0; i < cards.Len(); i++ {
					l, ok := starlark.AsString(cards.Index(i))
					if !ok {
						return nil, fmt.Errorf("unit_record: cards must be strings")
					}
					lines = append(lines, l)
				}
				u.Load(lines)
			}
			if err := v.m.CSS.AttachUnitRecord(uint16(devno), u); err != nil {
				return nil, err
			}
			v.units[uint16(devno)] = u
			return starlark.None, nil
		}), nil
	case "subchannel":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			dev, err := devArg(name, args, kwargs)
			if err != nil {
				return nil, err
			}
			x := v.m.CSS.bydev[dev]
			if x == nil {
				return nil, fmt.Errorf("subchannel: no device %04X", dev)
			}
			return starlark.String(fmt.Sprintf("dev %04X enabled=%v pending=%v irq=%v blocked=%v pci=%v attnHold=%v status=%02X/%02X ccw=%06X resid=%d",
				dev, x.enabled, x.pending, x.irq, x.blocked, x.pciWait, x.attnHold, x.devStatus, x.schStatus, x.ccwaddr, x.residual)), nil
		}), nil
	case "dasd_track":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno, cyl, head, show int
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "cylinder", &cyl, "head", &head, "bytes?", &show); err != nil {
				return nil, err
			}
			d := v.dasd[uint16(devno)]
			if d == nil || cyl < 0 || head < 0 || uint32(head) >= d.heads || uint32(cyl) >= d.cylinders {
				return nil, fmt.Errorf("dasd_track: no device %04X or track out of range", devno)
			}
			recs, err := d.ReadTrack(uint32(cyl)*d.heads + uint32(head))
			if err != nil {
				return nil, err
			}
			var out []string
			for _, r := range recs {
				line := fmt.Sprintf("%04X%04X%02X kl=%d dl=%d key=%s", r.Cylinder, r.Head, r.Number, len(r.Key), len(r.Data), EBCDICString(r.Key))
				if show > 0 {
					line += fmt.Sprintf(" data=%X", r.Data[:min(show, len(r.Data))])
				}
				out = append(out, line)
			}
			return stringList(out), nil
		}), nil
	case "cards":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var cards *starlark.List
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "cards", &cards); err != nil {
				return nil, err
			}
			u := v.units[uint16(devno)]
			if u == nil || !u.reader() {
				return nil, fmt.Errorf("cards: no card reader %04X", devno)
			}
			var lines []string
			for i := 0; i < cards.Len(); i++ {
				l, ok := starlark.AsString(cards.Index(i))
				if !ok {
					return nil, fmt.Errorf("cards: cards must be strings")
				}
				lines = append(lines, l)
			}
			u.Load(lines)
			// Readying the reader presents device end.
			v.m.CSS.Unsolicited(uint16(devno), usDE)
			return starlark.None, nil
		}), nil
	case "output":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			dev, err := devArg(name, args, kwargs)
			if err != nil {
				return nil, err
			}
			u := v.units[dev]
			if u == nil {
				return nil, fmt.Errorf("output: no unit-record device %04X", dev)
			}
			return stringList(u.Output), nil
		}), nil
	case "tape":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var file starlark.Value
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "file", &file); err != nil {
				return nil, err
			}
			src, ok := file.(storage.Reader)
			if !ok {
				return nil, fmt.Errorf("tape: portable file required")
			}
			t, err := MountAWS(src)
			if err != nil {
				return nil, err
			}
			_, err = v.m.CSS.Attach(uint16(devno), t)
			return starlark.None, err
		}), nil
	case "command":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var text string
			if err := starlark.UnpackArgs(name, args, kwargs, "text", &text); err != nil {
				return nil, err
			}
			v.m.Command(text)
			return starlark.None, nil
		}), nil
	case "messages":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			lines := v.m.ConsoleLines()
			out := make([]starlark.Value, len(lines))
			for i, s := range lines {
				out[i] = starlark.String(s)
			}
			return starlark.NewList(out), nil
		}), nil
	case "restart":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			v.m.CPUs[0].Restart()
			return starlark.None, nil
		}), nil
	case "web_terminals":
		return b(v.webTerminals), nil
	case "checkpoint":
		// checkpoint() -> bytes: the machine's state (see Machine.Save).
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := v.m.Save(&buf); err != nil {
				return nil, err
			}
			return starlark.Bytes(buf.String()), nil
		}), nil
	case "restore":
		// restore(file, disks_only=False): loads a checkpoint into this
		// identically configured machine (see Machine.Restore).
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var f starlark.Value
			disksOnly := false
			if err := starlark.UnpackArgs(name, args, kwargs, "file", &f, "disks_only?", &disksOnly); err != nil {
				return nil, err
			}
			var r io.Reader
			switch x := f.(type) {
			case starlark.Bytes:
				r = strings.NewReader(string(x))
			case storage.Reader:
				r = io.NewSectionReader(x, 0, x.Size())
			default:
				return nil, fmt.Errorf("restore: %s is not a file or bytes", f.Type())
			}
			return starlark.None, v.m.Restore(r, disksOnly)
		}), nil
	case "ctc":
		// ctc(device): a 3088 CTC adapter carrying IP (CTCI) at device
		// (read) and device+1 (write); web_terminals(network=...) connects
		// it to the host.
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			dev, err := devArg(name, args, kwargs)
			if err != nil {
				return nil, err
			}
			c, err := v.m.CSS.AttachCTCI(dev)
			if err != nil {
				return nil, err
			}
			v.ctcs[dev] = c
			return starlark.None, nil
		}), nil
	case "ctc_send":
		// ctc_send(device, packet): delivers an IP packet to the program.
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var packet starlark.Bytes
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "packet", &packet); err != nil {
				return nil, err
			}
			c := v.ctcs[uint16(devno)]
			if c == nil {
				return nil, fmt.Errorf("ctc_send: no CTC adapter at %04X", devno)
			}
			c.Deliver([]byte(packet))
			return starlark.None, nil
		}), nil
	case "ctc_packets":
		// ctc_packets(device) -> [bytes]: packets the program sent, when no
		// host network is attached; the list is emptied.
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			dev, err := devArg(name, args, kwargs)
			if err != nil {
				return nil, err
			}
			c := v.ctcs[dev]
			if c == nil {
				return nil, fmt.Errorf("ctc_packets: no CTC adapter at %04X", dev)
			}
			out := make([]starlark.Value, len(c.Outbox))
			for i, p := range c.Outbox {
				out[i] = starlark.Bytes(p)
			}
			c.Outbox = nil
			return starlark.NewList(out), nil
		}), nil
	case "transfer":
		// transfer(device, upload=None): the display answers the host's
		// next IND$FILE requests itself: uploads give it upload, downloads
		// are collected (see transfer_result).
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var upload starlark.Value = starlark.None
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "upload?", &upload); err != nil {
				return nil, err
			}
			t := v.consoles[uint16(devno)]
			if t == nil {
				return nil, fmt.Errorf("transfer: no 3270 console %04X", devno)
			}
			x := &Transfer{}
			if upload != starlark.None {
				data, err := dataOf(upload)
				if err != nil {
					return nil, fmt.Errorf("transfer: %v", err)
				}
				x.Upload = data
			}
			t.SetTransfer(x)
			return starlark.None, nil
		}), nil
	case "transfer_result":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			devno, err := devArg(name, args, kwargs)
			if err != nil {
				return nil, err
			}
			t := v.consoles[devno]
			if t == nil || t.TransferState() == nil {
				return starlark.None, nil
			}
			x := t.TransferState()
			return starfile.NewRecord(starlark.StringDict{
				"done": starlark.Bool(x.Done), "failed": starlark.Bool(x.Failed), "message": starlark.String(x.Message),
				"records": starlark.MakeInt(x.Records), "data": starlark.Bytes(x.Download.String()),
			}), nil
		}), nil
	case "disk_changes":
		// disk_changes() -> {device: written tracks}
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
				return nil, err
			}
			d := starlark.NewDict(4)
			for dev, n := range v.m.DASDOverlays() {
				d.SetKey(starlark.MakeInt(int(dev)), starlark.MakeInt(n))
			}
			return d, nil
		}), nil
	case "run":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			n := 1000000
			if err := starlark.UnpackArgs(name, args, kwargs, "instructions?", &n); err != nil {
				return nil, err
			}
			before := v.m.CPUs[0].Instructions
			began := time.Now()
			r := v.m.Run(uint64(n))
			ran := v.m.CPUs[0].Instructions - before
			return starfile.NewRecord(starlark.StringDict{
				"kind": starlark.String(r.Kind), "detail": starlark.String(r.Detail),
				"instructions": starlark.MakeUint64(ran), "psw": starlark.String(v.m.CPUs[0].PSW.String()),
				"seconds": starlark.Float(time.Since(began).Seconds()),
			}), nil
		}), nil
	case "psw":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.String(v.m.CPUs[0].PSW.String()), nil
		}), nil
	case "instructions":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.MakeUint64(v.m.CPUs[0].Instructions), nil
		}), nil
	case "registers":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			c := v.m.CPUs[0]
			gr, cr, ar := make([]starlark.Value, 16), make([]starlark.Value, 16), make([]starlark.Value, 16)
			for i := 0; i < 16; i++ {
				gr[i] = starlark.String(fmt.Sprintf("%08X", c.GR[i]))
				cr[i] = starlark.String(fmt.Sprintf("%08X", c.CR[i]))
				ar[i] = starlark.String(fmt.Sprintf("%08X", c.AR[i]))
			}
			return starfile.NewRecord(starlark.StringDict{"gr": starlark.NewList(gr), "cr": starlark.NewList(cr), "ar": starlark.NewList(ar),
				"prefix": starlark.String(fmt.Sprintf("%08X", c.Prefix)), "psw": starlark.String(c.PSW.String())}), nil
		}), nil
	case "screen", "screens":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if dev, err := devArg(name, args, kwargs); err == nil && v.lineConsoles[dev] != nil {
				lc := v.lineConsoles[dev]
				if name == "screen" {
					return starlark.String(lc.Text()), nil
				}
				return stringList(lc.Lines), nil
			}
			t, err := v.console(name, args, kwargs)
			if err != nil {
				return nil, err
			}
			if name == "screen" {
				return starlark.String(t.Text()), nil
			}
			out := make([]starlark.Value, len(t.Log))
			for i, s := range t.Log {
				out[i] = starlark.String(s)
			}
			return starlark.NewList(out), nil
		}), nil
	case "type":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var text string
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "text", &text); err != nil {
				return nil, err
			}
			if lc := v.lineConsoles[uint16(devno)]; lc != nil {
				lc.Type(text)
				return starlark.None, nil
			}
			t := v.consoles[uint16(devno)]
			if t == nil {
				return nil, fmt.Errorf("type: no console %04X", devno)
			}
			return starlark.None, t.Type(text)
		}), nil
	case "key":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			var key string
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "key", &key); err != nil {
				return nil, err
			}
			if lc := v.lineConsoles[uint16(devno)]; lc != nil {
				if key != "REQUEST" {
					return nil, fmt.Errorf("key: a 3215 has only the REQUEST key")
				}
				lc.Request()
				return starlark.None, nil
			}
			t := v.consoles[uint16(devno)]
			if t == nil {
				return nil, fmt.Errorf("key: no console %04X", devno)
			}
			return starlark.None, t.Key(key)
		}), nil
	case "cursor":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			row, col := -1, -1
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno, "row?", &row, "col?", &col); err != nil {
				return nil, err
			}
			t := v.consoles[uint16(devno)]
			if t == nil {
				return nil, fmt.Errorf("cursor: no console %04X", devno)
			}
			if row >= 0 {
				t.SetCursor(row, col)
			}
			r, c := t.Cursor()
			return starlark.Tuple{starlark.MakeInt(r), starlark.MakeInt(c)}, nil
		}), nil
	case "read":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr, n int
			virtual := false
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "length", &n, "virtual?", &virtual); err != nil {
				return nil, err
			}
			if virtual {
				b, err := v.m.ReadVirtual(uint32(addr), n)
				if err != nil {
					return nil, err
				}
				return starlark.Bytes(b), nil
			}
			if addr < 0 || n < 0 || n > 1<<20 || !v.m.S.valid(uint32(addr), uint32(n)) {
				return nil, fmt.Errorf("read: range outside storage")
			}
			return starlark.Bytes(v.m.S.Mem[addr : addr+n]), nil
		}), nil
	case "translate":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr); err != nil {
				return nil, err
			}
			a, err := v.m.TranslateVirtual(uint32(addr))
			if err != nil {
				return nil, err
			}
			return starlark.MakeUint64(uint64(a)), nil
		}), nil
	case "unknown":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			d := starlark.NewDict(8)
			for k, n := range v.m.CPUs[0].Unknown {
				d.SetKey(starlark.String(fmt.Sprintf("%04X", k)), starlark.MakeUint64(n))
			}
			return d, nil
		}), nil
	case "program_counts":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			d := starlark.NewDict(8)
			for k, n := range v.m.pgmCounts {
				d.SetKey(starlark.String(fmt.Sprintf("%02X", k)), starlark.MakeUint64(n))
			}
			return d, nil
		}), nil
	case "dasd_errors":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var devno int
			if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno); err != nil {
				return nil, err
			}
			d := v.dasd[uint16(devno)]
			if d == nil {
				return nil, fmt.Errorf("dasd_errors: no DASD %04X", devno)
			}
			out := make([]starlark.Value, len(d.Stats.Errors))
			for i, s := range d.Stats.Errors {
				out[i] = starlark.String(s)
			}
			return starfile.NewRecord(starlark.StringDict{"errors": starlark.NewList(out),
				"reads": starlark.MakeUint64(d.Stats.Reads), "writes": starlark.MakeUint64(d.Stats.Writes),
				"commands": starlark.MakeUint64(d.Stats.Commands), "tracks_written": starlark.MakeInt(len(d.overlay))}), nil
		}), nil
	case "time":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return starlark.String(v.m.Time().Format(time.RFC3339Nano)), nil
		}), nil
	case "break_at":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr); err != nil {
				return nil, err
			}
			if v.m.Breakpoints == nil {
				v.m.Breakpoints = map[uint32]bool{}
			}
			v.m.Breakpoints[uint32(addr)] = true
			return starlark.None, nil
		}), nil
	case "clear_breaks":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			v.m.Breakpoints = nil
			v.m.BreakProgram = nil
			return starlark.None, nil
		}), nil
	case "scp_config":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var cfg, cpu starlark.Bytes
			if err := starlark.UnpackArgs(name, args, kwargs, "bytes", &cfg, "cpu?", &cpu); err != nil {
				return nil, err
			}
			if len(cfg) != 6 || len(cpu) > 12 {
				return nil, fmt.Errorf("scp_config: six configuration bytes and up to twelve CPU facility bytes required")
			}
			copy(v.m.SCPConfig[:], cfg)
			copy(v.m.SCPCPUFacilities[:], cpu)
			return starlark.None, nil
		}), nil
	case "profile":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			on := starlark.Value(starlark.None)
			top := 20
			if err := starlark.UnpackArgs(name, args, kwargs, "on?", &on, "top?", &top); err != nil {
				return nil, err
			}
			if b, ok := on.(starlark.Bool); ok {
				if b {
					v.m.Profile = map[uint32]uint64{}
				} else {
					v.m.Profile = nil
				}
				return starlark.None, nil
			}
			type kv struct {
				k uint32
				n uint64
			}
			var all []kv
			for k, n := range v.m.Profile {
				all = append(all, kv{k, n})
			}
			sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n })
			out := []starlark.Value{}
			for i := 0; i < len(all) && i < top; i++ {
				out = append(out, starlark.String(fmt.Sprintf("%08X %d", all[i].k<<8, all[i].n)))
			}
			return starlark.NewList(out), nil
		}), nil
	case "screenshot":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			devno := -1
			rows, cols := 24, 80
			if err := starlark.UnpackArgs(name, args, kwargs, "device?", &devno, "rows?", &rows, "cols?", &cols); err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			fname := "hardware-console.png"
			if devno < 0 {
				// The hardware system console's operating system messages.
				if err := png.Encode(&buf, CaptureLines(v.m.ConsoleLines(), rows, cols)); err != nil {
					return nil, err
				}
			} else if lc := v.lineConsoles[uint16(devno)]; lc != nil {
				if err := png.Encode(&buf, CaptureLines(append(append([]string(nil), lc.Lines...), lc.Partial), rows, cols)); err != nil {
					return nil, err
				}
				fname = fmt.Sprintf("console-%04x.png", devno)
			} else {
				t := v.consoles[uint16(devno)]
				if t == nil {
					return nil, fmt.Errorf("screenshot: no console %04X", devno)
				}
				if err := png.Encode(&buf, t.Capture()); err != nil {
					return nil, err
				}
				fname = fmt.Sprintf("console-%04x.png", t.devno)
			}
			return &starfile.Bytes{Name: fname, Data: buf.Bytes()}, nil
		}), nil
	case "interrupts":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			d := starlark.NewDict(8)
			for k, n := range v.m.Interrupts {
				d.SetKey(starlark.String(k), starlark.MakeUint64(n))
			}
			for k, n := range v.m.CPUs[0].SIEExits {
				d.SetKey(starlark.String(fmt.Sprintf("sie-exit %d", k)), starlark.MakeUint64(n))
			}
			d.SetKey(starlark.String("sie-entries"), starlark.MakeUint64(v.m.CPUs[0].SIEEntries))
			d.SetKey(starlark.String("idle-skips"), starlark.MakeUint64(v.m.IdleSkips))
			return d, nil
		}), nil
	case "find":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var pat starlark.Bytes
			limit := 64
			if err := starlark.UnpackArgs(name, args, kwargs, "pattern", &pat, "limit?", &limit); err != nil {
				return nil, err
			}
			out := []starlark.Value{}
			mem := v.m.S.Mem
			p := []byte(pat)
			for i := 0; len(p) > 0 && i+len(p) <= len(mem) && len(out) < limit; {
				j := bytes.Index(mem[i:], p)
				if j < 0 {
					break
				}
				out = append(out, starlark.MakeInt(i+j))
				i += j + 1
			}
			return starlark.NewList(out), nil
		}), nil
	case "disassemble":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var addr, n int
			virtual := false
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &addr, "count", &n, "virtual?", &virtual); err != nil {
				return nil, err
			}
			out := []starlark.Value{}
			a := uint32(addr)
			for i := 0; i < n; i++ {
				var code []byte
				if virtual {
					b, err := v.m.ReadVirtual(a, 6)
					if err != nil {
						break
					}
					code = b
				} else {
					if !v.m.S.valid(a, 6) {
						break
					}
					code = v.m.S.Mem[a : a+6]
				}
				text, l := Disassemble(code, a)
				out = append(out, starlark.String(fmt.Sprintf("%08X %-12X %s", a, code[:l], text)))
				a += uint32(l)
			}
			return starlark.NewList(out), nil
		}), nil
	case "watch":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var lo, n int
			if err := starlark.UnpackArgs(name, args, kwargs, "address", &lo, "length", &n); err != nil {
				return nil, err
			}
			v.m.Watch(uint32(lo), uint32(lo+n))
			return starlark.None, nil
		}), nil
	case "history":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			n := -1
			guest := false
			if err := starlark.UnpackArgs(name, args, kwargs, "keep?", &n, "guest?", &guest); err != nil {
				return nil, err
			}
			if n >= 0 {
				v.m.EnableHistory(n)
				v.m.HistoryGuestOnly = guest
				return starlark.None, nil
			}
			h := v.m.RecentHistory()
			out := make([]starlark.Value, len(h))
			for i, e := range h {
				text, _ := Disassemble(e.Op[:], e.IA)
				out[i] = starlark.String(fmt.Sprintf("%08X %-12X %-28s cc%d", e.IA, e.Op[:ilen(e.Op[0])], text, e.CC))
			}
			return starlark.NewList(out), nil
		}), nil
	case "break_program":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var code int
			if err := starlark.UnpackArgs(name, args, kwargs, "code", &code); err != nil {
				return nil, err
			}
			if v.m.BreakProgram == nil {
				v.m.BreakProgram = map[uint16]bool{}
			}
			v.m.BreakProgram[uint16(code)] = true
			return starlark.None, nil
		}), nil
	case "event_limit":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var n int
			if err := starlark.UnpackArgs(name, args, kwargs, "count", &n); err != nil {
				return nil, err
			}
			if n < 1 || n > 1<<22 {
				return nil, fmt.Errorf("event_limit: count must be 1..4194304")
			}
			v.m.EventLimit = n
			return starlark.None, nil
		}), nil
	case "trace_io":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			on := true
			var skip *starlark.List
			if err := starlark.UnpackArgs(name, args, kwargs, "on?", &on, "skip?", &skip); err != nil {
				return nil, err
			}
			v.m.TraceIO = on
			v.m.TraceIOSkip = map[uint16]bool{}
			for i := 0; skip != nil && i < skip.Len(); i++ {
				d, err := starlark.AsInt32(skip.Index(i))
				if err != nil {
					return nil, err
				}
				v.m.TraceIOSkip[uint16(d)] = true
			}
			return starlark.None, nil
		}), nil
	case "events":
		return b(func(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			out := make([]starlark.Value, len(v.m.Events))
			for i, e := range v.m.Events {
				out[i] = starlark.String(fmt.Sprintf("%s cpu%d %s %s tod=%X", e.Kind, e.CPU, e.PSW, e.Detail, e.TOD>>12))
			}
			return starlark.NewList(out), nil
		}), nil
	}
	return nil, nil
}

func (v *machineValue) console(name string, args starlark.Tuple, kwargs []starlark.Tuple) (*Console3270, error) {
	var devno int
	if err := starlark.UnpackArgs(name, args, kwargs, "device", &devno); err != nil {
		return nil, err
	}
	t := v.consoles[uint16(devno)]
	if t == nil {
		return nil, fmt.Errorf("%s: no console %04X", name, devno)
	}
	return t, nil
}

func (v *machineValue) addDASD(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var devno int
	var file starlark.Value = starlark.None
	readOnly := false
	typ, cylinders, volser := "", 0, ""
	var ldl starlark.Value = starlark.None
	if err := starlark.UnpackArgs("dasd", args, kwargs, "device", &devno, "file?", &file, "read_only?", &readOnly, "type?", &typ, "cylinders?", &cylinders, "volser?", &volser, "ldl?", &ldl); err != nil {
		return nil, err
	}
	if ldl != starlark.None {
		// A 3390 in the Linux disk layout holding a partition image.
		src, ok := ldl.(storage.Reader)
		if !ok || cylinders <= 0 || cylinders > 65520 {
			return nil, fmt.Errorf("dasd: ldl needs a portable file and cylinders")
		}
		if src.Size() > LDLBlocks(uint32(cylinders))*4096 {
			return nil, fmt.Errorf("dasd: %d-byte partition exceeds %d cylinders", src.Size(), cylinders)
		}
		if volser == "" {
			volser = "LNX001"
		}
		d := NewDASD(LDLVolume{Data: src, Volser: strings.ToUpper(volser)}, 0x3390, uint32(cylinders), 15)
		d.ReadOnly = readOnly
		if _, err := v.m.CSS.Attach(uint16(devno), d); err != nil {
			return nil, err
		}
		v.dasd[uint16(devno)] = d
		return starlark.None, nil
	}
	var devType uint16
	if typ != "" {
		var t uint64
		if _, err := fmt.Sscanf(typ, "%x", &t); err != nil || t > 0xffff {
			return nil, fmt.Errorf("dasd: type %q", typ)
		}
		devType = uint16(t)
	}
	var d *DASD3390
	if file == starlark.None {
		// A newly initialized empty volume.
		var heads uint32
		for _, g := range DASDTypes {
			if g.Type == devType {
				heads = g.Heads
			}
		}
		if heads == 0 || cylinders <= 0 || volser == "" || len(volser) > 6 {
			return nil, fmt.Errorf("dasd: an empty volume needs a known type, cylinders and a volser of 1-6 characters")
		}
		d = NewDASD(FormattedVolume{Heads: heads, Volser: strings.ToUpper(volser)}, devType, uint32(cylinders), heads)
	} else {
		// A volume may be stored as several CKD files (a list of parts).
		var parts []storage.Reader
		if list, ok := file.(*starlark.List); ok {
			for i := 0; i < list.Len(); i++ {
				src, ok := list.Index(i).(storage.Reader)
				if !ok {
					return nil, fmt.Errorf("dasd: volume parts must be portable files")
				}
				parts = append(parts, src)
			}
		} else if src, ok := file.(storage.Reader); ok {
			parts = []storage.Reader{src}
		} else {
			return nil, fmt.Errorf("dasd: portable file or list of parts required")
		}
		disk, err := ckd.OpenParts(parts)
		if err != nil {
			return nil, err
		}
		g, known := DASDTypes[disk.Device]
		if devType == 0 {
			if !known {
				return nil, fmt.Errorf("dasd: unknown device code %02X; pass type=", disk.Device)
			}
			devType = g.Type
		}
		tracks := uint32((disk.Source.Size() - 512) / int64(disk.TrackSize))
		d = NewDASD(disk, devType, tracks/disk.Heads, disk.Heads)
	}
	d.ReadOnly = readOnly
	if _, err := v.m.CSS.Attach(uint16(devno), d); err != nil {
		return nil, err
	}
	v.dasd[uint16(devno)] = d
	return starlark.None, nil
}

func (v *machineValue) addConsole(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var devno int
	rows, cols, model := 24, 80, 0
	typ := "3270"
	if err := starlark.UnpackArgs("console", args, kwargs, "device", &devno, "rows?", &rows, "cols?", &cols, "type?", &typ, "model?", &model); err != nil {
		return nil, err
	}
	if typ == "3215" {
		lc := NewConsole3215()
		if err := v.m.CSS.AttachLineConsole(uint16(devno), lc); err != nil {
			return nil, err
		}
		v.lineConsoles[uint16(devno)] = lc
		return starlark.None, nil
	}
	if typ != "3270" {
		return nil, fmt.Errorf("console: type must be 3270 or 3215")
	}
	t := NewConsole3270(rows, cols)
	if model != 0 {
		if err := t.SetModel(model); err != nil {
			return nil, err
		}
	}
	if err := v.m.CSS.AttachConsole(uint16(devno), t); err != nil {
		return nil, err
	}
	v.consoles[uint16(devno)] = t
	return starlark.None, nil
}

func stringList(lines []string) *starlark.List {
	out := make([]starlark.Value, len(lines))
	for i, s := range lines {
		out[i] = starlark.String(s)
	}
	return starlark.NewList(out)
}

// dataOf reads a portable file or byte string.
func dataOf(v starlark.Value) ([]byte, error) {
	switch x := v.(type) {
	case starlark.Bytes:
		return []byte(x), nil
	case starlark.String:
		return []byte(x), nil
	case storage.Reader:
		return starfile.ReadAll(x)
	case interface{ StorageReader() storage.Reader }:
		return starfile.ReadAll(x.StorageReader())
	}
	return nil, fmt.Errorf("%s is not a file or bytes", v.Type())
}

// sortedKeys is a helper for deterministic output.
func sortedKeys[K ~uint16, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var _ = strings.TrimSpace

// webTerminals is m.web_terminals(devices=None, system_console=True,
// tn3270=None, state=None): the machine's consoles for interactive frontends. devices
// selects 3270 display stations, 3215 consoles and unit-record devices
// (readers, printers and punches; all of them, in device order, by default); system_console adds the hardware system console.
// Returned from a script's main under "trex -serve", the machine runs
// continuously, each console streams to web browsers, and with tn3270 set
// to a listen address the 3270 display stations also accept tn3270
// clients.
func (v *machineValue) webTerminals(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var devices *starlark.List
	system := true
	tn3270, state := "", ""
	autosave := 0
	var network *starlark.Dict
	if err := starlark.UnpackArgs("web_terminals", args, kwargs, "devices?", &devices, "system_console?", &system, "tn3270?", &tn3270, "state?", &state, "autosave?", &autosave, "network?", &network); err != nil {
		return nil, err
	}
	var netSpec *NetworkSpec
	if network != nil {
		var err error
		if netSpec, err = v.networkSpec(network); err != nil {
			return nil, err
		}
	}
	if autosave < 0 || autosave > 0 && (state == "" || autosave < 60) {
		return nil, fmt.Errorf("web_terminals: autosave needs a state file and an interval of at least 60 seconds")
	}
	var list []uint16
	if devices == nil {
		for d := range v.consoles {
			list = append(list, d)
		}
		for d := range v.lineConsoles {
			list = append(list, d)
		}
		for d := range v.units {
			list = append(list, d)
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	} else {
		for i := 0; i < devices.Len(); i++ {
			d, err := starlark.AsInt32(devices.Index(i))
			if err != nil {
				return nil, fmt.Errorf("web_terminals: %v", err)
			}
			list = append(list, uint16(d))
		}
	}
	out := &WebTerminals{TN3270: tn3270, State: state, AutoSave: time.Duration(autosave) * time.Second, Network: netSpec}
	var watched []Versioned
	for _, d := range list {
		t := WebTerminal{Name: fmt.Sprintf("%04X", d), Device: d}
		if c, ok := v.consoles[d]; ok {
			t.Display = c
			watched = append(watched, c)
		} else if c, ok := v.lineConsoles[d]; ok {
			t.Line = c
			watched = append(watched, c)
		} else if u, ok := v.units[d]; ok {
			if u.Reader() {
				t.Reader = u
			} else {
				t.Line, t.ReadOnly = u, true
			}
			watched = append(watched, u)
		} else {
			return nil, fmt.Errorf("web_terminals: no console at %04X", d)
		}
		out.Terminals = append(out.Terminals, t)
	}
	if system {
		sc := v.m.SystemConsole()
		out.Terminals = append(out.Terminals, WebTerminal{Name: "SYSTEM", Line: sc})
		watched = append(watched, sc)
	}
	if len(out.Terminals) == 0 {
		return nil, fmt.Errorf("web_terminals: no consoles")
	}
	out.Live = NewLive(v.m, watched...)
	return out, nil
}

// WebTerminal is one console offered to interactive frontends: a 3270
// display station (Display), a line-mode console (Line; ReadOnly for a
// printer or punch) or a card reader (Reader).
type WebTerminal struct {
	Name     string
	Device   uint16
	Display  *Console3270
	Line     LineConsole
	ReadOnly bool
	Reader   *UnitRecord
}

// WebTerminals is the Starlark value naming a live machine's consoles.
type WebTerminals struct {
	Live      *Live
	Terminals []WebTerminal
	// TN3270 is the tn3270 listen address, or empty.
	TN3270 string
	// State names where the native frontend saves checkpoints (on request
	// and at shutdown), or is empty.
	State string
	// AutoSave, when nonzero, saves the state at this interval.
	AutoSave time.Duration
	// Network, when set, connects a CTC adapter to the host.
	Network *NetworkSpec
}

// NetworkSpec connects a machine's CTC adapter to a host-side IP network:
// the guest has Address, and each Forwards entry maps a host listen
// address ("127.0.0.1:2323") to a guest TCP port.
type NetworkSpec struct {
	CTC      *CTCI
	Address  string
	Forwards map[string]int
}

// networkSpec parses network={"ctc": 0xE40, "address": "10.0.0.2",
// "forward": {"127.0.0.1:2323": 23}}.
func (v *machineValue) networkSpec(d *starlark.Dict) (*NetworkSpec, error) {
	get := func(key string) starlark.Value {
		x, _, _ := d.Get(starlark.String(key))
		return x
	}
	dev, err := starlark.AsInt32(get("ctc"))
	if err != nil {
		return nil, fmt.Errorf("web_terminals: network needs ctc, the adapter's device number")
	}
	c := v.ctcs[uint16(dev)]
	if c == nil {
		return nil, fmt.Errorf("web_terminals: no CTC adapter at %04X", dev)
	}
	addr, ok := starlark.AsString(get("address"))
	if !ok || addr == "" {
		return nil, fmt.Errorf("web_terminals: network needs the guest's address")
	}
	spec := &NetworkSpec{CTC: c, Address: addr, Forwards: map[string]int{}}
	if f, ok := get("forward").(*starlark.Dict); ok {
		for _, item := range f.Items() {
			host, ok := starlark.AsString(item[0])
			port, err := starlark.AsInt32(item[1])
			if !ok || err != nil || port <= 0 || port > 65535 {
				return nil, fmt.Errorf("web_terminals: network forward maps \"host:port\" to a guest port")
			}
			spec.Forwards[host] = port
		}
	}
	return spec, nil
}

func (w *WebTerminals) String() string {
	return fmt.Sprintf("<s390 web terminals %d>", len(w.Terminals))
}
func (w *WebTerminals) Type() string          { return "s390_web_terminals" }
func (w *WebTerminals) Freeze()               {}
func (w *WebTerminals) Truth() starlark.Bool  { return starlark.True }
func (w *WebTerminals) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: s390 web terminals") }
