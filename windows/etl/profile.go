package etl

import (
	"context"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"
)

// Profile is an IP-sampling profile, not an inferred CSwitch/function profile.
// Samples are counts, not seconds; no fixed interrupt frequency is assumed.
type Profile struct {
	Header         Header           `json:"header"`
	Samples        uint64           `json:"samples"`
	UnknownProcess uint64           `json:"unknown_process_samples"`
	UnknownImage   uint64           `json:"unknown_image_samples"`
	Modules        []Module         `json:"modules"`
	Processes      []ProfileProcess `json:"processes"`
	Points         []SamplePoint    `json:"points"`
	Warnings       []string         `json:"warnings"`
}
type Module struct {
	Path      string `json:"path"`
	Size      uint64 `json:"size"`
	Timestamp uint32 `json:"timestamp"`
	Checksum  uint32 `json:"checksum"`
}
type ProfileProcess struct {
	PID       uint32 `json:"pid"`
	StartTick uint64 `json:"start_tick"`
	Image     string `json:"image"`
	Command   string `json:"command_line"`
}
type SamplePoint struct {
	Process   int    `json:"process"`
	Module    int    `json:"module"`
	RVA       uint64 `json:"rva"`
	Interrupt bool   `json:"interrupt"`
	Samples   uint64 `json:"samples"`
}
type profileEvent struct {
	tick                uint64
	pid, tid            uint32
	kind, op            byte
	address, size       uint64
	timestamp, checksum uint32
	name, command       string
	interrupt           bool
}

func ProfileTrace(ctx context.Context, r io.ReaderAt, size int64, limits Limits) (*Profile, error) {
	out := &Profile{Modules: []Module{}, Processes: []ProfileProcess{}, Points: []SamplePoint{}, Warnings: []string{}}
	var events []profileEvent
	pointer := 4
	first := true
	h, err := Walk(ctx, r, size, limits, func(e Event) error {
		if first {
			header, err := logfileHeader(e)
			if err != nil {
				return err
			}
			pointer = int(header.PointerSize)
			if pointer != 8 {
				return fmt.Errorf("sampled profile currently requires a 64-bit trace")
			}
			first = false
		}
		p, ok, err := decodeProfile(e, pointer)
		if err != nil {
			return fmt.Errorf("ETL profile at %#x: %w", e.Offset, err)
		}
		if ok {
			events = append(events, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Header = h
	sort.SliceStable(events, func(i, j int) bool { return events[i].tick < events[j].tick })
	proc := map[uint32]int{}
	threads := map[uint32]int{}
	type mapping struct {
		base, size uint64
		module     int
	}
	images := map[int][]mapping{}
	modules := map[Module]int{}
	type pointKey struct {
		p, m      int
		rva       uint64
		interrupt bool
	}
	counts := map[pointKey]uint64{}
	getProc := func(pid uint32, tick uint64) int {
		if index, ok := proc[pid]; ok {
			return index
		}
		index := len(out.Processes)
		proc[pid] = index
		out.Processes = append(out.Processes, ProfileProcess{PID: pid, StartTick: tick, Image: "<unknown>"})
		return index
	}
	for i, e := range events {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		switch e.kind {
		case 3:
			if e.op == 4 {
				continue
			} // End rundown cannot establish a prior lifetime.
			if e.op == 1 {
				if index, ok := proc[e.pid]; ok && out.Processes[index].Image != "<unknown>" {
					delete(proc, e.pid)
					delete(images, index)
					for tid, p := range threads {
						if p == index {
							delete(threads, tid)
						}
					}
				}
			}
			index := getProc(e.pid, e.tick)
			if e.name != "" {
				out.Processes[index].Image = e.name
				out.Processes[index].Command = e.command
			}
			if e.op == 2 {
				delete(proc, e.pid)
				for tid, p := range threads {
					if p == index {
						delete(threads, tid)
					}
				}
				delete(images, index)
			}
		case 5:
			if e.op == 1 || e.op == 3 {
				threads[e.tid] = getProc(e.pid, e.tick)
			} else if e.op == 2 {
				delete(threads, e.tid)
			}
		case 20:
			// Kernel addresses are shared across process address spaces.
			p := -1
			if e.address < 1<<63 {
				p = getProc(e.pid, e.tick)
			}
			if e.op == 2 {
				rows := images[p]
				for j := len(rows) - 1; j >= 0; j-- {
					if rows[j].base == e.address {
						rows = append(rows[:j], rows[j+1:]...)
					}
				}
				images[p] = rows
				continue
			}
			if e.op == 4 {
				continue
			} // End rundown is not evidence of an earlier load epoch.
			m := Module{Path: e.name, Size: e.size, Timestamp: e.timestamp, Checksum: e.checksum}
			mi, ok := modules[m]
			if !ok {
				mi = len(out.Modules)
				out.Modules = append(out.Modules, m)
				modules[m] = mi
			}
			rows := images[p]
			for j := len(rows) - 1; j >= 0; j-- {
				if rows[j].base == e.address {
					rows = append(rows[:j], rows[j+1:]...)
				}
			}
			images[p] = append(rows, mapping{base: e.address, size: e.size, module: mi})
		case 15:
			out.Samples++
			p, ok := threads[e.tid]
			if !ok {
				p = -1
				out.UnknownProcess++
			}
			space := p
			if e.address >= 1<<63 {
				space = -1
			} else if p < 0 {
				space = -2
			}
			module := -1
			rva := e.address
			for _, m := range images[space] {
				if e.address >= m.base && e.address-m.base < m.size {
					if module >= 0 {
						module = -1
						rva = e.address
						break
					} // Overlapping images are ambiguous.
					module = m.module
					rva = e.address - m.base
				}
			}
			if module < 0 {
				out.UnknownImage++
			}
			counts[pointKey{p, module, rva, e.interrupt}]++
		}
	}
	for k, n := range counts {
		out.Points = append(out.Points, SamplePoint{Process: k.p, Module: k.m, RVA: k.rva, Interrupt: k.interrupt, Samples: n})
	}
	sort.Slice(out.Points, func(i, j int) bool {
		a, b := out.Points[i], out.Points[j]
		if a.Samples != b.Samples {
			return a.Samples > b.Samples
		}
		if a.Process != b.Process {
			return a.Process < b.Process
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.RVA != b.RVA {
			return a.RVA < b.RVA
		}
		return !a.Interrupt && b.Interrupt
	})
	if h.EventsLost != 0 || h.BuffersLost != 0 || h.LossFlaggedBuffers != 0 {
		out.Warnings = append(out.Warnings, "ETW loss: attribution may be incomplete or stale across unobserved lifecycle transitions")
	}
	if out.Samples == 0 {
		out.Warnings = append(out.Warnings, "No supported sampled-profile events; enable PROFILE before boot")
	}
	out.Warnings = append(out.Warnings, "IP samples are self cost only, not caller stacks or inclusive cost; sampled interrupt execution is tagged separately", "Unresolved images/threads remain explicit; end rundown is not retroactively treated as a load", "Sample counts are not wall time and do not measure host vCPU descheduling")
	return out, nil
}
func profilePointer(b []byte, p int) uint64 {
	if p == 8 {
		return le.Uint64(b)
	}
	return uint64(le.Uint32(b))
}
func decodeProfile(e Event, pointer int) (profileEvent, bool, error) {
	p := profileEvent{tick: e.Timestamp, op: e.Opcode, kind: e.Group}
	b := e.Payload
	short := func() (profileEvent, bool, error) {
		return p, false, fmt.Errorf("short profile payload group=%d op=%d version=%d", e.Group, e.Opcode, e.Version)
	}
	if e.Group == 3 && e.Opcode <= 4 || e.Group == 5 && e.Opcode <= 4 {
		it, ok, err := decode(e, pointer)
		p.pid = it.x
		p.tid = it.y
		p.name = it.name
		p.command = it.command
		return p, ok, err
	}
	if e.Group == 15 && e.Opcode == 46 && e.Version == 2 {
		if len(b) < pointer+8 {
			return short()
		}
		p.address = profilePointer(b, pointer)
		p.tid = le.Uint32(b[pointer:])
		p.interrupt = b[pointer+6]&3 != 0
		return p, true, nil
	}
	if (e.Group == 3 && e.Opcode == 10 || e.Group == 20 && e.Opcode >= 2 && e.Opcode <= 4) && (e.Version == 2 || e.Version == 3) {
		offset := 44 + 3*(pointer-4)
		if len(b) < offset+2 {
			return short()
		}
		p.kind = 20
		p.address = profilePointer(b, pointer)
		p.size = profilePointer(b[pointer:], pointer)
		p.pid = le.Uint32(b[2*pointer:])
		p.checksum = le.Uint32(b[2*pointer+4:])
		p.timestamp = le.Uint32(b[2*pointer+8:])
		if p.size == 0 || p.address+p.size < p.address {
			return p, false, fmt.Errorf("invalid image range")
		}
		var chars []uint16
		terminated := false
		for off := offset; off+2 <= len(b); off += 2 {
			c := le.Uint16(b[off:])
			if c == 0 {
				terminated = true
				break
			}
			chars = append(chars, c)
		}
		if !terminated {
			return short()
		}
		p.name = string(utf16.Decode(chars))
		return p, true, nil
	}
	return p, false, nil
}
