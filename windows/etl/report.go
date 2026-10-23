package etl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"unicode/utf16"
)

// Report deliberately separates elapsed time, CPU-seconds and overlapping I/O
// response time. It is not a causal critical-path or sampled-stack profile.
type Report struct {
	DPCSeconds            float64    `json:"dpc_seconds_sum"`
	ISRSeconds            float64    `json:"isr_seconds_sum"`
	Header                Header     `json:"header"`
	Events                int        `json:"events"`
	FirstTick             uint64     `json:"first_tick"`
	LastTick              uint64     `json:"last_tick"`
	ElapsedSeconds        float64    `json:"observed_seconds"`
	ScheduledSeconds      float64    `json:"scheduled_cpu_seconds"`
	IdleSeconds           float64    `json:"idle_cpu_seconds"`
	UnknownThreadSeconds  float64    `json:"unknown_thread_cpu_seconds"`
	UncoveredSeconds      float64    `json:"uncovered_cpu_seconds"`
	SwitchDiscontinuities int        `json:"switch_discontinuities"`
	Processes             []*Process `json:"processes"`
	Timeline              []Bucket   `json:"timeline"`
	Schemas               []*Schema  `json:"schemas"`
	Warnings              []string   `json:"warnings"`
}
type Schema struct {
	Group      byte   `json:"group"`
	Opcode     byte   `json:"opcode"`
	Version    uint16 `json:"version"`
	HeaderType byte   `json:"header_type"`
	Count      int    `json:"count"`
	Decoded    int    `json:"decoded"`
}
type Process struct {
	Timeline []*ProcessBucket `json:"timeline"`
	buckets  map[int]*ProcessBucket

	CommandLine            string           `json:"command_line"`
	ReadySeconds           float64          `json:"ready_thread_seconds_sum"`
	BlockedSeconds         float64          `json:"blocked_thread_seconds_sum"`
	WaitReasons            map[byte]float64 `json:"wait_reason_thread_seconds"`
	PID                    uint32           `json:"pid"`
	ParentPID              uint32           `json:"parent_pid"`
	Image                  string           `json:"image"`
	FirstSeenSeconds       float64          `json:"first_seen_seconds"`
	StartObserved          bool             `json:"start_observed"`
	EndSeconds             *float64         `json:"end_seconds,omitempty"`
	CPUSeconds             float64          `json:"scheduled_cpu_seconds"`
	DiskReads              uint64           `json:"disk_reads"`
	DiskWrites             uint64           `json:"disk_writes"`
	ReadBytes              uint64           `json:"read_bytes"`
	WriteBytes             uint64           `json:"write_bytes"`
	DiskResponseSeconds    float64          `json:"disk_response_seconds_sum"`
	MaxDiskResponseSeconds float64          `json:"disk_response_seconds_max"`
}

// ProcessBucket is sparse: omitted seconds contain no attributed CPU or disk I/O.
// Disk bytes are charged at completion, not spread over response time.
type ProcessBucket struct {
	Second     int     `json:"second"`
	CPUSeconds float64 `json:"scheduled_cpu_seconds"`
	ReadBytes  uint64  `json:"read_bytes"`
	WriteBytes uint64  `json:"write_bytes"`
}

type Bucket struct {
	Second     int     `json:"second"`
	Busy       float64 `json:"busy_cpu_seconds"`
	Idle       float64 `json:"idle_cpu_seconds"`
	Unknown    float64 `json:"unknown_thread_cpu_seconds"`
	ReadBytes  uint64  `json:"read_bytes"`
	WriteBytes uint64  `json:"write_bytes"`
}

type item struct {
	command       string
	state, reason byte
	tick          uint64
	cpu           uint16
	group, op     byte
	x, y          uint32
	amount        uint32
	duration      uint64
	name          string
}

// Analyze reads once, retains only decoded compact records, then sorts them by
// time. It bounds file bytes, event count and timeline length; cancellation is
// checked during both I/O and analysis. The caller owns the ReaderAt.
func Analyze(ctx context.Context, r io.ReaderAt, size int64, limits Limits) (*Report, error) {
	out := &Report{Warnings: []string{}, Processes: []*Process{}, Timeline: []Bucket{}, Schemas: []*Schema{}}
	var events []item
	schemas := map[[4]uint16]*Schema{}
	pointer := 4
	traceClock := uint32(1)
	h, err := Walk(ctx, r, size, limits, func(e Event) error {
		out.Events++
		if out.Events == 1 {
			header, err := logfileHeader(e)
			if err != nil {
				return err
			}
			pointer = int(header.PointerSize)
			traceClock = header.Clock
		}
		if out.Events == 1 || e.Timestamp < out.FirstTick {
			out.FirstTick = e.Timestamp
		}
		if e.Timestamp > out.LastTick {
			out.LastTick = e.Timestamp
		}
		key := [4]uint16{uint16(e.Group), uint16(e.Opcode), e.Version, uint16(e.HeaderType)}
		s := schemas[key]
		if s == nil {
			if len(schemas) >= 4096 {
				return fmt.Errorf("ETL: schema limit exceeded")
			}
			s = &Schema{Group: e.Group, Opcode: e.Opcode, Version: e.Version, HeaderType: e.HeaderType}
			schemas[key] = s
		}
		s.Count++
		it, ok, err := decode(e, pointer)
		if e.Group == 15 && traceClock != 1 {
			ok = false
		}
		if err != nil {
			return fmt.Errorf("ETL payload at %#x: %w", e.Offset, err)
		}
		if ok {
			s.Decoded++
			events = append(events, it)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Header = h
	freq := float64(h.QPCFrequency)
	if h.Clock == 2 {
		freq = 10_000_000
	}
	seconds := func(t uint64) float64 { return float64(t-out.FirstTick) / freq }
	out.ElapsedSeconds = seconds(out.LastTick)
	if out.ElapsedSeconds > 86400 || out.ElapsedSeconds < 0 {
		return nil, fmt.Errorf("ETL: invalid or excessive timestamp range")
	}
	for _, s := range schemas {
		out.Schemas = append(out.Schemas, s)
	}
	sort.Slice(out.Schemas, func(i, j int) bool {
		a, b := out.Schemas[i], out.Schemas[j]
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		if a.Opcode != b.Opcode {
			return a.Opcode < b.Opcode
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.HeaderType < b.HeaderType
	})
	sort.SliceStable(events, func(i, j int) bool { return events[i].tick < events[j].tick })
	out.Timeline = make([]Bucket, int(out.ElapsedSeconds)+1)
	for i := range out.Timeline {
		out.Timeline[i].Second = i
	}
	// Bound sparse attribution independently of timestamp and event limits.
	bucketCount := 0
	processBucket := func(p *Process, second int) (*ProcessBucket, error) {
		if b := p.buckets[second]; b != nil {
			return b, nil
		}
		if bucketCount >= 1_000_000 {
			return nil, fmt.Errorf("ETL: process timeline bucket limit exceeded")
		}
		bucketCount++
		b := &ProcessBucket{Second: second}
		p.buckets[second] = b
		p.Timeline = append(p.Timeline, b)
		return b, nil
	}
	current := map[uint32]*Process{}
	threads := map[uint32]*Process{}
	type wait struct {
		tick   uint64
		p      *Process
		reason byte
	}
	ready := map[uint32]wait{}
	blocked := map[uint32]wait{}
	getProcess := func(pid uint32, t float64) *Process {
		if p := current[pid]; p != nil {
			return p
		}
		p := &Process{Timeline: []*ProcessBucket{}, buckets: map[int]*ProcessBucket{}, PID: pid, Image: "<unknown>", FirstSeenSeconds: t, WaitReasons: map[byte]float64{}}
		current[pid] = p
		out.Processes = append(out.Processes, p)
		return p
	}
	type running struct {
		tick  uint64
		tid   uint32
		p     *Process
		valid bool
	}
	cpus := make([]running, h.Processors)
	switches := 0
	for i, e := range events {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		t := seconds(e.tick)
		switch e.group {
		case 3:
			p := getProcess(e.x, t)
			if e.op == 1 && p.StartObserved {
				delete(current, e.x)
				p = getProcess(e.x, t)
			}
			if e.name != "" {
				p.Image = e.name
				p.CommandLine = e.command
			}
			p.ParentPID = e.y
			if e.op == 1 {
				p.StartObserved = true
				p.FirstSeenSeconds = t
			}
			if e.op == 2 {
				end := t
				p.EndSeconds = &end
				delete(current, e.x)
			}
		case 5:
			switch e.op {
			case 1, 3:
				threads[e.y] = getProcess(e.x, t)
				delete(ready, e.y)
				delete(blocked, e.y)
			case 2, 4:
				// Rundown-end can name a thread already tracked, but is not a real exit.
				if e.op == 2 {
					delete(threads, e.y)
					delete(ready, e.y)
					delete(blocked, e.y)
				}
			case 50:
				if w, ok := blocked[e.x]; ok && w.p != nil && w.p == threads[e.x] {
					d := float64(e.tick-w.tick) / freq
					w.p.BlockedSeconds += d
					w.p.WaitReasons[w.reason] += d
				}
				delete(blocked, e.x)
				if _, ok := ready[e.x]; !ok {
					ready[e.x] = wait{tick: e.tick, p: threads[e.x]}
				}
			case 36:
				if w, ok := ready[e.x]; ok && w.p != nil && w.p == threads[e.x] {
					w.p.ReadySeconds += float64(e.tick-w.tick) / freq
				}
				delete(ready, e.x)
				delete(blocked, e.x)
				if e.y != 0 {
					delete(ready, e.y)
					delete(blocked, e.y)
					if e.state == 1 {
						ready[e.y] = wait{tick: e.tick, p: threads[e.y]}
					}
					if e.state == 5 {
						blocked[e.y] = wait{tick: e.tick, p: threads[e.y], reason: e.reason}
					}
				}
				switches++
				if int(e.cpu) >= len(cpus) {
					return nil, fmt.Errorf("ETL: CPU index %d exceeds header count", e.cpu)
				}
				prev := cpus[e.cpu]
				if prev.valid && prev.tid == e.y {
					from := seconds(prev.tick)
					duration := t - from
					category := 0
					if prev.tid == 0 {
						out.IdleSeconds += duration
						category = 1
					} else if prev.p != nil {
						prev.p.CPUSeconds += duration
						out.ScheduledSeconds += duration
					} else {
						out.UnknownThreadSeconds += duration
						category = 2
					}
					for start := from; start < t; {
						bucket := int(start)
						end := float64(bucket + 1)
						if end > t {
							end = t
						}
						span := end - start
						switch category {
						case 0:
							out.Timeline[bucket].Busy += span
							b, err := processBucket(prev.p, bucket)
							if err != nil {
								return nil, err
							}
							b.CPUSeconds += span
						case 1:
							out.Timeline[bucket].Idle += span
						case 2:
							out.Timeline[bucket].Unknown += span
						}
						start = end
					}
				} else if prev.valid {
					out.SwitchDiscontinuities++
				}
				cpus[e.cpu] = running{tick: e.tick, tid: e.x, p: threads[e.x], valid: true}
			}
		case 15:
			duration := float64(e.tick-e.duration) / freq
			if e.op == 50 || e.op == 67 {
				out.ISRSeconds += duration
			} else {
				out.DPCSeconds += duration
			}
		case 1:
			p := threads[e.x]
			if p == nil {
				p = getProcess(0xffffffff, t)
			}
			b, err := processBucket(p, int(t))
			if err != nil {
				return nil, err
			}
			response := float64(e.duration) / float64(h.QPCFrequency)
			p.DiskResponseSeconds += response
			if response > p.MaxDiskResponseSeconds {
				p.MaxDiskResponseSeconds = response
			}
			if e.op == 10 {
				p.DiskReads++
				p.ReadBytes += uint64(e.amount)
				b.ReadBytes += uint64(e.amount)
				out.Timeline[int(t)].ReadBytes += uint64(e.amount)
			} else {
				p.DiskWrites++
				p.WriteBytes += uint64(e.amount)
				b.WriteBytes += uint64(e.amount)
				out.Timeline[int(t)].WriteBytes += uint64(e.amount)
			}
		}
	}
	out.UncoveredSeconds = out.ElapsedSeconds*float64(h.Processors) - out.ScheduledSeconds - out.IdleSeconds - out.UnknownThreadSeconds
	if out.UncoveredSeconds < 0 && out.UncoveredSeconds > -1e-6 {
		out.UncoveredSeconds = 0
	}
	for _, p := range out.Processes {
		sort.Slice(p.Timeline, func(i, j int) bool { return p.Timeline[i].Second < p.Timeline[j].Second })
		p.buckets = nil
	}
	sort.SliceStable(out.Processes, func(i, j int) bool { return out.Processes[i].CPUSeconds > out.Processes[j].CPUSeconds })
	if h.EventsLost != 0 || h.BuffersLost != 0 || h.LossFlaggedBuffers != 0 {
		out.Warnings = append(out.Warnings, "ETW reports lost events/buffers: CPU and I/O totals are incomplete; matching switch IDs cannot detect every lost interval")
	}
	if switches == 0 {
		out.Warnings = append(out.Warnings, "No supported context switches: CPU attribution unavailable")
	}
	if out.SwitchDiscontinuities != 0 {
		out.Warnings = append(out.Warnings, "Context-switch discontinuities were excluded, not attributed across gaps")
	}
	out.Warnings = append(out.Warnings, "Times are relative to the first recorded event, not firmware entry; construction/firmware and pre-logger boot are outside this trace", "Scheduled CPU includes DPC/ISR interruption time; no sampled stacks or symbols are recorded", "Disk response times overlap; their sum is not wall-clock boot delay",
		"Ready and blocked durations are matched thread intervals, summed across threads; they are not boot critical-path delays", "Unsupported payload schemas are counted in the schema inventory; missing data is not evidence of no activity")
	return out, nil
}

func decode(e Event, pointer int) (item, bool, error) {
	it := item{tick: e.Timestamp, cpu: e.CPU, group: e.Group, op: e.Opcode}
	b := e.Payload
	short := func() (item, bool, error) {
		return it, false, fmt.Errorf("short group=%d opcode=%d version=%d payload (%d bytes)", e.Group, e.Opcode, e.Version, len(b))
	}
	if e.Group == 3 && e.Opcode >= 1 && e.Opcode <= 4 && e.Version >= 2 && e.Version <= 5 {
		fixed := 20 + pointer - 4
		if e.Version >= 3 {
			fixed = 24 + 2*(pointer-4)
		}
		if e.Version >= 4 {
			fixed = 28 + 2*(pointer-4)
		}
		if len(b) < fixed+4 {
			return short()
		}
		it.x = le.Uint32(b[pointer:])
		it.y = le.Uint32(b[pointer+4:])
		name := fixed + 4
		if le.Uint32(b[fixed:]) != 0 {
			sid := fixed + 2*pointer
			if len(b) < sid+8 {
				return short()
			}
			name = sid + 8 + 4*int(b[sid+1])
			if b[sid+1] > 15 || name > len(b) {
				return short()
			}
		}
		end := bytes.IndexByte(b[name:], 0)
		if end < 0 {
			return short()
		}
		it.name = string(bytes.ToValidUTF8(b[name:name+end], []byte("?")))
		command := b[name+end+1:]
		var units []uint16
		for len(command) >= 2 {
			u := le.Uint16(command)
			command = command[2:]
			if u == 0 {
				break
			}
			units = append(units, u)
		}
		it.command = string(utf16.Decode(units))
		return it, true, nil
	}
	if e.Group == 5 {
		if e.Opcode >= 1 && e.Opcode <= 4 && e.Version >= 1 && e.Version <= 4 {
			if len(b) < 8 {
				return short()
			}
			it.x = le.Uint32(b)
			it.y = le.Uint32(b[4:])
			return it, true, nil
		}
		if e.Opcode == 50 && e.Version == 2 {
			if len(b) < 8 {
				return short()
			}
			it.x = le.Uint32(b)
			return it, true, nil
		}
		if e.Opcode == 36 && (e.Version == 2 || e.Version == 3 || e.Version == 4 || e.Version == 5) {
			if len(b) < 24 {
				return short()
			}
			it.reason = b[12]
			it.state = b[14]
			it.x = le.Uint32(b)
			it.y = le.Uint32(b[4:])
			return it, true, nil
		}
	}
	if e.Group == 1 && (e.Opcode == 10 || e.Opcode == 11) && e.Version >= 2 && e.Version <= 3 {
		end := 40 + 2*(pointer-4)
		if len(b) < end {
			return short()
		}
		it.amount = le.Uint32(b[8:])
		it.duration = le.Uint64(b[end-8:])
		it.x = e.TID
		if len(b) >= end+4 {
			it.x = le.Uint32(b[end:])
		}
		return it, true, nil
	}
	if e.Group == 15 && e.Version == 2 && (e.Opcode == 50 || e.Opcode == 66 || e.Opcode == 67 || e.Opcode == 68 || e.Opcode == 69) {
		if len(b) < 8+pointer {
			return short()
		}
		it.duration = le.Uint64(b)
		if it.duration > it.tick {
			return it, false, fmt.Errorf("interrupt starts after it ends")
		}
		return it, true, nil
	}
	return it, false, nil
}
