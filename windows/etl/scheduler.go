package etl

import (
	"context"
	"fmt"
	"io"
	"sort"
)

// SchedulerRecord is an observation, not a causal wait-chain assertion.
// On ready events, PeerTID is the thread observed on that CPU at emission;
// interrupts/DPCs may be the actual source. Zero means idle or unknown.
type SchedulerRecord struct {
	Seconds float64 `json:"seconds"`
	Kind    string  `json:"kind"`
	TID     uint32  `json:"tid"`
	PeerTID uint32  `json:"peer_tid"`
	PeerPID uint32  `json:"peer_pid"`
	CPU     uint16  `json:"cpu"`
	State   byte    `json:"state"`
	Reason  byte    `json:"reason"`
}
type SchedulerReport struct {
	Header          Header            `json:"header"`
	FirstTick       uint64            `json:"first_tick"`
	LastTick        uint64            `json:"last_tick"`
	Records         []SchedulerRecord `json:"records"`
	Unsupported     int               `json:"unsupported_thread_events"`
	Discontinuities int               `json:"switch_discontinuities"`
}

// SchedulerTrace returns timestamp-ordered thread lifecycle and scheduling
// observations for a PID. Reused TIDs are attributed only during the observed
// owner lifetime. PID reuse is exposed by process_start/process_end records.
// End rundown never invents an earlier thread lifetime. All input is validated;
// framing errors fail and loss counters remain visible. Unsupported thread
// events are counted; use Analyze for the complete schema inventory.
func SchedulerTrace(ctx context.Context, r io.ReaderAt, size int64, limits Limits, pid uint32, maxRecords int) (*SchedulerReport, error) {
	if maxRecords < 1 || maxRecords > 1000000 {
		return nil, fmt.Errorf("ETL: scheduler result limit must be 1..1000000")
	}
	out := &SchedulerReport{Records: []SchedulerRecord{}}
	var events []item
	pointer, count := 4, 0
	h, err := Walk(ctx, r, size, limits, func(e Event) error {
		if count == 0 {
			h, err := logfileHeader(e)
			if err != nil {
				return err
			}
			pointer = int(h.PointerSize)
			out.FirstTick = e.Timestamp
		}
		count++
		if e.Timestamp < out.FirstTick {
			out.FirstTick = e.Timestamp
		}
		if e.Timestamp > out.LastTick {
			out.LastTick = e.Timestamp
		}
		if e.Group != 3 && e.Group != 5 {
			return nil
		}
		it, ok, err := decode(e, pointer)
		if err != nil {
			return err
		}
		if !ok {
			if e.Group == 5 {
				out.Unsupported++
			}
			return nil
		}
		events = append(events, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Header = h
	freq := float64(h.QPCFrequency)
	if h.Clock == 2 {
		freq = 10000000
	}
	if freq <= 0 || out.LastTick-out.FirstTick > uint64(freq*86400) {
		return nil, fmt.Errorf("ETL: invalid scheduler time range")
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].tick < events[j].tick })
	owners := map[uint32]uint32{}
	running := make([]uint32, h.Processors)
	known := make([]bool, h.Processors)
	emit := func(e item, kind string, tid, peer uint32) error {
		if len(out.Records) >= maxRecords {
			return fmt.Errorf("ETL: scheduler result limit exceeded")
		}
		out.Records = append(out.Records, SchedulerRecord{Seconds: float64(e.tick-out.FirstTick) / freq, Kind: kind, TID: tid, PeerTID: peer, PeerPID: owners[peer], CPU: e.cpu, State: e.state, Reason: e.reason})
		return nil
	}
	for i, e := range events {
		if i%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if e.group == 3 {
			if e.op == 1 || e.op == 2 {
				if e.x == pid {
					kind := "process_start"
					if e.op == 2 {
						kind = "process_end"
					}
					if err := emit(e, kind, 0, 0); err != nil {
						return nil, err
					}
				}
				for tid, owner := range owners {
					if owner == e.x {
						delete(owners, tid)
					}
				}
			}
			continue
		}
		switch e.op {
		case 1, 3:
			owners[e.y] = e.x
			if e.x == pid {
				kind := "thread_start"
				if e.op == 3 {
					kind = "thread_rundown"
				}
				if err := emit(e, kind, e.y, 0); err != nil {
					return nil, err
				}
			}
		case 2:
			if owner, ok := owners[e.y]; ok && owner == pid {
				if err := emit(e, "thread_end", e.y, 0); err != nil {
					return nil, err
				}
			}
			delete(owners, e.y)
		case 36:
			if int(e.cpu) >= len(running) {
				return nil, fmt.Errorf("ETL: CPU index exceeds header count")
			}
			if known[e.cpu] && running[e.cpu] != e.y {
				out.Discontinuities++
			}
			if owner, ok := owners[e.y]; ok && owner == pid {
				if err := emit(e, "out", e.y, e.x); err != nil {
					return nil, err
				}
			}
			if owner, ok := owners[e.x]; ok && owner == pid {
				if err := emit(e, "in", e.x, e.y); err != nil {
					return nil, err
				}
			}
			running[e.cpu], known[e.cpu] = e.x, true
		case 50:
			if int(e.cpu) >= len(running) {
				return nil, fmt.Errorf("ETL: CPU index exceeds header count")
			}
			if owner, ok := owners[e.x]; ok && owner == pid {
				if err := emit(e, "ready", e.x, running[e.cpu]); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}
