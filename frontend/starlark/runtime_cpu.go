package starlarkfrontend

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"runtime/pprof"
	"sort"
	"sync"
	"time"

	"go.starlark.net/starlark"
)

// The process has one Go CPU profiler. A script session owns it between
// cpu_profile_start and cpu_profile_stop; -cpuprofile owns it otherwise.
var runtimeCPUProfile struct {
	sync.Mutex
	buffer  *bytes.Buffer
	started time.Time
}

func runtimeCPUProfileStartBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("runtime.cpu_profile_start", args, kwargs); err != nil {
		return nil, err
	}
	if _, err := resourcesForThread(thread); err != nil {
		return nil, err
	}
	p := &runtimeCPUProfile
	p.Lock()
	defer p.Unlock()
	if p.buffer != nil {
		return nil, fmt.Errorf("runtime.cpu_profile_start: a capture is already running")
	}
	buffer := new(bytes.Buffer)
	if err := pprof.StartCPUProfile(buffer); err != nil {
		return nil, fmt.Errorf("runtime.cpu_profile_start: %w", err)
	}
	p.buffer, p.started = buffer, time.Now()
	return starlark.None, nil
}

// runtimeCPUProfileStopBuiltin ends the capture and summarizes host CPU time
// by Go function. data holds the complete pprof encoding for offline tools.
func runtimeCPUProfileStopBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	limit := 30
	if err := starlark.UnpackArgs("runtime.cpu_profile_stop", args, kwargs, "limit?", &limit); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		return nil, fmt.Errorf("runtime.cpu_profile_stop: limit must be between 1 and 200")
	}
	if _, err := resourcesForThread(thread); err != nil {
		return nil, err
	}
	p := &runtimeCPUProfile
	p.Lock()
	buffer, started := p.buffer, p.started
	if buffer == nil {
		p.Unlock()
		return nil, fmt.Errorf("runtime.cpu_profile_stop: no capture is running")
	}
	pprof.StopCPUProfile()
	p.buffer = nil
	p.Unlock()
	data := buffer.Bytes()
	summary, err := summarizeCPUProfile(data)
	if err != nil {
		return nil, fmt.Errorf("runtime.cpu_profile_stop: %w", err)
	}
	if len(summary.functions) > limit {
		summary.functions = summary.functions[:limit]
	}
	entries := make([]starlark.Value, len(summary.functions))
	for i, f := range summary.functions {
		entries[i] = newStarlarkRecord(starlark.StringDict{
			"function": starlark.String(f.name),
			"flat":     starlark.Float(float64(f.flat) / 1e9),
			"cum":      starlark.Float(float64(f.cum) / 1e9),
		})
	}
	return newStarlarkRecord(starlark.StringDict{
		"seconds":     starlark.Float(time.Since(started).Seconds()),
		"cpu_seconds": starlark.Float(float64(summary.total) / 1e9),
		"samples":     starlark.MakeInt64(summary.samples),
		"functions":   starlark.NewList(entries),
		"data":        starlark.Bytes(data),
	}), nil
}

type cpuProfileFunction struct {
	name      string
	flat, cum int64
}

type cpuProfileSummary struct {
	total, samples int64
	functions      []cpuProfileFunction // by flat time, then cumulative
}

// summarizeCPUProfile decodes the gzip-compressed profile.proto written by
// runtime/pprof. Flat time belongs to a sample's leaf (innermost inlined)
// function; cumulative time to every distinct function on its stack.
func summarizeCPUProfile(data []byte) (cpuProfileSummary, error) {
	var s cpuProfileSummary
	if len(data) == 0 {
		return s, nil
	}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return s, err
	}
	raw, err := io.ReadAll(io.LimitReader(z, 1<<30))
	if err != nil {
		return s, err
	}
	type sample struct {
		locations []uint64
		values    []int64
	}
	var (
		strs      []string
		types     []uint64 // sample_type string indexes
		samples   []sample
		locations = map[uint64][]uint64{} // id -> function ids, leaf first
		functions = map[uint64]uint64{}   // id -> name string index
	)
	err = protoFields(raw, func(field int, wire int, v uint64, b []byte) error {
		switch field {
		case 1: // sample_type
			return protoFields(b, func(f, _ int, v uint64, _ []byte) error {
				if f == 1 {
					types = append(types, v)
				}
				return nil
			})
		case 2:
			var sm sample
			err := protoFields(b, func(f, w int, v uint64, b []byte) error {
				switch f {
				case 1:
					return protoVarints(w, v, b, func(x uint64) { sm.locations = append(sm.locations, x) })
				case 2:
					return protoVarints(w, v, b, func(x uint64) { sm.values = append(sm.values, int64(x)) })
				}
				return nil
			})
			samples = append(samples, sm)
			return err
		case 4:
			var id uint64
			var fns []uint64
			err := protoFields(b, func(f, _ int, v uint64, b []byte) error {
				switch f {
				case 1:
					id = v
				case 4:
					return protoFields(b, func(f, _ int, v uint64, _ []byte) error {
						if f == 1 {
							fns = append(fns, v)
						}
						return nil
					})
				}
				return nil
			})
			locations[id] = fns
			return err
		case 5:
			var id, name uint64
			err := protoFields(b, func(f, _ int, v uint64, _ []byte) error {
				switch f {
				case 1:
					id = v
				case 2:
					name = v
				}
				return nil
			})
			functions[id] = name
			return err
		case 6:
			strs = append(strs, string(b))
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	column := -1
	for i, t := range types {
		if t < uint64(len(strs)) && strs[t] == "cpu" {
			column = i
		}
	}
	if column < 0 {
		return s, fmt.Errorf("profile has no cpu sample type")
	}
	name := func(fn uint64) string {
		if n, ok := functions[fn]; ok && n < uint64(len(strs)) {
			return strs[n]
		}
		return fmt.Sprintf("function#%d", fn)
	}
	byName := map[string]*cpuProfileFunction{}
	get := func(n string) *cpuProfileFunction {
		f := byName[n]
		if f == nil {
			f = &cpuProfileFunction{name: n}
			byName[n] = f
		}
		return f
	}
	for _, sm := range samples {
		if column >= len(sm.values) {
			continue
		}
		value := sm.values[column]
		s.total += value
		s.samples++
		seen := map[string]bool{}
		for i, loc := range sm.locations {
			fns := locations[loc]
			if len(fns) == 0 {
				// Code without Go symbols, such as generated native code.
				if i == 0 {
					get("(unsymbolized)").flat += value
				}
				if !seen["(unsymbolized)"] {
					seen["(unsymbolized)"] = true
					get("(unsymbolized)").cum += value
				}
				continue
			}
			for j, fn := range fns {
				n := name(fn)
				if i == 0 && j == 0 {
					get(n).flat += value
				}
				if !seen[n] {
					seen[n] = true
					get(n).cum += value
				}
			}
		}
	}
	for _, f := range byName {
		s.functions = append(s.functions, *f)
	}
	sort.Slice(s.functions, func(i, j int) bool {
		a, b := s.functions[i], s.functions[j]
		if a.flat != b.flat {
			return a.flat > b.flat
		}
		if a.cum != b.cum {
			return a.cum > b.cum
		}
		return a.name < b.name
	})
	return s, nil
}

// protoFields calls fn for each field of a protobuf message: v holds varint
// and fixed values, b holds length-delimited payloads.
func protoFields(data []byte, fn func(field, wire int, v uint64, b []byte) error) error {
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return fmt.Errorf("truncated protobuf key")
		}
		data = data[n:]
		field, wire := int(key>>3), int(key&7)
		var v uint64
		var b []byte
		switch wire {
		case 0:
			v, n = binary.Uvarint(data)
			if n <= 0 {
				return fmt.Errorf("truncated protobuf varint")
			}
			data = data[n:]
		case 1:
			if len(data) < 8 {
				return fmt.Errorf("truncated protobuf fixed64")
			}
			v, data = binary.LittleEndian.Uint64(data), data[8:]
		case 2:
			size, n := binary.Uvarint(data)
			if n <= 0 || size > uint64(len(data)-n) {
				return fmt.Errorf("truncated protobuf bytes")
			}
			b, data = data[n:n+int(size)], data[n+int(size):]
		case 5:
			if len(data) < 4 {
				return fmt.Errorf("truncated protobuf fixed32")
			}
			v, data = uint64(binary.LittleEndian.Uint32(data)), data[4:]
		default:
			return fmt.Errorf("unsupported protobuf wire type %d", wire)
		}
		if err := fn(field, wire, v, b); err != nil {
			return err
		}
	}
	return nil
}

// protoVarints accepts a repeated varint field in packed or unpacked form.
func protoVarints(wire int, v uint64, b []byte, add func(uint64)) error {
	if wire == 0 {
		add(v)
		return nil
	}
	if wire != 2 {
		return fmt.Errorf("unexpected wire type %d for repeated varint", wire)
	}
	for len(b) > 0 {
		x, n := binary.Uvarint(b)
		if n <= 0 {
			return fmt.Errorf("truncated packed varint")
		}
		add(x)
		b = b[n:]
	}
	return nil
}
