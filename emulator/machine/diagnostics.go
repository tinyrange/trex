package machine

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"

	"go.starlark.net/starlark"
)

type diagnostics struct {
	traceEnabled, profileEnabled bool
	traceLimit, profileLimit     int
	profileInterval              uint64
	traceAddresses               []uint64
	traceCursor                  int
	profileCounts                map[uint64]uint64
	operations, samples, dropped uint64
	profileCalls                 bool
	callCounts                   map[uint64]callSample
	callDropped                  uint64
}

// Callback times are inclusive of nested native invocations. They measure the
// original dispatch, not import thunks, and never replace a semantic callback.
type callSample struct {
	module, name       string
	count              uint64
	elapsed, maximum   time.Duration
	caller             uint64
	arguments          []uint64
	argumentsTruncated bool
}

func (m *Machine) observeCall(address uint64, binding hook, caller uint64, arguments []uint64, elapsed time.Duration) {
	sample, exists := m.callCounts[address]
	if !exists && len(m.callCounts) >= m.profileLimit {
		m.callDropped++
		return
	}
	if m.callCounts == nil {
		m.callCounts = make(map[uint64]callSample)
	}
	sample.module, sample.name = binding.module, binding.name
	sample.count++
	sample.elapsed += elapsed
	if !exists || elapsed > sample.maximum {
		sample.maximum, sample.caller = elapsed, caller
		sample.arguments = slices.Clone(arguments[:min(16, len(arguments))])
		sample.argumentsTruncated = len(arguments) > 16
	}
	m.callCounts[address] = sample
}

func (m *Machine) observe(pc uint64) {
	if m.traceEnabled {
		if len(m.traceAddresses) < m.traceLimit {
			m.traceAddresses = append(m.traceAddresses, pc)
		} else {
			m.traceAddresses[m.traceCursor] = pc
			m.traceCursor = (m.traceCursor + 1) % m.traceLimit
		}
	}
	if m.profileEnabled {
		if m.operations%m.profileInterval == 0 {
			m.samples++
			if _, exists := m.profileCounts[pc]; exists || len(m.profileCounts) < m.profileLimit {
				m.profileCounts[pc]++
			} else {
				m.dropped++
			}
		}
		m.operations++
	}
}

func (m *Machine) traceValue() starlark.Value {
	values := make([]starlark.Value, len(m.traceAddresses))
	for i := range values {
		pc := m.traceAddresses[(m.traceCursor+i)%len(values)]
		values[i] = record(starlark.StringDict{"pc": starlark.MakeUint64(pc), "eip": starlark.MakeUint64(pc)})
	}
	return starlark.NewList(values)
}

// clone copies execution and memory state. As with the legacy x86 snapshot,
// semantic callbacks retain their bindings; mutable plugin state is not forked.
func (m *Machine) clone() *Machine {
	clone := *m
	clone.attrCache = nil // methods must bind the clone, not the original machine
	clone.hookDepth = 0
	clone.pendingStop, clone.pendingStopDetail = "", ""
	clone.processor = m.processor.Clone()
	clone.memory = m.memory.Clone()
	clone.modules = slices.Clone(m.modules)
	clone.imports = maps.Clone(m.imports)
	clone.importIATs = make(map[string][]uint64, len(m.importIATs))
	for key, slots := range m.importIATs {
		clone.importIATs[key] = slices.Clone(slots)
	}
	clone.hooks = maps.Clone(m.hooks)
	clone.provided = maps.Clone(m.provided)
	clone.allocations = maps.Clone(m.allocations)
	clone.allocationNames = maps.Clone(m.allocationNames)
	clone.pluginStates = slices.Clone(m.pluginStates)
	clone.traceAddresses = slices.Clone(m.traceAddresses)
	clone.profileCounts = maps.Clone(m.profileCounts)
	clone.callCounts = maps.Clone(m.callCounts)
	return &clone
}

func (m *Machine) diagnosticMethod(name string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if name == "snapshot" {
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		return m.clone(), nil
	}
	limit, reset := 256, false
	calls := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs(name, args, kwargs, "limit?", &limit, "reset?", &reset, "calls?", &calls); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 65536 {
		return nil, fmt.Errorf("profile: limit must be between 1 and 65536")
	}
	if calls != starlark.None {
		enabled, ok := calls.(starlark.Bool)
		if !ok {
			return nil, fmt.Errorf("profile: calls must be bool or None")
		}
		m.profileCalls = bool(enabled)
	}
	addresses := make([]uint64, 0, len(m.profileCounts))
	for pc := range m.profileCounts {
		addresses = append(addresses, pc)
	}
	sort.Slice(addresses, func(i, j int) bool {
		if m.profileCounts[addresses[i]] != m.profileCounts[addresses[j]] {
			return m.profileCounts[addresses[i]] > m.profileCounts[addresses[j]]
		}
		return addresses[i] < addresses[j]
	})
	var entries []starlark.Value
	for _, pc := range addresses[:min(limit, len(addresses))] {
		name, offset := "", uint64(0)
		for _, module := range m.modules {
			if pc >= module.image.Base && pc-module.image.Base < uint64(len(module.image.Data)) {
				name, offset = module.name, pc-module.image.Base
				break
			}
		}
		entries = append(entries, record(starlark.StringDict{"address": starlark.MakeUint64(pc), "count": starlark.MakeUint64(m.profileCounts[pc]), "mapping": starlark.String(name), "offset": starlark.MakeUint64(offset)}))
	}
	callAddresses := make([]uint64, 0, len(m.callCounts))
	for address := range m.callCounts {
		callAddresses = append(callAddresses, address)
	}
	sort.Slice(callAddresses, func(i, j int) bool {
		a, b := m.callCounts[callAddresses[i]], m.callCounts[callAddresses[j]]
		if a.elapsed != b.elapsed {
			return a.elapsed > b.elapsed
		}
		return callAddresses[i] < callAddresses[j]
	})
	var callsOutput []starlark.Value
	for _, address := range callAddresses[:min(limit, len(callAddresses))] {
		sample := m.callCounts[address]
		arguments := make([]starlark.Value, len(sample.arguments))
		for i, argument := range sample.arguments {
			arguments[i] = starlark.MakeUint64(argument)
		}
		callsOutput = append(callsOutput, record(starlark.StringDict{
			"address": starlark.MakeUint64(address), "module": starlark.String(sample.module), "name": starlark.String(sample.name),
			"count": starlark.MakeUint64(sample.count), "seconds": starlark.Float(sample.elapsed.Seconds()),
			"max_seconds": starlark.Float(sample.maximum.Seconds()), "caller": starlark.MakeUint64(sample.caller),
			"arguments": starlark.NewList(arguments), "arguments_truncated": starlark.Bool(sample.argumentsTruncated),
		}))
	}
	result := record(starlark.StringDict{"calls_enabled": starlark.Bool(m.profileCalls), "calls": starlark.NewList(callsOutput), "call_tracked": starlark.MakeInt(len(m.callCounts)), "call_dropped": starlark.MakeUint64(m.callDropped), "enabled": starlark.Bool(m.profileEnabled), "operations": starlark.MakeUint64(m.operations), "interval": starlark.MakeUint64(m.profileInterval), "samples": starlark.MakeUint64(m.samples), "dropped": starlark.MakeUint64(m.dropped), "tracked": starlark.MakeInt(len(m.profileCounts)), "entries": starlark.NewList(entries)})
	if reset {
		clear(m.profileCounts)
		clear(m.callCounts)
		m.callDropped = 0
		m.operations, m.samples, m.dropped = 0, 0, 0
	}
	return result, nil
}
