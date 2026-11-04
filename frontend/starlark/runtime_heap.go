package starlarkfrontend

import (
	"fmt"
	"math"
	"runtime"
	"sort"

	"go.starlark.net/starlark"
)

// runtimeHeapProfileBuiltin observes the existing allocation sampler. It neither
// forces a collection nor changes the process-wide sampling rate.
func runtimeHeapProfileBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	limit := 20
	orderBy := "sampled_bytes"
	if err := starlark.UnpackArgs("runtime.heap_profile", args, kwargs, "limit?", &limit, "order_by?", &orderBy); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("runtime.heap_profile: limit must be between 1 and 100")
	}
	if orderBy != "sampled_bytes" && orderBy != "estimated_bytes" {
		return nil, fmt.Errorf("runtime.heap_profile: order_by must be sampled_bytes or estimated_bytes")
	}
	if _, err := resourcesForThread(thread); err != nil {
		return nil, err
	}
	n, _ := runtime.MemProfile(nil, false)
	var samples []runtime.MemProfileRecord
	ok := false
	// Concurrent allocations may add a stack between sizing and reading. Bound
	// retries and scratch memory rather than spinning on a changing profile.
	for attempt := 0; attempt < 3; attempt++ {
		if n > 1<<20 {
			return nil, fmt.Errorf("runtime.heap_profile: allocation stack count exceeds limit")
		}
		samples = make([]runtime.MemProfileRecord, n+64)
		n, ok = runtime.MemProfile(samples, false)
		if ok {
			samples = samples[:n]
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("runtime.heap_profile: allocation profile changed during bounded read")
	}
	rate := runtime.MemProfileRate
	weights := make(map[runtime.MemProfileRecord][2]float64, len(samples))
	var estimatedBytes, estimatedObjects float64
	for _, sample := range samples {
		objects, bytes := estimateHeapSample(sample.InUseObjects(), sample.InUseBytes(), rate)
		weights[sample] = [2]float64{objects, bytes}
		estimatedObjects += objects
		estimatedBytes += bytes
	}
	sort.SliceStable(samples, func(i, j int) bool {
		if orderBy == "estimated_bytes" {
			return weights[samples[i]][1] > weights[samples[j]][1]
		}
		return samples[i].InUseBytes() > samples[j].InUseBytes()
	})
	var totalBytes, totalObjects int64
	for _, sample := range samples {
		totalBytes += sample.InUseBytes()
		totalObjects += sample.InUseObjects()
	}
	count := len(samples)
	if count > limit {
		count = limit
	}
	entries := make([]starlark.Value, count)
	for i, sample := range samples[:count] {
		frames := runtime.CallersFrames(sample.Stack())
		stack := make([]starlark.Value, 0, 32)
		for {
			frame, more := frames.Next()
			stack = append(stack, newStarlarkRecord(starlark.StringDict{
				"function": starlark.String(frame.Function),
				"line":     starlark.MakeInt(frame.Line),
			}))
			if !more {
				break
			}
		}
		entries[i] = newStarlarkRecord(starlark.StringDict{
			"sampled_bytes":     starlark.MakeInt64(sample.InUseBytes()),
			"estimated_bytes":   starlark.Float(weights[sample][1]),
			"estimated_objects": starlark.Float(weights[sample][0]),
			"sampled_objects":   starlark.MakeInt64(sample.InUseObjects()),
			"stack":             starlark.NewList(stack),
		})
	}
	return newStarlarkRecord(starlark.StringDict{
		"sample_rate_bytes": starlark.MakeInt(rate),
		"order_by":          starlark.String(orderBy),
		"estimated_bytes":   starlark.Float(estimatedBytes),
		"estimated_objects": starlark.Float(estimatedObjects),
		"sampled_bytes":     starlark.MakeInt64(totalBytes),
		"sampled_objects":   starlark.MakeInt64(totalObjects),
		"stack_count":       starlark.MakeInt(len(samples)),
		"entries":           starlark.NewList(entries),
	}), nil
}

// Go samples allocations with probability 1-exp(-size/rate). Raw sampled
// bytes heavily favor large buffers and hide pointer-rich small allocations.
// Match pprof's per-stack inverse-probability estimate using mean object size.
// These remain statistical estimates, not exact live ownership measurements.
func estimateHeapSample(objects, bytes int64, rate int) (float64, float64) {
	if objects <= 0 || bytes <= 0 {
		return 0, 0
	}
	if rate <= 1 {
		return float64(objects), float64(bytes)
	}
	probability := -math.Expm1(-float64(bytes) / float64(objects) / float64(rate))
	return float64(objects) / probability, float64(bytes) / probability
}
