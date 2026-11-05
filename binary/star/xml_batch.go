package star

import (
	"fmt"
	"sync"

	"go.starlark.net/starlark"
)

// Input conversion stays on the caller thread, including any file protocol.
// Workers see only byte snapshots, and publish documents after every worker joins.
func binaryXMLManyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	workers, maximum := 4, defaultBinaryXMLLimit
	maxDepth, maxNodes := defaultBinaryXMLDepth, defaultBinaryXMLNodes
	totalMaximum := 256 << 20
	discardWhitespace := false
	if err := starlark.UnpackArgs("xml_many", args, kwargs, "values", &values,
		"workers?", &workers, "maximum?", &maximum, "max_depth?", &maxDepth,
		"max_nodes?", &maxNodes, "discard_whitespace?", &discardWhitespace,
		"total_maximum?", &totalMaximum); err != nil {
		return nil, err
	}
	if values.Len() > 4096 || workers < 1 || workers > 8 || maximum < 0 || maxDepth < 1 || maxNodes < 1 || totalMaximum < 0 || totalMaximum > 256<<20 {
		return nil, fmt.Errorf("xml_many: requires at most 4096 inputs, 1..8 workers, valid XML limits, and total_maximum in 0..256 MiB")
	}
	inputs := make([][]byte, values.Len())
	remaining := totalMaximum
	for i := range inputs {
		data, err := bytesForBinaryValueLimited(values.Index(i), int64(min(maximum, remaining)))
		if err != nil {
			return nil, fmt.Errorf("xml_many: input %d: %w", i, err)
		}
		// Some file values expose their backing slice: do not share that storage
		// with parsing workers, even though parsing itself does not modify it.
		inputs[i] = append([]byte(nil), data...)
		remaining -= len(data)
	}
	documents := make([]*binaryXMLDocument, len(inputs))
	errors := make([]error, len(inputs))
	workers = min(workers, len(inputs))
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(start int) {
			defer group.Done()
			for i := start; i < len(inputs); i += workers {
				documents[i], errors[i] = parseBinaryXML(inputs[i], maxDepth, maxNodes, discardWhitespace)
			}
		}(worker)
	}
	group.Wait()
	result := make([]starlark.Value, len(inputs))
	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("xml_many: input %d: %w", i, err)
		}
		result[i] = documents[i]
	}
	return starlark.NewList(result), nil
}
