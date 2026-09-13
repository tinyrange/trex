package windows

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

// containerIndexBuiltin is a compact inspection boundary for cumulative-update
// planning. It deliberately returns only explicitly requested records so a
// large CIX does not become an equally large Starlark object graph.
func containerIndexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	namesValue := starlark.Value(starlark.None)
	sourceType := ""
	targetHash := ""
	limit := 20
	if err := starlark.UnpackArgs("container_index", args, kwargs, "value", &value, "names?", &namesValue, "source_type?", &sourceType, "limit?", &limit, "target_hash?", &targetHash); err != nil {
		return nil, err
	}
	if limit < 0 || limit > 1000 {
		return nil, fmt.Errorf("container_index: limit must be between 0 and 1000")
	}
	sourceType = strings.ToUpper(strings.TrimSpace(sourceType))
	var wantedHash []byte
	if targetHash != "" {
		var err error
		wantedHash, err = hex.DecodeString(targetHash)
		if err != nil || len(wantedHash) != 32 {
			return nil, fmt.Errorf("container_index: target_hash must be a 64-digit SHA-256 hex string")
		}
	}
	reader, err := containerIndexReader(value)
	if err != nil {
		return nil, fmt.Errorf("container_index: %w", err)
	}
	index, err := uup.ParseContainerIndex(reader)
	if err != nil {
		return nil, fmt.Errorf("container_index: %w", err)
	}
	wanted := make(map[string]struct{})
	if namesValue != starlark.None {
		iterable, ok := namesValue.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("container_index: names got %s, want iterable", namesValue.Type())
		}
		iterator := iterable.Iterate()
		defer iterator.Done()
		var item starlark.Value
		for iterator.Next(&item) {
			name, ok := starlark.AsString(item)
			if !ok {
				return nil, fmt.Errorf("container_index: names item got %s, want string", item.Type())
			}
			wanted[strings.ToLower(strings.ReplaceAll(name, "/", "\\"))] = struct{}{}
		}
	}
	files := make([]starlark.Value, 0, min(limit, len(wanted)))
	sourceTypes := make(map[string]int)
	basisFiles := 0
	multipleSourceFiles := 0
	multipleBasisFiles := 0
	for _, file := range index.Files {
		if len(file.Bases) != 0 {
			basisFiles++
		}
		if len(file.Sources) > 1 {
			multipleSourceFiles++
		}
		if len(file.Bases) > 1 {
			multipleBasisFiles++
		}
		for _, source := range file.Sources {
			sourceTypes[source.Type]++
		}
		key := strings.ToLower(strings.ReplaceAll(file.Name, "/", "\\"))
		_, named := wanted[key]
		typed := false
		if sourceType != "" {
			for _, source := range file.Sources {
				typed = typed || source.Type == sourceType
			}
		}
		selected := named || typed || (wantedHash != nil && len(wanted) == 0 && sourceType == "")
		if !selected || len(files) >= limit || (wantedHash != nil && !bytes.Equal(wantedHash, file.Hash[:])) {
			continue
		}
		files = append(files, cixFileValue(file))
	}
	sourceTypeValues := starlark.NewDict(len(sourceTypes))
	for name, count := range sourceTypes {
		if err := sourceTypeValues.SetKey(starlark.String(name), starlark.MakeInt(count)); err != nil {
			return nil, err
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"basis_file_count":           starlark.MakeInt(basisFiles),
		"file_count":                 starlark.MakeInt(len(index.Files)),
		"files":                      starlark.NewList(files),
		"length":                     starlark.MakeInt64(index.Length),
		"location_count":             starlark.MakeInt(len(index.Locations)),
		"multiple_basis_file_count":  starlark.MakeInt(multipleBasisFiles),
		"multiple_source_file_count": starlark.MakeInt(multipleSourceFiles),
		"name":                       starlark.String(index.Name),
		"source_types":               sourceTypeValues,
		"type":                       starlark.String(index.Type),
		"version":                    starlark.MakeInt(index.Version),
	}), nil
}

func containerIndexReader(value starlark.Value) (io.Reader, error) {
	if file, ok := value.(starfile.File); ok {
		if file.Size() < 0 {
			return nil, fmt.Errorf("negative input size")
		}
		return io.NewSectionReader(file, 0, file.Size()), nil
	}
	switch value := value.(type) {
	case starlark.Bytes:
		return bytes.NewReader([]byte(value)), nil
	case starlark.String:
		return strings.NewReader(string(value)), nil
	default:
		return nil, fmt.Errorf("got %s, want file, bytes, or string", value.Type())
	}
}

func cixFileValue(file uup.CIXFile) starlark.Value {
	sources := make([]starlark.Value, len(file.Sources))
	for index, source := range file.Sources {
		sources[index] = starfile.NewRecord(starlark.StringDict{
			"hash":   starlark.String(fmt.Sprintf("%x", source.Hash)),
			"length": starlark.MakeInt64(source.Length),
			"name":   starlark.String(source.Name),
			"offset": starlark.MakeInt64(source.Offset),
			"type":   starlark.String(source.Type),
		})
	}
	bases := make([]starlark.Value, len(file.Bases))
	for index, basis := range file.Bases {
		bases[index] = starfile.NewRecord(starlark.StringDict{
			"hash":   starlark.String(fmt.Sprintf("%x", basis.Hash)),
			"length": starlark.MakeInt64(basis.Length),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"attributes": starlark.MakeUint64(file.Attributes),
		"bases":      starlark.NewList(bases),
		"hash":       starlark.String(fmt.Sprintf("%x", file.Hash)),
		"id":         starlark.MakeInt64(file.ID),
		"length":     starlark.MakeInt64(file.Length),
		"name":       starlark.String(file.Name),
		"sources":    starlark.NewList(sources),
		"time":       starlark.MakeUint64(file.Time),
	})
}

func servicingGraphBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var psfValue, historyValue, payloadValue starlark.Value
	targetsValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("servicing_graph", args, kwargs, "psf_index", &psfValue, "history_index", &historyValue, "psf_payload", &payloadValue, "targets?", &targetsValue); err != nil {
		return nil, err
	}
	psfReader, err := containerIndexReader(psfValue)
	if err != nil {
		return nil, fmt.Errorf("servicing_graph: PSF index: %w", err)
	}
	historyReader, err := containerIndexReader(historyValue)
	if err != nil {
		return nil, fmt.Errorf("servicing_graph: history index: %w", err)
	}
	psf, err := uup.ParseContainerIndex(psfReader)
	if err != nil {
		return nil, fmt.Errorf("servicing_graph: PSF index: %w", err)
	}
	history, err := uup.ParseContainerIndex(historyReader)
	if err != nil {
		return nil, fmt.Errorf("servicing_graph: history index: %w", err)
	}
	payload, ok := payloadValue.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("servicing_graph: psf_payload got %s, want file", payloadValue.Type())
	}
	graph, err := uup.BuildCumulativeGraphWithRecords(psf, history, payload, deltaInfoLimit)
	if err != nil {
		return nil, fmt.Errorf("servicing_graph: %w", err)
	}
	wanted := make(map[string]struct{})
	if targetsValue != starlark.None {
		iterable, ok := targetsValue.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("servicing_graph: targets got %s, want iterable", targetsValue.Type())
		}
		iterator := iterable.Iterate()
		defer iterator.Done()
		var item starlark.Value
		for iterator.Next(&item) {
			name, ok := starlark.AsString(item)
			if !ok {
				return nil, fmt.Errorf("servicing_graph: targets item got %s, want string", item.Type())
			}
			wanted[strings.ToLower(strings.ReplaceAll(name, "/", "\\"))] = struct{}{}
		}
	}
	withBasis := 0
	selected := make([]starlark.Value, 0, len(wanted))
	for _, payload := range graph.Payloads {
		if payload.Basis != nil {
			withBasis++
		}
		key := strings.ToLower(strings.ReplaceAll(payload.Target.Name, "/", "\\"))
		if _, ok := wanted[key]; ok {
			basis := starlark.Value(starlark.None)
			if payload.Basis != nil {
				basis = starfile.NewRecord(starlark.StringDict{
					"hash":   starlark.String(fmt.Sprintf("%x", payload.Basis.SHA256)),
					"length": starlark.MakeInt64(payload.Basis.Length),
				})
			}
			selected = append(selected, starfile.NewRecord(starlark.StringDict{
				"basis":         basis,
				"record_hash":   starlark.String(fmt.Sprintf("%x", payload.Record.SHA256)),
				"record_length": starlark.MakeInt64(payload.Record.Length),
				"record_name":   starlark.String(payload.Record.Name),
				"record_offset": starlark.MakeInt64(payload.RecordOffset),
				"target_hash":   starlark.String(fmt.Sprintf("%x", payload.Target.SHA256)),
				"target_length": starlark.MakeInt64(payload.Target.Length),
				"target_name":   starlark.String(payload.Target.Name),
			}))
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"container_length":    starlark.MakeInt64(graph.ContainerLength),
		"payload_count":       starlark.MakeInt(len(graph.Payloads)),
		"payloads":            starlark.NewList(selected),
		"source_count":        starlark.MakeInt(len(graph.Sources)),
		"with_basis_count":    starlark.MakeInt(withBasis),
		"without_basis_count": starlark.MakeInt(len(graph.Payloads) - withBasis),
	}), nil
}
