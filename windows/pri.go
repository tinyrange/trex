package windows

import (
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/pri"
	"go.starlark.net/starlark"
)

// priSectionsBuiltin exposes native envelope parsing without host paths or
// extracted intermediate files. Section payloads remain opaque file values.
func priSectionsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maxBytes := int64(256 << 20)
	if err := starlark.UnpackArgs("pri_sections", args, kwargs, "file", &value, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pri_sections: expected file, got %s", value.Type())
	}
	if maxBytes < 0 || file.Size() < 0 || file.Size() > maxBytes {
		return nil, fmt.Errorf("pri_sections: input exceeds max_bytes")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	container, err := pri.ParseContainer(data)
	if err != nil {
		return nil, err
	}
	sections := make([]starlark.Value, len(container.Sections))
	for i, section := range container.Sections {
		d := starlark.NewDict(4)
		_ = d.SetKey(starlark.String("type"), starlark.String(strings.TrimRight(string(section.Type[:]), "\x00")))
		_ = d.SetKey(starlark.String("metadata"), &starfile.Bytes{Data: section.Metadata[:]})
		_ = d.SetKey(starlark.String("data"), &starfile.Bytes{Data: section.Data})
		_ = d.SetKey(starlark.String("index"), starlark.MakeInt(i))
		sections[i] = d
	}
	return starlark.NewList(sections), nil
}

// priResourceCandidatesBuiltin returns structural candidate counts for selected
// schema indexes. It does not choose candidates or decode their values.
func priResourceCandidatesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var indices *starlark.List
	var sectionIndex int
	maxBytes := int64(256 << 20)
	if err := starlark.UnpackArgs("pri_resource_candidates", args, kwargs, "file", &value, "section_index", &sectionIndex,
		"resource_indices", &indices, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok || maxBytes < 0 || file.Size() < 0 || file.Size() > maxBytes {
		return nil, fmt.Errorf("pri_resource_candidates: invalid or oversized input")
	}
	if indices.Len() > 65536 {
		return nil, fmt.Errorf("pri_resource_candidates: too many requested resources")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	c, err := pri.ParseContainer(data)
	if err != nil {
		return nil, err
	}
	if sectionIndex < 0 || sectionIndex >= len(c.Sections) {
		return nil, fmt.Errorf("pri_resource_candidates: map section out of range")
	}
	m, err := pri.ParseResourceMap(c.Sections[sectionIndex])
	if err != nil {
		return nil, err
	}
	if int(m.DecisionSection) >= len(c.Sections) || int(m.SchemaSection) >= len(c.Sections) {
		return nil, fmt.Errorf("pri_resource_candidates: referenced section out of range")
	}
	d, err := pri.ParseDecisions(c.Sections[m.DecisionSection])
	if err != nil {
		return nil, err
	}
	schema, err := pri.ParseSchema(c.Sections[m.SchemaSection])
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, indices.Len())
	for i := range result {
		var index uint32
		if err := starlark.AsInt(indices.Index(i), &index); err != nil {
			return nil, err
		}
		if _, err := schema.Names.ItemName(index); err != nil {
			return nil, err
		}
		count, err := m.CandidateCount(index, d)
		if err != nil {
			return nil, err
		}
		result[i] = starlark.MakeInt(count)
	}
	return starlark.NewList(result), nil
}

func priSchemaBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	index := 0
	maxBytes := int64(256 << 20)
	if err := starlark.UnpackArgs("pri_schema", args, kwargs, "file", &value, "section_index", &index, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pri_schema: expected file")
	}
	if maxBytes < 0 || file.Size() < 0 || file.Size() > maxBytes {
		return nil, fmt.Errorf("pri_schema: input exceeds max_bytes")
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	c, err := pri.ParseContainer(data)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(c.Sections) {
		return nil, fmt.Errorf("pri_schema: section index out of range")
	}
	s, err := pri.ParseSchema(c.Sections[index])
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(4)
	_ = result.SetKey(starlark.String("identifiers"), starlark.Tuple{starlark.String(s.Identifiers[0]), starlark.String(s.Identifiers[1])})
	_ = result.SetKey(starlark.String("item_count"), starlark.MakeInt(s.Names.ItemCount()))
	_ = result.SetKey(starlark.String("item_name"), starlark.NewBuiltin("pri_schema.item_name", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var item uint32
		if err := starlark.UnpackArgs("item_name", args, kwargs, "index", &item); err != nil {
			return nil, err
		}
		name, err := s.Names.ItemName(item)
		if err != nil {
			return nil, err
		}
		return starlark.String(name), nil
	}))
	return result, nil
}
