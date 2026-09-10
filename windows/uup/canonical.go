package uup

import (
	"fmt"
	"sort"
)

// BuildCanonicalGraph validates the logical-file graph embedded in a
// canonical update cabinet. Each target is backed by one named cabinet member:
// either its bytes directly (RAW) or an MSDelta record (PA30). A PA30 basis may
// name another logical file by CIX file ID, producing an explicit DAG.
func BuildCanonicalGraph(index *ContainerIndex, memberSizes map[string]int64) (*CumulativeGraph, error) {
	if index == nil || index.Type != "CAB" || index.Length < 0 {
		return nil, fmt.Errorf("uup servicing: valid CAB index is required")
	}
	byID := make(map[int64]CIXFile, len(index.Files))
	byName := make(map[string]struct{}, len(index.Files))
	for _, file := range index.Files {
		name := normalizeCIXName(file.Name)
		if _, exists := byName[name]; exists {
			return nil, fmt.Errorf("uup servicing: duplicate canonical target name %q", file.Name)
		}
		byName[name] = struct{}{}
		byID[file.ID] = file
	}
	graph := &CumulativeGraph{ContainerLength: index.Length}
	for _, file := range index.Files {
		if len(file.Sources) != 1 || len(file.Bases) > 1 {
			return nil, fmt.Errorf("uup servicing: canonical target %q has %d sources and %d bases", file.Name, len(file.Sources), len(file.Bases))
		}
		source := file.Sources[0]
		if source.Name == "" || source.Offset >= 0 || source.Length >= 0 {
			return nil, fmt.Errorf("uup servicing: canonical target %q has invalid named source", file.Name)
		}
		size, found := memberSizes[normalizeCIXName(source.Name)]
		if !found || size < 0 {
			return nil, fmt.Errorf("uup servicing: canonical target %q references missing cabinet member %q", file.Name, source.Name)
		}
		if source.Type != "RAW" && source.Type != "PA30" {
			return nil, fmt.Errorf("uup servicing: canonical target %q uses unsupported source type %q", file.Name, source.Type)
		}
		if source.Type == "RAW" {
			if len(file.Bases) != 0 || source.Hash != file.Hash || size != file.Length {
				return nil, fmt.Errorf("uup servicing: canonical RAW target %q has inconsistent source metadata", file.Name)
			}
		}
		payload := DeltaPayload{
			Target:       ContentDescriptor{Name: file.Name, Length: file.Length, SHA256: file.Hash},
			Record:       ContentDescriptor{Name: source.Name, Length: size, SHA256: source.Hash},
			RecordOffset: -1,
			RecordType:   source.Type,
		}
		if len(file.Bases) == 1 {
			basis := file.Bases[0]
			if basis.FileID < 0 || basis.Length >= 0 || basis.Hash != ([32]byte{}) {
				return nil, fmt.Errorf("uup servicing: canonical target %q uses an external-style basis", file.Name)
			}
			basisFile, found := byID[basis.FileID]
			if !found || basisFile.ID == file.ID {
				return nil, fmt.Errorf("uup servicing: canonical target %q references invalid basis file id %d", file.Name, basis.FileID)
			}
			payload.Basis = &ContentDescriptor{Name: basisFile.Name, Length: basisFile.Length, SHA256: basisFile.Hash}
		}
		graph.Payloads = append(graph.Payloads, payload)
	}
	// Validate the file-ID basis relation as a DAG before any reconstruction.
	state := make(map[int64]uint8, len(index.Files))
	var visit func(int64) error
	visit = func(id int64) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("uup servicing: canonical basis graph contains a cycle at file id %d", id)
		case 2:
			return nil
		}
		state[id] = 1
		file := byID[id]
		if len(file.Bases) == 1 {
			if err := visit(file.Bases[0].FileID); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for id := range byID {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	sort.Slice(graph.Payloads, func(i, j int) bool {
		return normalizeCIXName(graph.Payloads[i].Target.Name) < normalizeCIXName(graph.Payloads[j].Target.Name)
	})
	return graph, nil
}
