package uup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/msdelta"
)

type ContentDescriptor struct {
	Name   string
	Length int64
	SHA256 [32]byte
	// nameHint distinguishes a planner-inferred predecessor name from an
	// explicit content-graph name. Abbreviated WinSxS names can collide.
	nameHint bool
}

type DeltaPayload struct {
	// Literal means the indexed RAW range is already the final file, rather
	// than a PSFX patch referenced by the history index.
	Literal      bool
	Target       ContentDescriptor
	Record       ContentDescriptor
	RecordOffset int64
	RecordType   string
	RecordTarget *ContentDescriptor
	RecordBasis  *ContentDescriptor
	Basis        *ContentDescriptor
}

// CarryPayload maps a current-stage logical target to byte-identical content
// from a predecessor stage or the base image. PSFX represents this as a named
// RAW source; the target alias must be retained because WinSxS versions differ.
type CarryPayload struct {
	Target ContentDescriptor
	Source ContentDescriptor
}

// CumulativeGraph is the content graph described jointly by a PSF CIX and its
// PSFX history CIX. Sources are exact predecessor files; payloads are exact
// reconstruction edges.
type CumulativeGraph struct {
	ContainerLength int64
	Sources         []ContentDescriptor
	Carries         []CarryPayload
	Payloads        []DeltaPayload
}

// BuildCumulativeGraph validates and joins PSF record locations with history
// target/basis relationships. Ambiguous or unresolved PA30 references are an
// error rather than a partially applicable update.
func BuildCumulativeGraph(psf, history *ContainerIndex) (*CumulativeGraph, error) {
	if psf == nil || psf.Type != "PSF" || psf.Length < 0 {
		return nil, fmt.Errorf("uup servicing: valid PSF index is required")
	}
	if history == nil || history.Type != "PSFX" {
		return nil, fmt.Errorf("uup servicing: valid PSFX history index is required")
	}
	mainByName := make(map[string]CIXFile, len(psf.Files))
	for _, file := range psf.Files {
		key := normalizeCIXName(file.Name)
		if _, exists := mainByName[key]; exists {
			return nil, fmt.Errorf("uup servicing: duplicate PSF record name %q", file.Name)
		}
		mainByName[key] = file
	}
	graph := &CumulativeGraph{ContainerLength: psf.Length}
	seenTargetNames := make(map[string]struct{})
	referencedRecords := make(map[string]struct{})
	for _, file := range history.Files {
		if len(file.Sources) != 1 || len(file.Bases) > 1 {
			return nil, fmt.Errorf("uup servicing: history file %q has %d sources and %d bases", file.Name, len(file.Sources), len(file.Bases))
		}
		source := file.Sources[0]
		switch source.Type {
		case "RAW":
			if len(file.Bases) != 0 || source.Name == "" || source.Offset >= 0 || source.Length >= 0 || source.Hash != file.Hash {
				return nil, fmt.Errorf("uup servicing: malformed RAW history source for %q", file.Name)
			}
			nameKey := normalizeCIXName(file.Name)
			if _, exists := seenTargetNames[nameKey]; exists {
				return nil, fmt.Errorf("uup servicing: duplicate target name %q", file.Name)
			}
			seenTargetNames[nameKey] = struct{}{}
			predecessor := ContentDescriptor{Name: source.Name, Length: file.Length, SHA256: file.Hash}
			graph.Sources = append(graph.Sources, predecessor)
			graph.Carries = append(graph.Carries, CarryPayload{
				Target: ContentDescriptor{Name: file.Name, Length: file.Length, SHA256: file.Hash},
				Source: predecessor,
			})
		case "PA30":
			referencedRecords[normalizeCIXName(source.Name)] = struct{}{}
			record, ok := mainByName[normalizeCIXName(source.Name)]
			if !ok {
				return nil, fmt.Errorf("uup servicing: target %q references missing PSF record %q", file.Name, source.Name)
			}
			if record.Hash != source.Hash || len(record.Sources) != 1 {
				return nil, fmt.Errorf("uup servicing: target %q has ambiguous PSF record %q", file.Name, source.Name)
			}
			raw := record.Sources[0]
			if raw.Type == "PA30" {
				// This CIX entry wraps a directly ranged PA30/31 stream. The
				// payload-aware pass below validates its header and history edge.
				continue
			}
			if raw.Type != "RAW" || raw.Offset < 0 || raw.Length < 0 || raw.Hash != record.Hash || raw.Length != record.Length || raw.Offset > psf.Length-raw.Length {
				return nil, fmt.Errorf("uup servicing: PSF record %q has no valid bounded RAW payload", record.Name)
			}
			target := ContentDescriptor{Name: file.Name, Length: file.Length, SHA256: file.Hash}
			payload := DeltaPayload{
				Target: target, Record: ContentDescriptor{Name: record.Name, Length: record.Length, SHA256: record.Hash}, RecordOffset: raw.Offset, RecordType: "RAW",
			}
			if len(file.Bases) == 1 {
				basis := file.Bases[0]
				payload.Basis = &ContentDescriptor{Length: basis.Length, SHA256: basis.Hash}
			}
			nameKey := normalizeCIXName(file.Name)
			if _, exists := seenTargetNames[nameKey]; exists {
				return nil, fmt.Errorf("uup servicing: duplicate target name %q", file.Name)
			}
			seenTargetNames[nameKey] = struct{}{}
			graph.Payloads = append(graph.Payloads, payload)
		default:
			return nil, fmt.Errorf("uup servicing: unsupported history source type %q for %q", source.Type, file.Name)
		}
	}
	sort.Slice(graph.Sources, func(i, j int) bool {
		return normalizeCIXName(graph.Sources[i].Name) < normalizeCIXName(graph.Sources[j].Name)
	})
	// Some final component files (for example SecureBoot firmware cabinets)
	// are stored directly in the main PSF index, without a history edge.
	// Do not mistake container metadata or unreferenced f/r delta records for
	// installed content. Actual patch records retain their history semantics.
	for _, file := range psf.Files {
		key := normalizeCIXName(file.Name)
		if _, referenced := referencedRecords[key]; referenced {
			continue
		}
		_, relative, err := ParseComponentContentName(file.Name)
		if err != nil || strings.HasPrefix(strings.ToLower(relative), `f\`) || strings.HasPrefix(strings.ToLower(relative), `r\`) {
			continue
		}
		if len(file.Sources) != 1 || file.Sources[0].Type != "RAW" {
			continue
		}
		source := file.Sources[0]
		if len(file.Bases) != 0 || source.Name != "" || source.Offset < 0 || source.Length < 0 || source.Length != file.Length || source.Hash != file.Hash || source.Offset > psf.Length-source.Length {
			return nil, fmt.Errorf("uup servicing: literal target %q has invalid RAW range or identity", file.Name)
		}
		if _, exists := seenTargetNames[key]; exists {
			return nil, fmt.Errorf("uup servicing: duplicate literal target name %q", file.Name)
		}
		descriptor := ContentDescriptor{Name: file.Name, Length: file.Length, SHA256: file.Hash}
		graph.Payloads = append(graph.Payloads, DeltaPayload{Literal: true, Target: descriptor, Record: descriptor, RecordOffset: source.Offset, RecordType: "RAW"})
		seenTargetNames[key] = struct{}{}
	}
	sort.Slice(graph.Carries, func(i, j int) bool {
		return normalizeCIXName(graph.Carries[i].Target.Name) < normalizeCIXName(graph.Carries[j].Target.Name)
	})
	sort.Slice(graph.Payloads, func(i, j int) bool {
		return normalizeCIXName(graph.Payloads[i].Target.Name) < normalizeCIXName(graph.Payloads[j].Target.Name)
	})
	return graph, nil
}

// BuildCumulativeGraphWithRecords also resolves the direct PA30 entries found
// in a PSF index. Unlike ordinary indexed records, these entries describe the
// target directly, so their exact basis hash is read from the bounded PA30/31
// header and verified against the history source catalog.
func BuildCumulativeGraphWithRecords(psf, history *ContainerIndex, payload storage.Reader, maximumRecordBytes int64) (*CumulativeGraph, error) {
	if payload == nil || payload.Size() < 0 {
		return nil, fmt.Errorf("uup servicing: PSF payload is required")
	}
	if maximumRecordBytes <= 0 {
		return nil, fmt.Errorf("uup servicing: maximum record size must be positive")
	}
	graph, err := BuildCumulativeGraph(psf, history)
	if err != nil {
		return nil, err
	}
	if psf.Length > payload.Size() {
		return nil, fmt.Errorf("uup servicing: declared PSF length %d exceeds payload size %d", psf.Length, payload.Size())
	}
	seenTargets := make(map[string]struct{}, len(graph.Payloads))
	for _, item := range graph.Payloads {
		seenTargets[normalizeCIXName(item.Target.Name)] = struct{}{}
	}
	historyByRecordName := make(map[string]CIXFile)
	for _, file := range history.Files {
		if len(file.Sources) != 1 || file.Sources[0].Type != "PA30" {
			continue
		}
		source := file.Sources[0]
		key := normalizeCIXName(source.Name)
		if previous, exists := historyByRecordName[key]; exists && normalizeCIXName(previous.Name) != normalizeCIXName(file.Name) {
			return nil, fmt.Errorf("uup servicing: PA30 record name %q maps to multiple targets", source.Name)
		}
		historyByRecordName[key] = file
	}
	for _, file := range psf.Files {
		if len(file.Sources) != 1 || file.Sources[0].Type != "PA30" {
			continue
		}
		source := file.Sources[0]
		if source.Name != "" || source.Offset < 0 || source.Length <= 0 || source.Length > maximumRecordBytes || source.Offset > psf.Length-source.Length {
			return nil, fmt.Errorf("uup servicing: direct PA30 target %q has invalid record range", file.Name)
		}
		data := make([]byte, source.Length)
		if _, err := io.ReadFull(io.NewSectionReader(payload, source.Offset, source.Length), data); err != nil {
			return nil, fmt.Errorf("uup servicing: read direct PA30 record for %q: %w", file.Name, err)
		}
		digest := sha256.Sum256(data)
		if digest != source.Hash {
			return nil, fmt.Errorf("uup servicing: direct PA30 record for %q has SHA-256 %x, want %x", file.Name, digest, source.Hash)
		}
		header, err := msdelta.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("uup servicing: parse direct PA30 record for %q: %w", file.Name, err)
		}
		historyTarget, found := historyByRecordName[normalizeCIXName(file.Name)]
		if !found {
			// The main CIX may retain record-generating deltas for source
			// revisions which are not targets of this history index.
			continue
		}
		if len(historyTarget.Sources) != 1 || historyTarget.Sources[0].Hash != file.Hash {
			return nil, fmt.Errorf("uup servicing: direct PA30 record %q does not match its history target", file.Name)
		}
		if header.TargetSize != uint64(file.Length) || len(header.TargetHash) != 32 || !equalHashBytes(file.Hash, header.TargetHash) {
			return nil, fmt.Errorf("uup servicing: nested PA30 record identity mismatch for %q", file.Name)
		}
		key := normalizeCIXName(historyTarget.Name)
		if _, exists := seenTargets[key]; exists {
			return nil, fmt.Errorf("uup servicing: duplicate target name %q", file.Name)
		}
		item := DeltaPayload{
			Target:       ContentDescriptor{Name: historyTarget.Name, Length: historyTarget.Length, SHA256: historyTarget.Hash},
			Record:       ContentDescriptor{Name: file.Name, Length: source.Length, SHA256: source.Hash},
			RecordOffset: source.Offset, RecordType: "PA30",
		}
		recordTarget := ContentDescriptor{Name: file.Name, Length: file.Length, SHA256: file.Hash}
		item.RecordTarget = &recordTarget
		if len(header.ExtensionHash) != 0 {
			if len(header.ExtensionHash) != 32 {
				return nil, fmt.Errorf("uup servicing: direct PA30 target %q uses a non-SHA-256 basis", file.Name)
			}
			var basisHash [32]byte
			copy(basisHash[:], header.ExtensionHash)
			basis, found, err := graph.FindSourceByHash(basisHash)
			if err != nil {
				return nil, err
			}
			if !found {
				return nil, fmt.Errorf("uup servicing: nested PA30 record %q has unresolved basis SHA-256 %x", file.Name, basisHash)
			}
			item.RecordBasis = &basis
		}
		if len(historyTarget.Bases) == 1 {
			basis, err := graph.resolveEdgeBasis(historyTarget.Bases[0])
			if err != nil {
				return nil, err
			}
			item.Basis = &basis
		}
		seenTargets[key] = struct{}{}
		graph.Payloads = append(graph.Payloads, item)
	}
	sort.Slice(graph.Payloads, func(i, j int) bool {
		return normalizeCIXName(graph.Payloads[i].Target.Name) < normalizeCIXName(graph.Payloads[j].Target.Name)
	})
	return graph, nil
}

func (g *CumulativeGraph) resolveEdgeBasis(edge CIXBasis) (ContentDescriptor, error) {
	basis, found, err := g.FindSourceByHash(edge.Hash)
	if err != nil {
		return ContentDescriptor{}, err
	}
	if !found {
		return ContentDescriptor{Length: edge.Length, SHA256: edge.Hash}, nil
	}
	// The matching history source supplies the installed predecessor's name.
	// Its file length describes that history target and can differ from the byte
	// sequence consumed by this particular delta edge.
	basis.Length = edge.Length
	return basis, nil
}

func equalHashBytes(hash [32]byte, value []byte) bool {
	if len(value) != len(hash) {
		return false
	}
	for index := range hash {
		if hash[index] != value[index] {
			return false
		}
	}
	return true
}

func normalizeCIXName(name string) string {
	return strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(name, "/", "\\"), "\\"))
}

// FindSourceByHash returns an unambiguous predecessor descriptor.
func (g *CumulativeGraph) FindSourceByHash(hash [32]byte) (ContentDescriptor, bool, error) {
	var result ContentDescriptor
	found := false
	for _, source := range g.Sources {
		if source.SHA256 != hash {
			continue
		}
		if found && result.Length != source.Length {
			return ContentDescriptor{}, false, fmt.Errorf("uup servicing: SHA-256 %x has conflicting source lengths", hash)
		}
		result, found = source, true
	}
	return result, found, nil
}
