package uup

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	defaultCIXMaximumFiles          = 1 << 20
	defaultCIXMaximumLocations      = 256
	defaultCIXMaximumSourcesPerFile = 64
	defaultCIXMaximumNameBytes      = 4096
)

// ContainerIndex is a Microsoft ContainerIndex document. PSF indexes map
// named records to byte ranges; PSFX history indexes map target files to the
// record and exact basis hash required to reconstruct them.
type ContainerIndex struct {
	Name      string
	Type      string
	Length    int64
	Version   int
	Locations []CIXLocation
	Files     []CIXFile
}

type CIXLocation struct {
	ID    int64
	Path  string
	Flags uint64
}

type CIXFile struct {
	ID         int64
	Name       string
	Length     int64
	Time       uint64
	Attributes uint64
	Hash       [32]byte
	Sources    []CIXSource
	Bases      []CIXBasis
}

type CIXSource struct {
	Type   string
	Name   string
	Offset int64
	Length int64
	Hash   [32]byte
}

type CIXBasis struct {
	// FileID is used by cabinet ContainerIndexes to name another logical file
	// in the same index. PSFX history indexes instead describe an external
	// basis by exact length and hash. Exactly one representation is present.
	FileID int64
	Length int64
	Hash   [32]byte
}

type rawCIXFile struct {
	ID     string      `xml:"id,attr"`
	Name   string      `xml:"name,attr"`
	Length string      `xml:"length,attr"`
	Time   string      `xml:"time,attr"`
	Attr   string      `xml:"attr,attr"`
	Hash   rawCIXHash  `xml:"Hash"`
	Delta  rawCIXDelta `xml:"Delta"`
}

type rawCIXDelta struct {
	Sources []rawCIXSource `xml:"Source"`
	Bases   []rawCIXBasis  `xml:"Basis"`
}

type rawCIXSource struct {
	Type   string     `xml:"type,attr"`
	Name   string     `xml:"name,attr"`
	Offset string     `xml:"offset,attr"`
	Length string     `xml:"length,attr"`
	Hash   rawCIXHash `xml:"Hash"`
}

type rawCIXBasis struct {
	File   string     `xml:"file,attr"`
	Length string     `xml:"length,attr"`
	Hash   rawCIXHash `xml:"Hash"`
}

type rawCIXHash struct {
	Algorithm string `xml:"alg,attr"`
	Value     string `xml:"value,attr"`
}

type rawCIXLocation struct {
	ID    string `xml:"id,attr"`
	Path  string `xml:"path,attr"`
	Flags string `xml:"flags,attr"`
}

// ParseContainerIndex parses a CIX document without loading the XML source as
// one byte slice. Collection sizes are bounded independently from input size.
func ParseContainerIndex(reader io.Reader) (*ContainerIndex, error) {
	decoder := xml.NewDecoder(reader)
	var result *ContainerIndex
	seenIDs := make(map[int64]struct{})
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("uup CIX: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Container":
			if result != nil {
				return nil, fmt.Errorf("uup CIX: duplicate Container element")
			}
			result = &ContainerIndex{Length: -1}
			for _, attribute := range start.Attr {
				switch attribute.Name.Local {
				case "name":
					result.Name = attribute.Value
				case "type":
					result.Type = strings.ToUpper(attribute.Value)
				case "length":
					result.Length, err = parseCIXInt64("container length", attribute.Value, true)
				case "version":
					var value int64
					value, err = parseCIXInt64("container version", attribute.Value, false)
					result.Version = int(value)
				}
				if err != nil {
					return nil, err
				}
			}
		case "Location":
			if result == nil {
				return nil, fmt.Errorf("uup CIX: Location precedes Container")
			}
			if len(result.Locations) >= defaultCIXMaximumLocations {
				return nil, fmt.Errorf("uup CIX: location count exceeds %d", defaultCIXMaximumLocations)
			}
			var raw rawCIXLocation
			if err := decoder.DecodeElement(&raw, &start); err != nil {
				return nil, fmt.Errorf("uup CIX: location: %w", err)
			}
			location, err := convertCIXLocation(raw)
			if err != nil {
				return nil, err
			}
			result.Locations = append(result.Locations, location)
		case "File":
			if result == nil {
				return nil, fmt.Errorf("uup CIX: File precedes Container")
			}
			if len(result.Files) >= defaultCIXMaximumFiles {
				return nil, fmt.Errorf("uup CIX: file count exceeds %d", defaultCIXMaximumFiles)
			}
			var raw rawCIXFile
			if err := decoder.DecodeElement(&raw, &start); err != nil {
				return nil, fmt.Errorf("uup CIX: file: %w", err)
			}
			file, err := convertCIXFile(raw)
			if err != nil {
				return nil, err
			}
			if _, exists := seenIDs[file.ID]; exists {
				return nil, fmt.Errorf("uup CIX: duplicate file id %d", file.ID)
			}
			seenIDs[file.ID] = struct{}{}
			result.Files = append(result.Files, file)
		}
	}
	if result == nil || result.Name == "" || result.Type == "" || result.Version <= 0 {
		return nil, fmt.Errorf("uup CIX: incomplete Container identity")
	}
	if result.Type == "PSF" && result.Length < 0 {
		return nil, fmt.Errorf("uup CIX: PSF container has no length")
	}
	return result, nil
}

func convertCIXLocation(raw rawCIXLocation) (CIXLocation, error) {
	id, err := parseCIXInt64("location id", raw.ID, false)
	if err != nil {
		return CIXLocation{}, err
	}
	if raw.Path == "" || len(raw.Path) > defaultCIXMaximumNameBytes {
		return CIXLocation{}, fmt.Errorf("uup CIX: invalid location path")
	}
	flags, err := strconv.ParseUint(raw.Flags, 16, 64)
	if err != nil {
		return CIXLocation{}, fmt.Errorf("uup CIX: invalid location flags %q", raw.Flags)
	}
	return CIXLocation{ID: id, Path: raw.Path, Flags: flags}, nil
}

func convertCIXFile(raw rawCIXFile) (CIXFile, error) {
	id, err := parseCIXInt64("file id", raw.ID, false)
	if err != nil {
		return CIXFile{}, err
	}
	if raw.Name == "" || len(raw.Name) > defaultCIXMaximumNameBytes {
		return CIXFile{}, fmt.Errorf("uup CIX: file %d has invalid name", id)
	}
	length, err := parseCIXInt64("file length", raw.Length, false)
	if err != nil {
		return CIXFile{}, err
	}
	timestamp, err := parseCIXUint64("file time", raw.Time, true)
	if err != nil {
		return CIXFile{}, err
	}
	attributes, err := parseCIXUint64("file attributes", raw.Attr, true)
	if err != nil {
		return CIXFile{}, err
	}
	hash, err := parseCIXHash(raw.Hash)
	if err != nil {
		return CIXFile{}, fmt.Errorf("uup CIX: file %d: %w", id, err)
	}
	if len(raw.Delta.Sources) == 0 || len(raw.Delta.Sources) > defaultCIXMaximumSourcesPerFile || len(raw.Delta.Bases) > defaultCIXMaximumSourcesPerFile {
		return CIXFile{}, fmt.Errorf("uup CIX: file %d has invalid delta cardinality", id)
	}
	file := CIXFile{ID: id, Name: raw.Name, Length: length, Time: timestamp, Attributes: attributes, Hash: hash}
	for _, rawSource := range raw.Delta.Sources {
		source, err := convertCIXSource(id, rawSource)
		if err != nil {
			return CIXFile{}, err
		}
		file.Sources = append(file.Sources, source)
	}
	for _, rawBasis := range raw.Delta.Bases {
		if rawBasis.File != "" {
			if rawBasis.Length != "" || rawBasis.Hash.Algorithm != "" || rawBasis.Hash.Value != "" {
				return CIXFile{}, fmt.Errorf("uup CIX: file %d basis mixes file and hash forms", id)
			}
			fileID, err := parseCIXInt64("basis file id", rawBasis.File, false)
			if err != nil {
				return CIXFile{}, fmt.Errorf("uup CIX: file %d: %w", id, err)
			}
			file.Bases = append(file.Bases, CIXBasis{FileID: fileID, Length: -1})
			continue
		}
		length, err := parseCIXInt64("basis length", rawBasis.Length, false)
		if err != nil {
			return CIXFile{}, fmt.Errorf("uup CIX: file %d: %w", id, err)
		}
		hash, err := parseCIXHash(rawBasis.Hash)
		if err != nil {
			return CIXFile{}, fmt.Errorf("uup CIX: file %d basis: %w", id, err)
		}
		file.Bases = append(file.Bases, CIXBasis{FileID: -1, Length: length, Hash: hash})
	}
	return file, nil
}

func convertCIXSource(fileID int64, raw rawCIXSource) (CIXSource, error) {
	typ := strings.ToUpper(raw.Type)
	if typ == "" || len(raw.Name) > defaultCIXMaximumNameBytes {
		return CIXSource{}, fmt.Errorf("uup CIX: file %d has invalid source", fileID)
	}
	offset, err := parseCIXInt64("source offset", raw.Offset, true)
	if err != nil {
		return CIXSource{}, fmt.Errorf("uup CIX: file %d: %w", fileID, err)
	}
	length, err := parseCIXInt64("source length", raw.Length, true)
	if err != nil {
		return CIXSource{}, fmt.Errorf("uup CIX: file %d: %w", fileID, err)
	}
	hash, err := parseCIXHash(raw.Hash)
	if err != nil {
		return CIXSource{}, fmt.Errorf("uup CIX: file %d source: %w", fileID, err)
	}
	if raw.Offset != "" && raw.Length == "" || raw.Offset == "" && raw.Length != "" {
		return CIXSource{}, fmt.Errorf("uup CIX: file %d source has incomplete range", fileID)
	}
	if raw.Offset == "" && raw.Name == "" {
		return CIXSource{}, fmt.Errorf("uup CIX: file %d source has neither name nor range", fileID)
	}
	return CIXSource{Type: typ, Name: raw.Name, Offset: offset, Length: length, Hash: hash}, nil
}

func parseCIXHash(raw rawCIXHash) ([32]byte, error) {
	var result [32]byte
	if !strings.EqualFold(raw.Algorithm, "SHA256") {
		return result, fmt.Errorf("unsupported hash algorithm %q", raw.Algorithm)
	}
	decoded, err := hex.DecodeString(raw.Value)
	if err != nil || len(decoded) != len(result) {
		return result, fmt.Errorf("invalid SHA-256 value %q", raw.Value)
	}
	copy(result[:], decoded)
	return result, nil
}

func parseCIXInt64(name, value string, optional bool) (int64, error) {
	if value == "" && optional {
		return -1, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("uup CIX: invalid %s %q", name, value)
	}
	return parsed, nil
}

func parseCIXUint64(name, value string, optional bool) (uint64, error) {
	if value == "" && optional {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("uup CIX: invalid %s %q", name, value)
	}
	return parsed, nil
}
