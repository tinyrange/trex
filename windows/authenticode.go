package windows

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

var errNotPortableExecutable = errors.New("not a portable executable")

type authenticodeRange struct {
	offset int
	size   int
}

func catalogHashBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	algorithm := "sha1"
	if err := starlark.UnpackArgs("catalog_hash", args, kwargs, "file", &value, "algorithm?", &algorithm); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("catalog_hash: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("catalog_hash: %w", err)
	}
	digest, err := windowsCatalogHash(data, algorithm)
	if err != nil {
		return nil, fmt.Errorf("catalog_hash: %w", err)
	}
	return starlark.Bytes(digest), nil
}

// windowsCatalogHash implements the file digest used by Windows catalog
// membership checks. PE images use their Authenticode image digest; other
// formats use a flat digest of the complete file.
func windowsCatalogHash(data []byte, algorithm string) ([]byte, error) {
	h, err := authenticodeHasher(algorithm)
	if err != nil {
		return nil, err
	}
	ranges, err := authenticodePERanges(data)
	if errors.Is(err, errNotPortableExecutable) {
		_, _ = h.Write(data)
		return h.Sum(nil), nil
	}
	if err != nil {
		return nil, err
	}
	for _, region := range ranges {
		_, _ = h.Write(data[region.offset : region.offset+region.size])
	}
	return h.Sum(nil), nil
}

func authenticodeHasher(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "md5":
		return md5.New(), nil
	case "sha1", "sha-1":
		return sha1.New(), nil
	case "sha256", "sha-256":
		return sha256.New(), nil
	case "sha512", "sha-512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}
}

func authenticodePERanges(data []byte) ([]authenticodeRange, error) {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return nil, errNotPortableExecutable
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if peOffset < 0x40 || peOffset > len(data)-24 || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, errNotPortableExecutable
	}
	coff := peOffset + 4
	sectionCount := int(binary.LittleEndian.Uint16(data[coff+2 : coff+4]))
	optionalSize := int(binary.LittleEndian.Uint16(data[coff+16 : coff+18]))
	optional := coff + 20
	if sectionCount <= 0 || optionalSize < 68 || optional > len(data)-optionalSize {
		return nil, fmt.Errorf("invalid PE optional header")
	}

	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	var directoryCountOffset, directoriesOffset int
	switch magic {
	case 0x10b:
		directoryCountOffset, directoriesOffset = optional+92, optional+96
	case 0x20b:
		directoryCountOffset, directoriesOffset = optional+108, optional+112
	default:
		return nil, fmt.Errorf("unsupported PE optional header magic %#x", magic)
	}
	optionalEnd := optional + optionalSize
	if directoryCountOffset > optionalEnd-4 {
		return nil, fmt.Errorf("truncated PE data-directory count")
	}
	headerSize := int(binary.LittleEndian.Uint32(data[optional+60 : optional+64]))
	checksumOffset := optional + 64
	if headerSize < checksumOffset+4 || headerSize > len(data) {
		return nil, fmt.Errorf("invalid PE header size %#x", headerSize)
	}

	exclusions := []authenticodeRange{{offset: checksumOffset, size: 4}}
	directoryCount := binary.LittleEndian.Uint32(data[directoryCountOffset : directoryCountOffset+4])
	securityEntry := directoriesOffset + 4*8
	if directoryCount > 4 && securityEntry <= optionalEnd-8 {
		exclusions = append(exclusions, authenticodeRange{offset: securityEntry, size: 8})
	}
	sort.Slice(exclusions, func(i, j int) bool { return exclusions[i].offset < exclusions[j].offset })

	ranges := make([]authenticodeRange, 0, sectionCount+len(exclusions)+1)
	cursor := 0
	for _, exclusion := range exclusions {
		if exclusion.offset < cursor || exclusion.offset+exclusion.size > headerSize {
			return nil, fmt.Errorf("invalid Authenticode exclusion range")
		}
		if exclusion.offset > cursor {
			ranges = append(ranges, authenticodeRange{offset: cursor, size: exclusion.offset - cursor})
		}
		cursor = exclusion.offset + exclusion.size
	}
	if cursor < headerSize {
		ranges = append(ranges, authenticodeRange{offset: cursor, size: headerSize - cursor})
	}

	sectionTable := optionalEnd
	if sectionTable > headerSize || sectionCount > (headerSize-sectionTable)/40 {
		return nil, fmt.Errorf("PE section table exceeds headers")
	}
	sections := make([]authenticodeRange, 0, sectionCount)
	for index := 0; index < sectionCount; index++ {
		entry := sectionTable + index*40
		size := int(binary.LittleEndian.Uint32(data[entry+16 : entry+20]))
		offset := int(binary.LittleEndian.Uint32(data[entry+20 : entry+24]))
		if size == 0 {
			continue
		}
		if offset < headerSize || offset > len(data) || size > len(data)-offset {
			return nil, fmt.Errorf("PE section %d exceeds file", index)
		}
		sections = append(sections, authenticodeRange{offset: offset, size: size})
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].offset < sections[j].offset })
	for index, section := range sections {
		if index > 0 && section.offset < sections[index-1].offset+sections[index-1].size {
			return nil, fmt.Errorf("overlapping PE sections")
		}
		ranges = append(ranges, section)
	}
	return ranges, nil
}
