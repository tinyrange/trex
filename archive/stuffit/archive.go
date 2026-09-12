// Package stuffit reads the classic 22/112-byte StuffIt archive generation.
// Layout: https://code.google.com/archive/p/theunarchiver/wikis/StuffItFormat.wiki
// Original media establishes CRC-16/ARC (not the CCITT CRC named in that page).
package stuffit

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Entry struct {
	Occurrence                                 int
	InstallerRecord                            bool
	DeclaredSizes                              [2]uint32
	Path                                       string
	Name                                       []byte
	Directory                                  bool
	Type, Creator                              [4]byte
	Created, Modified                          uint32
	FinderFlags                                uint16
	Methods                                    [2]byte
	CRC                                        [2]uint16
	Data, Resource, StoredData, StoredResource starfile.File
}
type Archive struct {
	Signature                    string
	DeclaredCount, TopLevelCount int
	RootCountVerified            bool
	Version                      byte
	Entries                      []Entry
}

func crc16(b []byte) uint16 {
	var c uint16
	for _, v := range b {
		c ^= uint16(v)
		for i := 0; i < 8; i++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xa001
			} else {
				c >>= 1
			}
		}
	}
	return c
}
func component(name []byte) string {
	const digits = "0123456789ABCDEF"
	dot := string(name) == "." || string(name) == ".."
	var b []byte
	for _, v := range name {
		if dot || v < 32 || v >= 127 || v == '/' || v == '%' {
			b = append(b, '%', digits[v>>4], digits[v&15])
		} else {
			b = append(b, v)
		}
	}
	return string(b)
}

// Open validates every header, directory boundary and decoded fork CRC. The
// byte limit bounds total decoded forks and each stored compressed input.
func Open(file starfile.File, maximumEntries int, maximumBytes int64) (*Archive, error) {
	if maximumEntries <= 0 || maximumBytes < 0 {
		return nil, fmt.Errorf("stuffit: invalid limits")
	}
	var h [22]byte
	if _, err := starfile.ReadFullAt(file, h[:], 0); err != nil {
		return nil, err
	}
	be := binary.BigEndian
	if string(h[:8]) == "StuffIt " {
		return open5(file, maximumEntries, maximumBytes)
	}
	switch string(h[:4]) {
	case "SIT!", "ST46", "ST50", "ST60", "ST65", "STin", "STi2", "STi3", "STi4":
	default:
		return nil, fmt.Errorf("stuffit: unknown archive signature")
	}
	if string(h[10:14]) != "rLau" || int64(be.Uint32(h[6:])) != file.Size() {
		return nil, fmt.Errorf("stuffit: invalid archive signature or declared size")
	}
	a := &Archive{Version: h[14], Signature: string(h[:4]), DeclaredCount: int(be.Uint16(h[4:]))}
	offset := int64(22)
	remaining := maximumBytes
	stack := []string{""}
	seen := map[string]bool{}
	occurrences := map[string]int{}
	roots, headers := 0, 0
	for offset < file.Size() {
		// Closing markers are records too; bound them independently of files.
		headers++
		if int64(headers) > int64(maximumEntries)*2 {
			return nil, fmt.Errorf("stuffit: header limit exceeded")
		}
		var b [112]byte
		if _, err := starfile.ReadFullAt(file, b[:], offset); err != nil {
			return nil, err
		}
		offset += 112
		if crc16(b[:110]) != be.Uint16(b[110:]) {
			return nil, fmt.Errorf("stuffit: header CRC mismatch at %d", offset-112)
		}
		if b[2] > 63 {
			return nil, fmt.Errorf("stuffit: invalid name length")
		}
		if b[0] == 33 || b[1] == 33 {
			if b[0] != 33 || b[1] != 33 || len(stack) == 1 {
				return nil, fmt.Errorf("stuffit: unmatched directory end")
			}
			// End markers can repeat the archive root name, not the immediate
			// directory name. The markers' nesting defines ownership.
			stack = stack[:len(stack)-1]
			continue
		}
		if len(a.Entries) >= maximumEntries {
			return nil, fmt.Errorf("stuffit: entry limit exceeded")
		}
		if b[2] == 0 {
			return nil, fmt.Errorf("stuffit: empty file name")
		}
		e := Entry{Name: append([]byte{}, b[3:3+int(b[2])]...), Methods: [2]byte{b[0], b[1]}}
		e.DeclaredSizes = [2]uint32{be.Uint32(b[84:]), be.Uint32(b[88:])}
		copy(e.Type[:], b[66:70])
		copy(e.Creator[:], b[70:74])
		extendedMetadata := a.Signature == "ST60" || a.Signature == "ST65"
		metadata := string(e.Type[:]) == "STcp" || string(e.Type[:]) == "STde" || string(e.Type[:]) == "STal" ||
			(extendedMetadata && (string(e.Type[:]) == "STda" || string(e.Type[:]) == "STmv"))
		installerDialect := a.Signature == "ST46" || extendedMetadata
		e.InstallerRecord = string(e.Creator[:]) == "STin" && (metadata || string(e.Type[:]) == "DIFF")
		e.Path = stack[len(stack)-1] + "/" + component(e.Name)
		directory := b[0] == 32 && b[1] == 32
		previousDirectory, exists := seen[e.Path]
		// ST60/ST65 metadata may name an earlier directory (for example STde).
		// It is an instruction record, not a replacement file at that path.
		allowRepeatedRecord := installerDialect && e.InstallerRecord && !directory &&
			(!previousDirectory || (extendedMetadata && metadata))
		// ST60 also stores alternative ordinary file records. Palm Desktop
		// includes two pairs of alternative help-file records.
		// Keep their occurrences; selecting an installed variant is not parsing.
		allowRepeatedRecord = allowRepeatedRecord || (a.Signature == "ST60" && !directory && !previousDirectory)
		if exists && !(a.Signature == "STi2" && directory && previousDirectory) && !allowRepeatedRecord {
			return nil, fmt.Errorf("stuffit: duplicate path %q at header %d (type %q, creator %q)", e.Path, offset-112, e.Type, e.Creator)
		}
		// Metadata preceding a file does not occupy that file's path either.
		// Keep identity in occurrences, but track only actual files/directories
		// for the ordinary collision check.
		metadataOnly := installerDialect && e.InstallerRecord && metadata && !directory
		if !metadataOnly && (!exists || !allowRepeatedRecord) {
			seen[e.Path] = directory
		}
		occurrences[e.Path]++
		e.Occurrence = occurrences[e.Path]
		if len(stack) == 1 {
			roots++
		}
		e.FinderFlags = be.Uint16(b[74:])
		e.Created = be.Uint32(b[76:])
		e.Modified = be.Uint32(b[80:])
		if b[0] == 32 || b[1] == 32 {
			if b[0] != 32 || b[1] != 32 {
				return nil, fmt.Errorf("stuffit: inconsistent directory marker")
			}
			e.Directory = true
			stack = append(stack, e.Path)
		} else {
			for i := 0; i < 2; i++ {
				size, stored := int64(be.Uint32(b[84+i*4:])), int64(be.Uint32(b[92+i*4:]))
				e.DeclaredSizes[i] = uint32(size)
				// Installer metadata payloads are not zero-length installed
				// files. Their CRC covers the stored, uncompressed bytes.
				// Preserve them and the raw logical size without performing copies.
				if installerDialect && e.InstallerRecord && metadata && i == 1 && size == 0 && e.Methods[i] == 0 {
					size = stored
				}
				if size > remaining || stored > maximumBytes || size >= int64(int(^uint(0)>>1)) {
					return nil, fmt.Errorf("stuffit: decoded or stored fork limit exceeded")
				}
				if stored > file.Size()-offset {
					return nil, fmt.Errorf("stuffit: fork outside input")
				}
				e.CRC[i] = be.Uint16(b[100+i*2:])
				view := &starfile.Slice{Name: e.Path, Base: file, Offset: offset, Length: stored}
				offset += stored
				input, err := starfile.ReadAll(view)
				if err != nil {
					return nil, err
				}
				var decoded []byte
				switch e.Methods[i] {
				case 0:
					if stored != size {
						return nil, fmt.Errorf("stuffit: stored fork length mismatch")
					}
					decoded = input
				case 13:
					decoded, err = decode13(input, int(size))
				case 14:
					decoded, err = decode14(input, int(size))
				default:
					err = fmt.Errorf("unsupported or encrypted compression method %d", e.Methods[i])
				}
				if err != nil {
					return nil, fmt.Errorf("stuffit %q fork %d: %w", e.Path, i, err)
				}
				if crc16(decoded) != e.CRC[i] {
					return nil, fmt.Errorf("stuffit %q fork %d: CRC mismatch", e.Path, i)
				}
				value := &starfile.Bytes{Name: e.Path, Data: decoded}
				if i == 0 {
					e.Resource, e.StoredResource = value, view
				} else {
					e.Data, e.StoredData = value, view
				}
				remaining -= size
			}
		}
		a.Entries = append(a.Entries, e)
	}
	a.TopLevelCount = roots
	// Installer catalogs contain directory/selection records beyond the normal
	// archive root count. Preserve this field without inventing its meaning.
	a.RootCountVerified = a.Signature != "STi2" && a.Signature != "ST46" && a.Signature != "ST50" && a.Signature != "ST60" && a.Signature != "ST65"
	if len(stack) != 1 || (a.RootCountVerified && roots != a.DeclaredCount) {
		return nil, fmt.Errorf("stuffit: unclosed directory or top-level count mismatch")
	}
	return a, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumEntries, maximumBytes := 1000000, int64(256<<20)
	if err := starlark.UnpackArgs("stuffit", args, kwargs, "file", &value, "maximum_entries?", &maximumEntries, "maximum_decoded_bytes?", &maximumBytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("stuffit: expected file")
	}
	a, err := Open(file, maximumEntries, maximumBytes)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(a.Entries))
	for i, e := range a.Entries {
		kind := "file"
		if e.Directory {
			kind = "directory"
		}
		attrs := starlark.StringDict{"path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "entry_type": starlark.String(kind), "size": starlark.MakeInt(0), "resource_size": starlark.MakeInt(0), "file_type": starlark.Bytes(e.Type[:]), "creator": starlark.Bytes(e.Creator[:]), "created": starlark.MakeUint(uint(e.Created)), "modified": starlark.MakeUint(uint(e.Modified)), "finder_flags": starlark.MakeInt(int(e.FinderFlags))}
		attrs["occurrence"] = starlark.MakeInt(e.Occurrence)
		attrs["installer_record"] = starlark.Bool(e.InstallerRecord)
		attrs["declared_resource_size"] = starlark.MakeUint(uint(e.DeclaredSizes[0]))
		attrs["declared_data_size"] = starlark.MakeUint(uint(e.DeclaredSizes[1]))
		if !e.Directory {
			attrs["data"], attrs["resource"], attrs["stored_data"], attrs["stored_resource"] = e.Data, e.Resource, e.StoredData, e.StoredResource
			attrs["size"], attrs["resource_size"] = starlark.MakeInt64(e.Data.Size()), starlark.MakeInt64(e.Resource.Size())
			attrs["resource_method"], attrs["data_method"] = starlark.MakeInt(int(e.Methods[0])), starlark.MakeInt(int(e.Methods[1]))
			attrs["resource_crc16"], attrs["data_crc16"] = starlark.MakeInt(int(e.CRC[0])), starlark.MakeInt(int(e.CRC[1]))
			if a.Signature == "StuffIt5" {
				attrs["resource_crc16"], attrs["data_crc16"] = starlark.None, starlark.None
			}
		}
		entries[i] = starfile.NewRecord(attrs)
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "version": starlark.MakeInt(int(a.Version)), "signature": starlark.String(a.Signature), "declared_count": starlark.MakeInt(a.DeclaredCount), "top_level_count": starlark.MakeInt(a.TopLevelCount), "root_count_verified": starlark.Bool(a.RootCountVerified)}), nil
}
