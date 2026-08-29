package installshield

import (
	"bytes"
	"compress/flate"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"
	"sync"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	installShieldSignature      = uint32(0x28635349)
	installShieldMaxHeaderSize  = int64(64 << 20)
	installShieldMaxEntries     = uint32(1 << 20)
	installShieldFileInvalid    = uint16(8)
	installShieldFileObfuscated = uint16(2)
	installShieldFileCompressed = uint16(4)
)

type UnsupportedVersionError struct {
	version int
	raw     uint32
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("installshield: unsupported cabinet version %d (raw %#08x)", e.version, e.raw)
}

// The cabinet layout is independently implemented with format behavior
// validated against the MIT-licensed Unshield project. See
// docs/third-party-format-references.md. Shell-object records were derived from
// bounded structural analysis of the media database and synthetic fixtures.

type installShieldFileGroup struct {
	name      string
	target    string
	firstFile int32
	lastFile  int32
	offset    uint32
}

type installShieldComponent struct {
	name       string
	fileGroups []string
	offset     uint32
}

type shortcut struct {
	folder       string
	folderRoot   string
	component    string
	name         string
	display      string
	target       string
	arguments    string
	workingDir   string
	icon         string
	description  string
	shortcutType uint16
	iconIndex    int32
	showCommand  int32
	flags        uint32
}

type fileRecord struct {
	name           string
	directory      string
	group          string
	components     []string
	path           string
	flags          uint16
	expandedSize   uint64
	compressedSize uint64
	dataOffset     uint64
	digest         [16]byte
	volume         uint16
	linkPrevious   uint32
	linkFlags      byte
}

type installShieldV5VolumeHeader struct {
	firstFileIndex      uint32
	lastFileIndex       uint32
	firstFileOffset     uint32
	firstExpandedSize   uint32
	firstCompressedSize uint32
	lastFileOffset      uint32
	lastExpandedSize    uint32
	lastCompressedSize  uint32
}

type Archive struct {
	version    int
	header     starfile.File
	volumes    map[uint16]starfile.File
	external   map[string][]starfile.File
	files      []fileRecord
	fileIndex  map[string]int
	groups     []installShieldFileGroup
	components []installShieldComponent
	shortcuts  []shortcut
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var headerValue, cabinetsValue starlark.Value
	externalValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("installshield", args, kwargs, "header", &headerValue, "cabinets", &cabinetsValue, "external?", &externalValue); err != nil {
		return nil, err
	}
	header, ok := headerValue.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("installshield: header is %s, want file", headerValue.Type())
	}
	iterable, ok := cabinetsValue.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("installshield: cabinets must be iterable")
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	volumes := make(map[uint16]starfile.File)
	var item starlark.Value
	for iterator.Next(&item) {
		file, ok := item.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("installshield: cabinet %d is %s, want file", len(volumes)+1, item.Type())
		}
		volumes[uint16(len(volumes)+1)] = file
	}
	external := make(map[string][]starfile.File)
	if externalValue != starlark.None {
		dict, ok := externalValue.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("installshield: external must be a dict of names to files")
		}
		for _, pair := range dict.Items() {
			name, ok := starlark.AsString(pair[0])
			if !ok {
				return nil, fmt.Errorf("installshield: external name is %s, want string", pair[0].Type())
			}
			file, ok := pair[1].(starfile.File)
			if !ok {
				return nil, fmt.Errorf("installshield: external %q is %s, want file", name, pair[1].Type())
			}
			addInstallShieldExternal(external, name, file)
		}
	}
	return Open(header, volumes, external)
}

func addInstallShieldExternal(external map[string][]starfile.File, name string, file starfile.File) {
	normalized := strings.ToLower(normalizeInstallShieldPart(name))
	parts := strings.Split(normalized, "/")
	for index := range parts {
		key := strings.Join(parts[index:], "/")
		if key != "" {
			external[key] = append(external[key], file)
		}
	}
}

func Open(header starfile.File, volumes map[uint16]starfile.File, external map[string][]starfile.File) (*Archive, error) {
	if header.Size() < 20 || header.Size() > installShieldMaxHeaderSize {
		return nil, fmt.Errorf("installshield: invalid header size %d", header.Size())
	}
	data := make([]byte, int(header.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(header, 0, header.Size()), data); err != nil {
		return nil, fmt.Errorf("installshield: read header: %w", err)
	}
	if binary.LittleEndian.Uint32(data[:4]) != installShieldSignature {
		return nil, fmt.Errorf("installshield: invalid ISc( signature")
	}
	rawVersion := binary.LittleEndian.Uint32(data[4:8])
	version := 0
	if rawVersion>>24 == 1 {
		version = int((rawVersion >> 12) & 0xf)
	} else if rawVersion>>24 == 2 || rawVersion>>24 == 4 {
		version = int(rawVersion & 0xffff)
		if version != 0 {
			version /= 100
		}
	}
	if version < 5 || version > 16 {
		return nil, &UnsupportedVersionError{version: version, raw: rawVersion}
	}
	descriptor := uint64(binary.LittleEndian.Uint32(data[12:16]))
	descriptorSize := uint64(binary.LittleEndian.Uint32(data[16:20]))
	if descriptorSize == 0 || descriptor > uint64(len(data)) || descriptorSize > uint64(len(data))-descriptor {
		return nil, fmt.Errorf("installshield: cabinet descriptor is out of bounds")
	}
	read32 := func(offset uint64) (uint32, error) {
		if offset > uint64(len(data)) || 4 > uint64(len(data))-offset {
			return 0, fmt.Errorf("offset %#x is out of bounds", offset)
		}
		return binary.LittleEndian.Uint32(data[offset : offset+4]), nil
	}
	fileTableOffset, err := read32(descriptor + 0x0c)
	if err != nil {
		return nil, fmt.Errorf("installshield: file table: %w", err)
	}
	directoryCount, err := read32(descriptor + 0x1c)
	if err != nil {
		return nil, fmt.Errorf("installshield: directory count: %w", err)
	}
	fileCount, err := read32(descriptor + 0x28)
	if err != nil {
		return nil, fmt.Errorf("installshield: file count: %w", err)
	}
	fileDescriptorOffset, err := read32(descriptor + 0x2c)
	if err != nil {
		return nil, fmt.Errorf("installshield: file descriptors: %w", err)
	}
	if directoryCount > installShieldMaxEntries || fileCount > installShieldMaxEntries || uint64(directoryCount)+uint64(fileCount) > uint64(installShieldMaxEntries) {
		return nil, fmt.Errorf("installshield: implausible table sizes: %d directories, %d files", directoryCount, fileCount)
	}
	table := descriptor + uint64(fileTableOffset)
	if table > uint64(len(data)) || uint64(directoryCount+fileCount)*4 > uint64(len(data))-table {
		return nil, fmt.Errorf("installshield: file table is out of bounds")
	}
	readCString := func(offset uint64) (string, error) {
		if offset >= uint64(len(data)) {
			return "", fmt.Errorf("string offset %#x is out of bounds", offset)
		}
		remaining := data[offset:]
		end := bytes.IndexByte(remaining, 0)
		if end < 0 {
			return "", fmt.Errorf("unterminated string at %#x", offset)
		}
		return string(remaining[:end]), nil
	}
	directories := make([]string, directoryCount)
	for index := range directories {
		offset := binary.LittleEndian.Uint32(data[table+uint64(index)*4:])
		name, err := readCString(table + uint64(offset))
		if err != nil {
			return nil, fmt.Errorf("installshield: directory %d: %w", index, err)
		}
		directories[index] = normalizeInstallShieldPart(name)
	}

	groups, err := parseInstallShieldGroups(data, descriptor, version, readCString)
	if err != nil {
		return nil, err
	}
	components, err := parseInstallShieldComponents(data, descriptor, version, readCString)
	if err != nil {
		return nil, err
	}
	shortcuts, err := parseInstallShieldShortcuts(data, descriptor, version, readCString)
	if err != nil {
		return nil, err
	}

	files := make([]fileRecord, fileCount)
	fileIndex := make(map[string]int, fileCount*2)
	groupComponents := make(map[string][]string)
	for _, component := range components {
		for _, group := range component.fileGroups {
			groupComponents[strings.ToLower(group)] = append(groupComponents[strings.ToLower(group)], component.name)
		}
	}
	for index := range files {
		var file fileRecord
		var nameOffset uint32
		var directoryIndex uint16
		if version <= 5 {
			relative := binary.LittleEndian.Uint32(data[table+(uint64(directoryCount)+uint64(index))*4:])
			offset := table + uint64(relative)
			if offset > uint64(len(data)) || 0x3a > uint64(len(data))-offset {
				return nil, fmt.Errorf("installshield: file descriptor %d is out of bounds", index)
			}
			record := data[offset : offset+0x3a]
			nameOffset = binary.LittleEndian.Uint32(record[0:4])
			directoryIndex = binary.LittleEndian.Uint16(record[4:6])
			file.flags = binary.LittleEndian.Uint16(record[8:10])
			file.expandedSize = uint64(binary.LittleEndian.Uint32(record[10:14]))
			file.compressedSize = uint64(binary.LittleEndian.Uint32(record[14:18]))
			file.dataOffset = uint64(binary.LittleEndian.Uint32(record[0x26:0x2a]))
			copy(file.digest[:], record[0x2a:0x3a])
			file.volume, err = installShieldV5VolumeForFile(volumes, index)
			if err != nil {
				return nil, err
			}
		} else {
			offset := table + uint64(fileDescriptorOffset) + uint64(index)*0x57
			if offset > uint64(len(data)) || 0x57 > uint64(len(data))-offset {
				return nil, fmt.Errorf("installshield: file descriptor %d is out of bounds", index)
			}
			record := data[offset : offset+0x57]
			nameOffset = binary.LittleEndian.Uint32(record[0x3a:0x3e])
			directoryIndex = binary.LittleEndian.Uint16(record[0x3e:0x40])
			file.flags = binary.LittleEndian.Uint16(record[:2])
			file.expandedSize = binary.LittleEndian.Uint64(record[2:10])
			file.compressedSize = binary.LittleEndian.Uint64(record[10:18])
			file.dataOffset = binary.LittleEndian.Uint64(record[18:26])
			copy(file.digest[:], record[0x1a:0x2a])
			file.linkPrevious = binary.LittleEndian.Uint32(record[0x4c:0x50])
			file.linkFlags = record[0x54]
			file.volume = binary.LittleEndian.Uint16(record[0x55:0x57])
		}
		if uint32(directoryIndex) >= directoryCount {
			return nil, fmt.Errorf("installshield: file %d has invalid directory %d", index, directoryIndex)
		}
		name, err := readCString(table + uint64(nameOffset))
		if err != nil {
			return nil, fmt.Errorf("installshield: file %d name: %w", index, err)
		}
		group := "ungrouped"
		for _, candidate := range groups {
			if int32(index) >= candidate.firstFile && int32(index) <= candidate.lastFile {
				group = candidate.name
				break
			}
		}
		memberPath := normalizeInstallShieldPath(group, directories[directoryIndex], name)
		file.name = name
		file.directory = directories[directoryIndex]
		file.group = group
		file.components = append([]string(nil), groupComponents[strings.ToLower(group)]...)
		file.path = memberPath
		files[index] = file
		addInstallShieldIndex(fileIndex, memberPath, index)
		addInstallShieldIndex(fileIndex, name, index)
	}
	return &Archive{version: version, header: header, volumes: volumes, external: external, files: files, fileIndex: fileIndex, groups: groups, components: components, shortcuts: shortcuts}, nil
}

func installShieldV5VolumeForFile(volumes map[uint16]starfile.File, index int) (uint16, error) {
	if len(volumes) == 0 {
		return 1, nil
	}
	indices := make([]int, 0, len(volumes))
	for volume := range volumes {
		indices = append(indices, int(volume))
	}
	sort.Ints(indices)
	for _, volumeIndex := range indices {
		volume := volumes[uint16(volumeIndex)]
		header, err := readInstallShieldV5VolumeHeader(volume, uint16(volumeIndex))
		if err != nil {
			return 0, err
		}
		if uint32(index) >= header.firstFileIndex && uint32(index) <= header.lastFileIndex {
			return uint16(volumeIndex), nil
		}
	}
	return 0, fmt.Errorf("installshield: file %d is not covered by a version 5 volume", index)
}

func readInstallShieldV5VolumeHeader(volume starfile.File, index uint16) (installShieldV5VolumeHeader, error) {
	if volume.Size() < 60 {
		return installShieldV5VolumeHeader{}, fmt.Errorf("installshield: data%d.cab has a truncated version 5 volume header", index)
	}
	data := make([]byte, 60)
	if _, err := io.ReadFull(io.NewSectionReader(volume, 0, 60), data); err != nil {
		return installShieldV5VolumeHeader{}, fmt.Errorf("installshield: read data%d.cab volume header: %w", index, err)
	}
	if binary.LittleEndian.Uint32(data[:4]) != installShieldSignature {
		return installShieldV5VolumeHeader{}, fmt.Errorf("installshield: data%d.cab has an invalid volume signature", index)
	}
	return installShieldV5VolumeHeader{
		firstFileIndex:      binary.LittleEndian.Uint32(data[28:32]),
		lastFileIndex:       binary.LittleEndian.Uint32(data[32:36]),
		firstFileOffset:     binary.LittleEndian.Uint32(data[36:40]),
		firstExpandedSize:   binary.LittleEndian.Uint32(data[40:44]),
		firstCompressedSize: binary.LittleEndian.Uint32(data[44:48]),
		lastFileOffset:      binary.LittleEndian.Uint32(data[48:52]),
		lastExpandedSize:    binary.LittleEndian.Uint32(data[52:56]),
		lastCompressedSize:  binary.LittleEndian.Uint32(data[56:60]),
	}, nil
}

func parseInstallShieldShortcuts(data []byte, descriptor uint64, version int, readString func(uint64) (string, error)) ([]shortcut, error) {
	const (
		shortcutRecordSize = uint64(0x32)
		maximumShortcuts   = 4096
	)
	marker := []byte("<SHELL_OBJECT_FOLDER>\x00")
	shortcuts := make([]shortcut, 0)
	seenRecords := make(map[uint64]bool)
	parseFolder := func(descriptorAt uint64, allowEmptyFolder bool, folderRoot string) bool {
		if descriptorAt+20 > uint64(len(data)) {
			return false
		}
		count := binary.LittleEndian.Uint16(data[descriptorAt+14:])
		tableOffset := binary.LittleEndian.Uint32(data[descriptorAt+16:])
		tableAt := descriptor + uint64(tableOffset)
		if count == 0 || count > maximumShortcuts || tableAt > uint64(len(data)) || uint64(count)*4 > uint64(len(data))-tableAt {
			return false
		}
		folderOffset := binary.LittleEndian.Uint32(data[descriptorAt:])
		folder := ""
		if folderOffset != 0 {
			var err error
			folder, err = readString(descriptor + uint64(folderOffset))
			if err != nil || folder == "" {
				return false
			}
		} else if !allowEmptyFolder {
			return false
		}
		candidate := make([]shortcut, 0, count)
		recordOffsets := make([]uint64, 0, count)
		for index := uint16(0); index < count; index++ {
			recordOffset := binary.LittleEndian.Uint32(data[tableAt+uint64(index)*4:])
			recordAt := descriptor + uint64(recordOffset)
			if recordAt > uint64(len(data)) || shortcutRecordSize > uint64(len(data))-recordAt || seenRecords[recordAt] {
				return false
			}
			readField := func(offset uint64) (string, error) {
				value := binary.LittleEndian.Uint32(data[recordAt+offset:])
				if value == 0 {
					return "", nil
				}
				return readString(descriptor + uint64(value))
			}
			name, nameErr := readField(0)
			display, displayErr := readField(4)
			target, targetErr := readField(10)
			arguments, argumentsErr := readField(15)
			workingDir, workingErr := readField(19)
			icon, iconErr := readField(23)
			description, descriptionErr := readField(31)
			if nameErr != nil || displayErr != nil || targetErr != nil || argumentsErr != nil || workingErr != nil || iconErr != nil || descriptionErr != nil || name == "" || display == "" || target == "" {
				return false
			}
			shortcut := shortcut{
				folder: folder, folderRoot: folderRoot, name: name, display: display, target: target,
				arguments: arguments, workingDir: workingDir, icon: icon, description: description,
				shortcutType: binary.LittleEndian.Uint16(data[recordAt+8:]),
				iconIndex:    int32(binary.LittleEndian.Uint32(data[recordAt+27:])),
			}
			if version <= 5 {
				shortcut.showCommand = int32(binary.LittleEndian.Uint32(data[recordAt+35:]))
				shortcut.flags = uint32(binary.LittleEndian.Uint16(data[recordAt+39:]))
				componentOffset := binary.LittleEndian.Uint32(data[recordAt+46:])
				if componentOffset != 0 {
					shortcut.component, _ = readString(descriptor + uint64(componentOffset))
				}
			} else {
				shortcut.showCommand = int32(binary.LittleEndian.Uint32(data[recordAt+39:]))
				shortcut.flags = binary.LittleEndian.Uint32(data[recordAt+43:])
			}
			candidate = append(candidate, shortcut)
			recordOffsets = append(recordOffsets, recordAt)
		}
		for _, recordAt := range recordOffsets {
			seenRecords[recordAt] = true
		}
		shortcuts = append(shortcuts, candidate...)
		return true
	}
	if version <= 5 {
		for descriptorAt := descriptor; descriptorAt+20 <= uint64(len(data)); descriptorAt += 2 {
			parseFolder(descriptorAt, true, "<SHELL_OBJECT_FOLDER>")
		}
		return shortcuts, nil
	}
	// InstallShield 6 stores shell objects for four well-known folders in a
	// fixed descriptor table. Unlike named program groups below, these folder
	// descriptors have no string-valued folder root to discover by reference.
	// The table slots are Desktop, Start Menu, Programs, and Startup.
	specialRoots := [...]string{"<DESKTOP_FOLDER>", "<START_MENU_FOLDER>", "<SHELL_OBJECT_FOLDER>", "<STARTUP_FOLDER>"}
	const specialTableField = uint64(0x27e)
	if descriptor+specialTableField+4 <= uint64(len(data)) {
		tableOffset := binary.LittleEndian.Uint32(data[descriptor+specialTableField:])
		tableAt := descriptor + uint64(tableOffset)
		if tableOffset != 0 && tableAt <= uint64(len(data)) && uint64(len(specialRoots))*4 <= uint64(len(data))-tableAt {
			for index, root := range specialRoots {
				folderOffset := binary.LittleEndian.Uint32(data[tableAt+uint64(index)*4:])
				if folderOffset != 0 {
					parseFolder(descriptor+uint64(folderOffset), true, root)
				}
			}
		}
	}
	for markerAt := 0; markerAt < len(data); {
		index := bytes.Index(data[markerAt:], marker)
		if index < 0 {
			break
		}
		markerAt += index
		if uint64(markerAt) < descriptor || uint64(markerAt)-descriptor > uint64(^uint32(0)) {
			markerAt++
			continue
		}
		reference := make([]byte, 4)
		binary.LittleEndian.PutUint32(reference, uint32(uint64(markerAt)-descriptor))
		for referenceAt := 4; referenceAt+4 <= len(data); {
			found := bytes.Index(data[referenceAt:], reference)
			if found < 0 {
				break
			}
			referenceAt += found
			descriptorAt := uint64(referenceAt - 4)
			parseFolder(descriptorAt, false, "<SHELL_OBJECT_FOLDER>")
			referenceAt++
		}
		markerAt++
	}
	return shortcuts, nil
}

func parseInstallShieldGroups(data []byte, descriptor uint64, version int, readString func(uint64) (string, error)) ([]installShieldFileGroup, error) {
	groups := make([]installShieldFileGroup, 0)
	seen := make(map[uint32]bool)
	for bucket := 0; bucket < 71; bucket++ {
		at := descriptor + 0x3e + uint64(bucket)*4
		if at+4 > uint64(len(data)) {
			return nil, fmt.Errorf("installshield: file group buckets are truncated")
		}
		next := binary.LittleEndian.Uint32(data[at:])
		for next != 0 {
			if seen[next] {
				return nil, fmt.Errorf("installshield: cyclic file group list at %#x", next)
			}
			seen[next] = true
			list := descriptor + uint64(next)
			if list+12 > uint64(len(data)) {
				return nil, fmt.Errorf("installshield: file group list is out of bounds")
			}
			descriptorOffset := binary.LittleEndian.Uint32(data[list+4:])
			next = binary.LittleEndian.Uint32(data[list+8:])
			groupAt := descriptor + uint64(descriptorOffset)
			minimum := uint64(0x3e)
			if version <= 5 {
				minimum = 0x54
			}
			if groupAt+minimum > uint64(len(data)) {
				return nil, fmt.Errorf("installshield: file group descriptor is out of bounds")
			}
			nameOffset := binary.LittleEndian.Uint32(data[groupAt:])
			name, err := readString(descriptor + uint64(nameOffset))
			if err != nil {
				return nil, fmt.Errorf("installshield: file group name: %w", err)
			}
			target := ""
			firstOffset := uint64(0x16)
			if version <= 5 {
				firstOffset = 0x4c
			} else {
				targetOffset := binary.LittleEndian.Uint32(data[groupAt+0x3a:])
				if targetOffset != 0 {
					target, err = readString(descriptor + uint64(targetOffset))
					if err != nil {
						return nil, fmt.Errorf("installshield: file group target: %w", err)
					}
				}
			}
			groups = append(groups, installShieldFileGroup{name: normalizeInstallShieldPart(name), target: target, firstFile: int32(binary.LittleEndian.Uint32(data[groupAt+firstOffset:])), lastFile: int32(binary.LittleEndian.Uint32(data[groupAt+firstOffset+4:])), offset: descriptorOffset})
		}
	}
	return groups, nil
}

func parseInstallShieldComponents(data []byte, descriptor uint64, version int, readString func(uint64) (string, error)) ([]installShieldComponent, error) {
	components := make([]installShieldComponent, 0)
	seen := make(map[uint32]bool)
	for bucket := 0; bucket < 71; bucket++ {
		at := descriptor + 0x15a + uint64(bucket)*4
		if at+4 > uint64(len(data)) {
			return nil, fmt.Errorf("installshield: component buckets are truncated")
		}
		next := binary.LittleEndian.Uint32(data[at:])
		for next != 0 {
			if seen[next] {
				return nil, fmt.Errorf("installshield: cyclic component list at %#x", next)
			}
			seen[next] = true
			list := descriptor + uint64(next)
			if list+12 > uint64(len(data)) {
				return nil, fmt.Errorf("installshield: component list is out of bounds")
			}
			descriptorOffset := binary.LittleEndian.Uint32(data[list+4:])
			next = binary.LittleEndian.Uint32(data[list+8:])
			componentAt := descriptor + uint64(descriptorOffset)
			skip := uint64(0x6b)
			if version <= 5 {
				skip = 0x6c
			}
			if componentAt+4+skip+6 > uint64(len(data)) {
				return nil, fmt.Errorf("installshield: component descriptor is out of bounds")
			}
			nameOffset := binary.LittleEndian.Uint32(data[componentAt:])
			name, err := readString(descriptor + uint64(nameOffset))
			if err != nil {
				return nil, fmt.Errorf("installshield: component name: %w", err)
			}
			countAt := componentAt + 4 + skip
			count := binary.LittleEndian.Uint16(data[countAt:])
			tableOffset := binary.LittleEndian.Uint32(data[countAt+2:])
			tableAt := descriptor + uint64(tableOffset)
			if tableAt > uint64(len(data)) || uint64(count)*4 > uint64(len(data))-tableAt {
				return nil, fmt.Errorf("installshield: component file-group table is out of bounds")
			}
			groups := make([]string, count)
			for i := range groups {
				offset := binary.LittleEndian.Uint32(data[tableAt+uint64(i)*4:])
				groups[i], err = readString(descriptor + uint64(offset))
				if err != nil {
					return nil, fmt.Errorf("installshield: component file group: %w", err)
				}
				groups[i] = normalizeInstallShieldPart(groups[i])
			}
			components = append(components, installShieldComponent{name: normalizeInstallShieldPart(name), fileGroups: groups, offset: descriptorOffset})
		}
	}
	return components, nil
}

func normalizeInstallShieldPart(value string) string {
	return strings.Trim(strings.ReplaceAll(value, "\\", "/"), "/")
}

func normalizeInstallShieldPath(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = normalizeInstallShieldPart(part)
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return path.Clean("/" + strings.Join(cleaned, "/"))
}

func addInstallShieldIndex(index map[string]int, name string, value int) {
	key := strings.ToLower(normalizeInstallShieldPath(name))
	if _, exists := index[key]; !exists {
		index[key] = value
	}
}

func (a *Archive) String() string {
	return fmt.Sprintf("<installshield version=%d>", a.version)
}
func (a *Archive) Type() string         { return "installshield" }
func (a *Archive) Freeze()              {}
func (a *Archive) Truth() starlark.Bool { return starlark.True }
func (a *Archive) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", a.Type())
}
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	index, ok := a.fileIndex[strings.ToLower(normalizeInstallShieldPath(name))]
	if !ok {
		return nil, false, nil
	}
	return &Entry{archive: a, index: index}, true, nil
}
func (a *Archive) AttrNames() []string {
	return []string{"components", "entries", "files", "find", "groups", "shortcuts", "unresolved", "version"}
}
func (a *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "version":
		return starlark.MakeInt(a.version), nil
	case "files":
		values := make([]starlark.Value, len(a.files))
		for i, file := range a.files {
			values[i] = starlark.String(file.path)
		}
		return starlark.NewList(values), nil
	case "entries":
		values := make([]starlark.Value, len(a.files))
		for i, file := range a.files {
			values[i] = installShieldFileValue(file)
		}
		return starlark.NewList(values), nil
	case "groups":
		values := make([]starlark.Value, len(a.groups))
		for i, group := range a.groups {
			values[i] = starlarkStringDict(map[string]starlark.Value{"name": starlark.String(group.name), "target": starlark.String(group.target), "first_file": starlark.MakeInt(int(group.firstFile)), "last_file": starlark.MakeInt(int(group.lastFile)), "offset": starlark.MakeUint64(uint64(group.offset))})
		}
		return starlark.NewList(values), nil
	case "components":
		values := make([]starlark.Value, len(a.components))
		for i, component := range a.components {
			groups := make([]starlark.Value, len(component.fileGroups))
			for j, group := range component.fileGroups {
				groups[j] = starlark.String(group)
			}
			values[i] = starlarkStringDict(map[string]starlark.Value{"name": starlark.String(component.name), "groups": starlark.NewList(groups), "offset": starlark.MakeUint64(uint64(component.offset))})
		}
		return starlark.NewList(values), nil
	case "shortcuts":
		values := make([]starlark.Value, len(a.shortcuts))
		for index, shortcut := range a.shortcuts {
			values[index] = installShieldShortcutValue(shortcut)
		}
		return starlark.NewList(values), nil
	case "unresolved":
		values := make([]starlark.Value, 0)
		for _, file := range a.files {
			if file.dataOffset != 0 || file.expandedSize == 0 {
				continue
			}
			external, err := a.externalFile(file)
			if err != nil {
				return nil, err
			}
			if external == nil {
				values = append(values, starlark.String(file.path))
			}
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("installshield.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("installshield.find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			value, found, err := a.Get(starlark.String(name))
			if err != nil || !found {
				return starlark.None, err
			}
			return value, nil
		}), nil
	}
	return nil, nil
}

func installShieldShortcutValue(shortcut shortcut) *starlark.Dict {
	return starlarkStringDict(map[string]starlark.Value{
		"folder": starlark.String(shortcut.folder), "component": starlark.String(shortcut.component), "name": starlark.String(shortcut.name),
		"folder_root": starlark.String(shortcut.folderRoot),
		"display":     starlark.String(shortcut.display), "target": starlark.String(shortcut.target),
		"arguments": starlark.String(shortcut.arguments), "working_directory": starlark.String(shortcut.workingDir),
		"icon": starlark.String(shortcut.icon), "description": starlark.String(shortcut.description),
		"type": starlark.MakeInt(int(shortcut.shortcutType)), "icon_index": starlark.MakeInt64(int64(shortcut.iconIndex)),
		"show_command": starlark.MakeInt64(int64(shortcut.showCommand)), "flags": starlark.MakeUint64(uint64(shortcut.flags)),
	})
}

func installShieldFileValue(file fileRecord) *starlark.Dict {
	components := make([]starlark.Value, len(file.components))
	for index, component := range file.components {
		components[index] = starlark.String(component)
	}
	return starlarkStringDict(map[string]starlark.Value{
		"path": starlark.String(file.path), "name": starlark.String(file.name), "directory": starlark.String(file.directory), "group": starlark.String(file.group), "components": starlark.NewList(components),
		"size": starlark.MakeUint64(file.expandedSize), "compressed_size": starlark.MakeUint64(file.compressedSize), "external": starlark.Bool(file.dataOffset == 0), "flags": starlark.MakeInt(int(file.flags)), "volume": starlark.MakeInt(int(file.volume)),
	})
}

func starlarkStringDict(values map[string]starlark.Value) *starlark.Dict {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	dict := starlark.NewDict(len(values))
	for _, key := range keys {
		_ = dict.SetKey(starlark.String(key), values[key])
	}
	return dict
}

type Entry struct {
	archive *Archive
	index   int
	once    sync.Once
	data    []byte
	err     error
}

func (f *Entry) materialize() ([]byte, error) {
	f.once.Do(func() { f.data, f.err = f.archive.fileData(f.index) })
	return f.data, f.err
}
func (a *Archive) fileData(index int) ([]byte, error) {
	return a.fileDataLinked(index, make(map[int]bool))
}

func (a *Archive) fileDataLinked(index int, linked map[int]bool) ([]byte, error) {
	if index < 0 || index >= len(a.files) {
		return nil, fmt.Errorf("installshield: invalid file index %d", index)
	}
	if linked[index] {
		return nil, fmt.Errorf("installshield: cyclic file link at index %d", index)
	}
	linked[index] = true
	file := a.files[index]
	if file.flags&installShieldFileInvalid != 0 {
		return nil, fmt.Errorf("installshield: file %q has no cabinet data", file.path)
	}
	if file.expandedSize == 0 {
		return []byte{}, nil
	}
	if file.expandedSize > uint64(^uint(0)>>1) || file.compressedSize > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("installshield: file %q is too large", file.path)
	}
	if file.dataOffset == 0 {
		external, err := a.externalFile(file)
		if err != nil {
			return nil, err
		}
		if external == nil {
			return nil, fmt.Errorf("installshield: file %q is external and was not supplied", file.path)
		}
		if uint64(external.Size()) != file.expandedSize {
			return nil, fmt.Errorf("installshield: external file %q has size %d, want %d", file.path, external.Size(), file.expandedSize)
		}
		result := make([]byte, int(file.expandedSize))
		if _, err := io.ReadFull(io.NewSectionReader(external, 0, external.Size()), result); err != nil {
			return nil, fmt.Errorf("installshield: read external %q: %w", file.path, err)
		}
		if a.version >= 6 && file.digest != ([16]byte{}) && md5.Sum(result) != file.digest {
			return nil, fmt.Errorf("installshield: checksum mismatch for external %q", file.path)
		}
		return result, nil
	}
	if file.linkFlags&1 != 0 {
		if file.linkPrevious >= uint32(len(a.files)) || int(file.linkPrevious) == index {
			return nil, fmt.Errorf("installshield: file %q has invalid previous link", file.path)
		}
		return a.fileDataLinked(int(file.linkPrevious), linked)
	}
	volume, ok := a.volumes[file.volume]
	if !ok {
		return nil, fmt.Errorf("installshield: file %q needs missing data%d.cab", file.path, file.volume)
	}
	readSize := file.expandedSize
	if file.flags&installShieldFileCompressed != 0 {
		readSize = file.compressedSize
	}
	var encoded []byte
	if a.version == 5 {
		var readErr error
		encoded, readErr = a.readV5FileData(index, file, readSize)
		if readErr != nil {
			return nil, readErr
		}
	} else {
		if file.dataOffset > uint64(volume.Size()) || readSize > uint64(volume.Size())-file.dataOffset {
			return nil, fmt.Errorf("installshield: file %q data is out of bounds", file.path)
		}
		encoded = make([]byte, int(readSize))
		if _, err := io.ReadFull(io.NewSectionReader(volume, int64(file.dataOffset), int64(readSize)), encoded); err != nil {
			return nil, fmt.Errorf("installshield: read %q: %w", file.path, err)
		}
	}
	if file.flags&installShieldFileObfuscated != 0 {
		deobfuscateInstallShield(encoded)
	}
	var result []byte
	if file.flags&installShieldFileCompressed == 0 {
		result = encoded
	} else {
		result = make([]byte, 0, int(file.expandedSize))
		for offset := 0; offset < len(encoded); {
			if len(encoded)-offset < 2 {
				return nil, fmt.Errorf("installshield: compressed chunk header for %q is truncated", file.path)
			}
			size := int(binary.LittleEndian.Uint16(encoded[offset:]))
			offset += 2
			if size == 0 || size > len(encoded)-offset {
				return nil, fmt.Errorf("installshield: invalid compressed chunk size %d for %q", size, file.path)
			}
			reader := flate.NewReader(bytes.NewReader(encoded[offset : offset+size]))
			chunk, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
			closeErr := reader.Close()
			if err != nil {
				return nil, fmt.Errorf("installshield: decompress %q: %w", file.path, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("installshield: close decompressor for %q: %w", file.path, closeErr)
			}
			if len(chunk) > 64<<10 || uint64(len(result)+len(chunk)) > file.expandedSize {
				return nil, fmt.Errorf("installshield: expanded data for %q exceeds declared size", file.path)
			}
			result = append(result, chunk...)
			offset += size
		}
	}
	if uint64(len(result)) != file.expandedSize {
		return nil, fmt.Errorf("installshield: expanded %q to %d bytes, want %d", file.path, len(result), file.expandedSize)
	}
	if a.version >= 6 && file.digest != ([16]byte{}) && md5.Sum(result) != file.digest {
		return nil, fmt.Errorf("installshield: checksum mismatch for %q", file.path)
	}
	return result, nil
}

func (a *Archive) readV5FileData(index int, file fileRecord, readSize uint64) ([]byte, error) {
	firstVolume := file.volume
	firstHeader, err := readInstallShieldV5VolumeHeader(a.volumes[firstVolume], firstVolume)
	if err != nil {
		return nil, err
	}
	// Version 5 cabinets commonly set bit zero on files that are not split.
	// The volume boundary records are authoritative: a file is split when the
	// fragment stored for a boundary file is smaller than its logical size.
	split := false
	if uint32(index) == firstHeader.lastFileIndex && firstHeader.lastFileOffset != 0 && firstHeader.lastFileOffset != uint32(math.MaxInt32) {
		partSize := uint64(firstHeader.lastExpandedSize)
		if file.flags&installShieldFileCompressed != 0 {
			partSize = uint64(firstHeader.lastCompressedSize)
		}
		split = partSize != 0 && partSize < readSize
	}
	if !split {
		volume := a.volumes[firstVolume]
		if file.dataOffset > uint64(volume.Size()) || readSize > uint64(volume.Size())-file.dataOffset {
			return nil, fmt.Errorf("installshield: file %q data is out of bounds", file.path)
		}
		encoded := make([]byte, int(readSize))
		if _, err := io.ReadFull(io.NewSectionReader(volume, int64(file.dataOffset), int64(readSize)), encoded); err != nil {
			return nil, fmt.Errorf("installshield: read %q: %w", file.path, err)
		}
		return encoded, nil
	}

	encoded := make([]byte, 0, int(readSize))
	for volumeIndex := firstVolume; uint64(len(encoded)) < readSize; volumeIndex++ {
		volume, ok := a.volumes[volumeIndex]
		if !ok {
			return nil, fmt.Errorf("installshield: split file %q needs missing data%d.cab", file.path, volumeIndex)
		}
		header, err := readInstallShieldV5VolumeHeader(volume, volumeIndex)
		if err != nil {
			return nil, err
		}
		var offset, expandedSize, compressedSize uint32
		switch {
		case uint32(index) == header.lastFileIndex && header.lastFileOffset != 0 && header.lastFileOffset != uint32(math.MaxInt32):
			offset, expandedSize, compressedSize = header.lastFileOffset, header.lastExpandedSize, header.lastCompressedSize
		case uint32(index) == header.firstFileIndex:
			offset, expandedSize, compressedSize = header.firstFileOffset, header.firstExpandedSize, header.firstCompressedSize
		default:
			return nil, fmt.Errorf("installshield: data%d.cab has no fragment for split file %q", volumeIndex, file.path)
		}
		partSize := uint64(expandedSize)
		if file.flags&installShieldFileCompressed != 0 {
			partSize = uint64(compressedSize)
		}
		remaining := readSize - uint64(len(encoded))
		if partSize == 0 || partSize > remaining || uint64(offset) > uint64(volume.Size()) || partSize > uint64(volume.Size())-uint64(offset) {
			return nil, fmt.Errorf("installshield: invalid data%d.cab fragment for split file %q", volumeIndex, file.path)
		}
		start := len(encoded)
		encoded = append(encoded, make([]byte, int(partSize))...)
		if _, err := io.ReadFull(io.NewSectionReader(volume, int64(offset), int64(partSize)), encoded[start:]); err != nil {
			return nil, fmt.Errorf("installshield: read split file %q from data%d.cab: %w", file.path, volumeIndex, err)
		}
	}
	return encoded, nil
}

func (a *Archive) externalFile(file fileRecord) (starfile.File, error) {
	keys := []string{
		strings.ToLower(normalizeInstallShieldPath(file.directory, file.name)[1:]),
		strings.ToLower(normalizeInstallShieldPath(file.path)[1:]),
		strings.ToLower(normalizeInstallShieldPart(file.name)),
	}
	for _, key := range keys {
		matches := make([]starfile.File, 0)
		seen := make(map[string]bool)
		for _, candidate := range a.external[key] {
			if uint64(candidate.Size()) != file.expandedSize || seen[candidate.String()] {
				continue
			}
			seen[candidate.String()] = true
			matches = append(matches, candidate)
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			identical := true
			for _, candidate := range matches[1:] {
				equal, err := installShieldFilesEqual(matches[0], candidate)
				if err != nil {
					return nil, fmt.Errorf("installshield: compare external file %q: %w", file.path, err)
				}
				if !equal {
					identical = false
					break
				}
			}
			if identical {
				return matches[0], nil
			}
			return nil, fmt.Errorf("installshield: external file %q is ambiguous", file.path)
		}
	}
	return nil, nil
}

func installShieldFilesEqual(left, right starfile.File) (bool, error) {
	if left.Size() != right.Size() {
		return false, nil
	}
	const chunkSize = int64(32 << 10)
	leftReader := io.NewSectionReader(left, 0, left.Size())
	rightReader := io.NewSectionReader(right, 0, right.Size())
	leftChunk := make([]byte, chunkSize)
	rightChunk := make([]byte, chunkSize)
	for remaining := left.Size(); remaining > 0; {
		size := chunkSize
		if size > remaining {
			size = remaining
		}
		if _, err := io.ReadFull(leftReader, leftChunk[:size]); err != nil {
			return false, err
		}
		if _, err := io.ReadFull(rightReader, rightChunk[:size]); err != nil {
			return false, err
		}
		if !bytes.Equal(leftChunk[:size], rightChunk[:size]) {
			return false, nil
		}
		remaining -= size
	}
	return true, nil
}

func deobfuscateInstallShield(data []byte) {
	for index := range data {
		value := data[index] ^ 0xd5
		value = value>>2 | value<<6
		data[index] = value - byte(index%0x47)
	}
}

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	data, err := f.materialize()
	if err != nil {
		return 0, err
	}
	return bytes.NewReader(data).ReadAt(p, off)
}
func (f *Entry) WriteAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.String())
}
func (f *Entry) Size() int64 { return int64(f.archive.files[f.index].expandedSize) }
func (f *Entry) String() string {
	return fmt.Sprintf("<installshield.file %q>", f.archive.files[f.index].path)
}
func (f *Entry) Type() string         { return "file" }
func (f *Entry) Freeze()              {}
func (f *Entry) Truth() starlark.Bool { return starlark.True }
func (f *Entry) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *Entry) AttrNames() []string { return append(starfile.AttrNames(), "metadata") }
func (f *Entry) Attr(name string) (starlark.Value, error) {
	if name == "metadata" {
		return installShieldFileValue(f.archive.files[f.index]), nil
	}
	return starfile.Attr(f, name), nil
}
