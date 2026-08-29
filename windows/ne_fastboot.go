package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
)

const windowsNEFastBootMaximum = 64 << 20

type windowsNEModule struct {
	data            []byte
	ne              int
	nonresident     int
	nonresidentSize int
	segments        int
	segmentCount    int
	resources       int
	resident        int
	alignShift      uint
	flags           uint16
	autoData        uint16
}

func windowsNEFastBootBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var moduleValues starlark.Value
	overlayPath := `C:\WINDOWS\WIN100.OVL`
	maximum := windowsNEFastBootMaximum
	if err := starlark.UnpackArgs("ne_fastboot", args, kwargs, "modules", &moduleValues, "overlay_path?", &overlayPath, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("ne_fastboot: maximum must be positive")
	}
	if strings.ContainsRune(overlayPath, 0) {
		return nil, fmt.Errorf("ne_fastboot: overlay_path must not contain NUL")
	}
	iterable, ok := moduleValues.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("ne_fastboot: modules must be iterable, got %s", moduleValues.Type())
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	var modules []windowsNEModule
	var value starlark.Value
	for iterator.Next(&value) {
		file, ok := value.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("ne_fastboot: module %d is %s, want file", len(modules), value.Type())
		}
		data, err := bytesForBinaryValueLimited(file, int64(maximum))
		if err != nil {
			return nil, fmt.Errorf("ne_fastboot: module %d: %w", len(modules), err)
		}
		module, err := parseWindowsNEModule(data)
		if err != nil {
			return nil, fmt.Errorf("ne_fastboot: module %d: %w", len(modules), err)
		}
		modules = append(modules, module)
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("ne_fastboot: modules must not be empty")
	}
	binImage, overlay, err := buildWindowsNEFastBoot(modules, overlayPath, maximum)
	if err != nil {
		return nil, fmt.Errorf("ne_fastboot: %w", err)
	}
	result := starlark.NewDict(2)
	_ = result.SetKey(starlark.String("bin"), &starfile.Bytes{Name: "WIN100.BIN", Data: binImage})
	_ = result.SetKey(starlark.String("overlay"), &starfile.Bytes{Name: "WIN100.OVL", Data: overlay})
	return result, nil
}

func parseWindowsNEModule(data []byte) (windowsNEModule, error) {
	if len(data) < 64 || binary.LittleEndian.Uint16(data) != 0x5a4d {
		return windowsNEModule{}, fmt.Errorf("missing MZ header")
	}
	ne := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if ne < 64 || ne > len(data)-64 || ne&15 != 0 || binary.LittleEndian.Uint16(data[ne:]) != 0x454e {
		return windowsNEModule{}, fmt.Errorf("invalid NE header offset %d", ne)
	}
	nonresident := int(binary.LittleEndian.Uint32(data[ne+0x2c:]))
	nonresidentSize := int(binary.LittleEndian.Uint16(data[ne+0x20:]))
	segmentCount := int(binary.LittleEndian.Uint16(data[ne+0x1c:]))
	segments := ne + int(binary.LittleEndian.Uint16(data[ne+0x22:]))
	resources := ne + int(binary.LittleEndian.Uint16(data[ne+0x24:]))
	resident := ne + int(binary.LittleEndian.Uint16(data[ne+0x26:]))
	if nonresident < ne+64 || nonresident > len(data) || nonresidentSize > len(data)-nonresident {
		return windowsNEModule{}, fmt.Errorf("invalid nonresident-name table")
	}
	if segmentCount > 8192 || segments < ne+64 || segments > nonresident || segmentCount > (nonresident-segments)/8 {
		return windowsNEModule{}, fmt.Errorf("invalid segment table")
	}
	if resources < ne+64 || resources > resident || resident > nonresident {
		return windowsNEModule{}, fmt.Errorf("invalid resource table")
	}
	alignShift := uint(binary.LittleEndian.Uint16(data[ne+0x32:]))
	if alignShift == 0 {
		alignShift = 9
	}
	if alignShift < 4 || alignShift > 15 {
		return windowsNEModule{}, fmt.Errorf("unsupported alignment shift %d", alignShift)
	}
	return windowsNEModule{
		data: data, ne: ne, nonresident: nonresident, nonresidentSize: nonresidentSize,
		segments: segments, segmentCount: segmentCount, resources: resources,
		resident:   resident,
		alignShift: alignShift, flags: binary.LittleEndian.Uint16(data[ne+0x0c:]),
		autoData: binary.LittleEndian.Uint16(data[ne+0x0e:]),
	}, nil
}

func buildWindowsNEFastBoot(modules []windowsNEModule, overlayPath string, maximum int) ([]byte, []byte, error) {
	first := modules[0]
	binImage := append([]byte(nil), first.data[:first.ne]...)
	overlay := append([]byte(nil), []byte(overlayPath)...)
	overlay = append(overlay, 0)
	overlay = padWindowsNEParagraph(overlay)
	if len(overlay) > maximum {
		return nil, nil, fmt.Errorf("overlay path exceeds maximum %d", maximum)
	}
	previousHeader := -1
	firstHeader := -1

	appendBounded := func(destination *[]byte, payload []byte, label string) (int, error) {
		start := len(*destination)
		if len(payload) > maximum-start {
			return 0, fmt.Errorf("%s exceeds maximum %d", label, maximum)
		}
		*destination = append(*destination, payload...)
		*destination = padWindowsNEParagraph(*destination)
		if len(*destination) > maximum {
			return 0, fmt.Errorf("%s exceeds maximum %d", label, maximum)
		}
		return start, nil
	}

	for moduleIndex := range modules {
		module := &modules[moduleIndex]
		binImage = padWindowsNEParagraph(binImage)
		header := len(binImage)
		if firstHeader < 0 {
			firstHeader = header
		}
		if previousHeader >= 0 {
			binary.LittleEndian.PutUint32(binImage[previousHeader+8:], uint32(header/16))
		}
		if module.nonresident-module.ne > maximum-len(binImage) {
			return nil, nil, fmt.Errorf("module %d header exceeds maximum %d", moduleIndex, maximum)
		}
		binImage = append(binImage, module.data[module.ne:module.nonresident]...)
		binary.LittleEndian.PutUint32(binImage[header+8:], 0)
		binary.LittleEndian.PutUint16(binImage[header+0x32:], 4)
		binImage = padWindowsNEParagraph(binImage)

		nonresidentOffset, err := appendBounded(&overlay, module.data[module.nonresident:module.nonresident+module.nonresidentSize], "overlay")
		if err != nil {
			return nil, nil, err
		}
		binary.LittleEndian.PutUint32(binImage[header+0x2c:], uint32(nonresidentOffset/16))

		for segmentIndex := 0; segmentIndex < module.segmentCount; segmentIndex++ {
			sourceEntry := module.segments + segmentIndex*8
			targetEntry := header + (module.segments - module.ne) + segmentIndex*8
			sector := uint64(binary.LittleEndian.Uint16(module.data[sourceEntry:]))
			storedLength := binary.LittleEndian.Uint16(module.data[sourceEntry+2:])
			flags := binary.LittleEndian.Uint16(module.data[sourceEntry+4:])
			storedAllocation := binary.LittleEndian.Uint16(module.data[sourceEntry+6:])
			length := windowsNEExpandedLength(storedLength)
			allocation := windowsNEExpandedLength(storedAllocation)
			source := sector << module.alignShift
			if source > uint64(len(module.data)) || length > uint64(len(module.data))-source {
				return nil, nil, fmt.Errorf("module %d segment %d exceeds input", moduleIndex, segmentIndex+1)
			}
			relocationLength := 0
			if flags&0x0100 != 0 {
				relocation := source + length
				if relocation > uint64(len(module.data)-2) {
					return nil, nil, fmt.Errorf("module %d segment %d has truncated relocations", moduleIndex, segmentIndex+1)
				}
				count := uint64(binary.LittleEndian.Uint16(module.data[relocation:]))
				if count > (uint64(len(module.data))-relocation-2)/8 {
					return nil, nil, fmt.Errorf("module %d segment %d has invalid relocation count", moduleIndex, segmentIndex+1)
				}
				relocationLength = int(2 + count*8)
			}
			payload := module.data[int(source):int(source+length)]
			preload := flags&0x0040 != 0
			if preload {
				highFlags := flags&0xf000 != 0
				segmentNumber := uint16(segmentIndex + 1)
				if !highFlags && module.flags&0x0002 != 0 && module.autoData == segmentNumber {
					flags |= 0xf000
					highFlags = true
					binary.LittleEndian.PutUint16(binImage[targetEntry+4:], flags)
				}
				start := len(binImage)
				if len(payload) > maximum-start {
					return nil, nil, fmt.Errorf("module %d segment %d exceeds maximum %d", moduleIndex, segmentIndex+1, maximum)
				}
				binImage = append(binImage, payload...)
				if highFlags {
					if allocation < length || allocation-length > uint64(maximum-len(binImage)) {
						return nil, nil, fmt.Errorf("module %d segment %d has invalid allocation", moduleIndex, segmentIndex+1)
					}
					binImage = append(binImage, make([]byte, int(allocation-length))...)
					binary.LittleEndian.PutUint16(binImage[targetEntry+2:], storedAllocation)
				}
				if relocationLength != 0 {
					relocation := int(source + length)
					binImage = append(binImage, module.data[relocation:relocation+relocationLength]...)
				}
				binImage = padWindowsNEParagraph(binImage)
				if len(binImage) > maximum {
					return nil, nil, fmt.Errorf("bound image exceeds maximum %d", maximum)
				}
				paragraph, err := windowsNEParagraphOffset(start, "bound segment")
				if err != nil {
					return nil, nil, err
				}
				binary.LittleEndian.PutUint16(binImage[targetEntry:], paragraph)
				if highFlags {
					overlayStart, err := appendBounded(&overlay, binImage[start:], "overlay")
					if err != nil {
						return nil, nil, err
					}
					overlayParagraph, err := windowsNEParagraphOffset(overlayStart, "overlay segment")
					if err != nil {
						return nil, nil, err
					}
					binary.LittleEndian.PutUint16(binImage[targetEntry+6:], overlayParagraph)
				}
			} else {
				fullPayload := payload
				if relocationLength != 0 {
					relocation := int(source + length)
					fullPayload = append(append([]byte(nil), payload...), module.data[relocation:relocation+relocationLength]...)
				}
				start, err := appendBounded(&overlay, fullPayload, "overlay")
				if err != nil {
					return nil, nil, err
				}
				paragraph, err := windowsNEParagraphOffset(start, "overlay segment")
				if err != nil {
					return nil, nil, err
				}
				binary.LittleEndian.PutUint16(binImage[targetEntry:], paragraph)
			}
		}

		if err := bindWindowsNEResources(module, moduleIndex, header, &binImage, &overlay, maximum, appendBounded); err != nil {
			return nil, nil, err
		}
		previousHeader = header
	}

	binImage = padWindowsNEParagraph(binImage)
	if previousHeader >= 0 {
		binary.LittleEndian.PutUint32(binImage[previousHeader+8:], uint32(len(binImage)/16))
	}
	binImage = append(binImage, 0, 0)
	binImage = padWindowsNEParagraph(binImage)
	initialHeap := int(binary.LittleEndian.Uint16(binImage[firstHeader+0x10:]))
	if initialHeap > maximum-len(binImage) {
		return nil, nil, fmt.Errorf("initial heap exceeds maximum %d", maximum)
	}
	binImage = append(binImage, make([]byte, initialHeap)...)
	if len(binImage) > maximum {
		return nil, nil, fmt.Errorf("bound image exceeds maximum %d", maximum)
	}
	pages := (len(binImage) + 511) / 512
	lastPage := len(binImage) & 511
	binary.LittleEndian.PutUint16(binImage[2:], uint16(lastPage))
	binary.LittleEndian.PutUint16(binImage[4:], uint16(pages))
	return binImage, overlay, nil
}

func bindWindowsNEResources(module *windowsNEModule, moduleIndex, header int, binImage, overlay *[]byte, maximum int, appendBounded func(*[]byte, []byte, string) (int, error)) error {
	if module.resources == module.resident {
		return nil
	}
	if module.resources+2 > module.nonresident {
		return fmt.Errorf("module %d has truncated resource table", moduleIndex)
	}
	originalAlign := uint(binary.LittleEndian.Uint16(module.data[module.resources:]))
	if originalAlign < 4 || originalAlign > 15 {
		return fmt.Errorf("module %d has unsupported resource alignment %d", moduleIndex, originalAlign)
	}
	targetTable := header + module.resources - module.ne
	binary.LittleEndian.PutUint16((*binImage)[targetTable:], 4)
	cursor := module.resources + 2
	for {
		if cursor+2 > module.nonresident {
			return fmt.Errorf("module %d has unterminated resource table", moduleIndex)
		}
		typeID := binary.LittleEndian.Uint16(module.data[cursor:])
		if typeID == 0 {
			return nil
		}
		if cursor+8 > module.nonresident {
			return fmt.Errorf("module %d has truncated resource type", moduleIndex)
		}
		count := int(binary.LittleEndian.Uint16(module.data[cursor+2:]))
		cursor += 8
		if count > (module.nonresident-cursor)/12 {
			return fmt.Errorf("module %d has invalid resource count", moduleIndex)
		}
		for resourceIndex := 0; resourceIndex < count; resourceIndex++ {
			target := header + cursor - module.ne
			offsetUnits := uint64(binary.LittleEndian.Uint16(module.data[cursor:]))
			lengthUnits := uint64(binary.LittleEndian.Uint16(module.data[cursor+2:]))
			flags := binary.LittleEndian.Uint16(module.data[cursor+4:])
			source := offsetUnits << originalAlign
			length := lengthUnits << originalAlign
			if source > uint64(len(module.data)) || length > uint64(len(module.data))-source || length > uint64(maximum) {
				return fmt.Errorf("module %d resource %d exceeds input", moduleIndex, resourceIndex)
			}
			convertedLength := length >> 4
			if convertedLength > 0xffff {
				return fmt.Errorf("module %d resource %d is too large", moduleIndex, resourceIndex)
			}
			binary.LittleEndian.PutUint16((*binImage)[target+2:], uint16(convertedLength))
			payload := module.data[int(source):int(source+length)]
			if flags&0x0040 != 0 {
				start, err := appendBounded(binImage, payload, "bound resource")
				if err != nil {
					return err
				}
				paragraph, err := windowsNEParagraphOffset(start, "bound resource")
				if err != nil {
					return err
				}
				binary.LittleEndian.PutUint16((*binImage)[target:], paragraph)
				overlayStart, err := appendBounded(overlay, (*binImage)[start:], "overlay resource")
				if err != nil {
					return err
				}
				overlayParagraph, err := windowsNEParagraphOffset(overlayStart, "overlay resource")
				if err != nil {
					return err
				}
				binary.LittleEndian.PutUint16((*binImage)[target+8:], overlayParagraph)
			} else {
				start, err := appendBounded(overlay, payload, "overlay resource")
				if err != nil {
					return err
				}
				paragraph, err := windowsNEParagraphOffset(start, "overlay resource")
				if err != nil {
					return err
				}
				binary.LittleEndian.PutUint16((*binImage)[target:], paragraph)
			}
			cursor += 12
		}
	}
}

func windowsNEExpandedLength(value uint16) uint64 {
	if value == 0 {
		return 65536
	}
	return uint64(value)
}

func windowsNEParagraphOffset(offset int, label string) (uint16, error) {
	if offset < 0 || offset&15 != 0 || offset/16 > 0xffff {
		return 0, fmt.Errorf("%s offset %d cannot be represented as an NE paragraph", label, offset)
	}
	return uint16(offset / 16), nil
}

func padWindowsNEParagraph(data []byte) []byte {
	// The original Setup linker advanced over these gaps without initializing
	// them. Zero fill makes equivalent bound images deterministic and avoids
	// carrying unrelated installer memory into the final artifact.
	if remainder := len(data) & 15; remainder != 0 {
		data = append(data, make([]byte, 16-remainder)...)
	}
	return data
}
