package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	virtualfs "github.com/tinyrange/trex/filesystem"
	"go.starlark.net/starlark"
)

func shortcutBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var target string
	var shortTarget string
	var description string
	var arguments string
	var workingDir string
	var iconLocation string
	var iconIndex int
	var targetSize int
	var systemRoot string
	if err := starlark.UnpackArgs(
		"shortcut", args, kwargs,
		"target", &target,
		"short_target?", &shortTarget,
		"description?", &description,
		"arguments?", &arguments,
		"working_dir?", &workingDir,
		"icon_location?", &iconLocation,
		"icon_index?", &iconIndex,
		"target_size?", &targetSize,
		"system_root?", &systemRoot,
	); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("shortcut: target is empty")
	}
	data, err := buildShellLink(shellLinkOptions{
		Target:       target,
		ShortTarget:  shortTarget,
		Description:  description,
		Arguments:    arguments,
		WorkingDir:   workingDir,
		IconLocation: iconLocation,
		IconIndex:    int32(iconIndex),
		TargetSize:   uint32(targetSize),
		SystemRoot:   systemRoot,
	})
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

func internetShortcutBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url string
	var iconLocation string
	var iconIndex int
	if err := starlark.UnpackArgs(
		"internet_shortcut", args, kwargs,
		"url", &url,
		"icon_location?", &iconLocation,
		"icon_index?", &iconIndex,
	); err != nil {
		return nil, err
	}
	data, err := buildInternetShortcut(url, iconLocation, iconIndex)
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

func buildInternetShortcut(url, iconLocation string, iconIndex int) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("url is empty")
	}
	if strings.ContainsAny(url, "\x00\r\n") {
		return nil, fmt.Errorf("url contains a control character")
	}
	if strings.ContainsAny(iconLocation, "\x00\r\n") {
		return nil, fmt.Errorf("icon location contains a control character")
	}
	var output strings.Builder
	output.WriteString("[InternetShortcut]\r\nURL=")
	output.WriteString(url)
	output.WriteString("\r\n")
	if iconLocation != "" {
		output.WriteString("IconFile=")
		output.WriteString(iconLocation)
		output.WriteString("\r\nIconIndex=")
		output.WriteString(fmt.Sprintf("%d", iconIndex))
		output.WriteString("\r\n")
	}
	return []byte(output.String()), nil
}

type shellLinkOptions struct {
	Target       string
	ShortTarget  string
	Description  string
	Arguments    string
	WorkingDir   string
	IconLocation string
	IconIndex    int32
	TargetSize   uint32
	SystemRoot   string
}

func buildShellLink(opts shellLinkOptions) ([]byte, error) {
	target := strings.ReplaceAll(opts.Target, "/", `\`)
	shortTarget := strings.ReplaceAll(opts.ShortTarget, "/", `\`)
	workingDir := strings.ReplaceAll(opts.WorkingDir, "/", `\`)
	iconLocation := strings.ReplaceAll(opts.IconLocation, "/", `\`)
	if target == "" {
		return nil, fmt.Errorf("target is empty")
	}

	if workingDir == "" {
		workingDir = windowsDirname(target)
	}
	envTarget := shellLinkEnvironmentTarget(target, opts.SystemRoot)
	defaultIconLocation := iconLocation == "" || strings.EqualFold(iconLocation, target)
	if iconLocation == "" {
		iconLocation = target
	}
	if envTarget != "" && defaultIconLocation {
		iconLocation = envTarget
	}

	flags := uint32(0x00000001 | 0x00000002 | 0x00000080) // HasLinkTargetIDList | HasLinkInfo | IsUnicode
	if opts.Description != "" {
		flags |= 0x00000004 // HasName
	}
	if opts.Arguments != "" {
		flags |= 0x00000020 // HasArguments
	}
	if workingDir != "" {
		flags |= 0x00000010 // HasWorkingDir
	}
	if iconLocation != "" {
		flags |= 0x00000040 // HasIconLocation
	}
	if envTarget != "" {
		flags |= 0x00000200 // HasExpString
	}

	var out bytes.Buffer
	writeLE(&out, uint32(0x4c))
	out.Write([]byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46})
	writeLE(&out, flags)
	writeLE(&out, uint32(0))
	writeLE(&out, uint64(0))
	writeLE(&out, uint64(0))
	writeLE(&out, uint64(0))
	writeLE(&out, uint32(0))
	writeLE(&out, opts.IconIndex)
	writeLE(&out, uint32(1)) // SW_SHOWNORMAL
	writeLE(&out, uint16(0))
	writeLE(&out, uint16(0))
	writeLE(&out, uint32(0))
	writeLE(&out, uint32(0))

	idList := buildIDList(target, shortTarget, opts.TargetSize)
	writeLE(&out, uint16(len(idList)))
	out.Write(idList)

	linkInfoTarget := target
	if shortTarget != "" {
		linkInfoTarget = shortTarget
	}
	linkInfo := buildLinkInfo(linkInfoTarget)
	out.Write(linkInfo)
	if opts.Description != "" {
		writeShellLinkString(&out, opts.Description)
	}
	if workingDir != "" {
		writeShellLinkString(&out, workingDir)
	}
	if opts.Arguments != "" {
		writeShellLinkString(&out, opts.Arguments)
	}
	if iconLocation != "" {
		writeShellLinkString(&out, iconLocation)
	}
	if envTarget != "" {
		writeEnvironmentVariableDataBlock(&out, envTarget)
	}
	writeLE(&out, uint32(0)) // TerminalBlock
	return out.Bytes(), nil
}

func windowsDirname(path string) string {
	idx := strings.LastIndex(path, `\`)
	if idx <= 0 {
		return ""
	}
	return path[:idx]
}

func shellLinkEnvironmentTarget(target, systemRoot string) string {
	systemRoot = strings.TrimRight(strings.ReplaceAll(systemRoot, "/", `\`), `\`)
	if systemRoot != "" && len(target) >= len(systemRoot) && strings.EqualFold(target[:len(systemRoot)], systemRoot) {
		if len(target) == len(systemRoot) || target[len(systemRoot)] == '\\' {
			return `%SystemRoot%` + target[len(systemRoot):]
		}
	}
	if len(target) >= 3 && target[1] == ':' && target[2] == '\\' && len(systemRoot) >= 2 && strings.EqualFold(target[:2], systemRoot[:2]) {
		return `%SystemDrive%` + target[2:]
	}
	return ""
}

func buildIDList(target, shortTarget string, targetSize uint32) []byte {
	parts := strings.Split(strings.TrimPrefix(target, `C:\`), `\`)
	shortParts := strings.Split(strings.TrimPrefix(shortTarget, `C:\`), `\`)
	var out bytes.Buffer
	out.Write([]byte{
		0x14, 0x00, 0x1f, 0x00, 0xe0, 0x4f, 0xd0, 0x20,
		0xea, 0x3a, 0x69, 0x10, 0xa2, 0xd8, 0x08, 0x00,
		0x2b, 0x30, 0x30, 0x9d,
	})
	out.Write([]byte{
		0x19, 0x00, 0x23, 'C', ':', '\\', 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		shortName := ""
		if len(shortParts) == len(parts) {
			shortName = shortParts[i]
		}
		if i == len(parts)-1 {
			out.Write(fileIDListItemWithShortName(part, shortName, targetSize))
		} else {
			out.Write(directoryIDListItemWithShortName(part, shortName))
		}
	}
	writeLE(&out, uint16(0))
	return out.Bytes()
}

func directoryIDListItem(name string) []byte {
	return directoryIDListItemWithShortName(name, defaultFATShortName(name))
}

func fileIDListItem(name string, size uint32) []byte {
	return fileIDListItemWithShortName(name, defaultFATShortName(name), size)
}

func defaultFATShortName(name string) string {
	return virtualfs.DefaultFATShortName(name)
}

func directoryIDListItemWithShortName(name, shortName string) []byte {
	return fileSystemIDListItem(name, shortName, 0, 0x10, 0x31)
}

func fileIDListItemWithShortName(name, shortName string, size uint32) []byte {
	return fileSystemIDListItem(name, shortName, size, 0x20, 0x32)
}

func fileSystemIDListItem(name, shortName string, size uint32, attributes uint16, itemType byte) []byte {
	var out bytes.Buffer
	writeLE(&out, uint16(0)) // ItemIDSize, filled after the item is complete.
	out.Write([]byte{itemType, 0})
	writeLE(&out, size)
	writeLE(&out, uint32(0)) // Last-modified DOS date and time.
	writeLE(&out, attributes)
	out.WriteString(shortName)
	out.WriteByte(0)
	out.WriteByte(0)
	if out.Len()%2 != 0 {
		out.WriteByte(0)
	}

	extensionOffset := out.Len()
	var extension bytes.Buffer
	writeLE(&extension, uint16(0)) // ExtensionSize, filled below.
	extension.Write(make([]byte, 18))
	writeUTF16Z(&extension, name)
	writeLE(&extension, uint16(extensionOffset))
	extensionBytes := extension.Bytes()
	binary.LittleEndian.PutUint16(extensionBytes[0:2], uint16(len(extensionBytes)))
	out.Write(extensionBytes)

	item := out.Bytes()
	binary.LittleEndian.PutUint16(item[0:2], uint16(len(item)))
	return item
}

func writeUTF16Z(out *bytes.Buffer, value string) {
	for _, r := range utf16.Encode([]rune(value)) {
		writeLE(out, r)
	}
	writeLE(out, uint16(0))
}

func writeShellLinkString(out *bytes.Buffer, value string) {
	chars := utf16.Encode([]rune(strings.TrimRight(value, "\x00")))
	writeLE(out, uint16(len(chars)))
	for _, r := range chars {
		writeLE(out, r)
	}
}

func writeEnvironmentVariableDataBlock(out *bytes.Buffer, target string) {
	writeLE(out, uint32(0x314))
	writeLE(out, uint32(0xa0000001))
	writeFixedANSIString(out, target, 260)
	writeFixedUTF16String(out, target, 260)
}

func writeFixedANSIString(out *bytes.Buffer, value string, size int) {
	written := 0
	for i := 0; i < len(value) && written < size-1; i++ {
		ch := value[i]
		if ch < 0x20 || ch > 0x7e {
			ch = '?'
		}
		out.WriteByte(ch)
		written++
	}
	for written < size {
		out.WriteByte(0)
		written++
	}
}

func writeFixedUTF16String(out *bytes.Buffer, value string, size int) {
	chars := utf16.Encode([]rune(value))
	if len(chars) > size-1 {
		chars = chars[:size-1]
	}
	for _, r := range chars {
		writeLE(out, r)
	}
	for i := len(chars); i < size; i++ {
		writeLE(out, uint16(0))
	}
}

func buildLinkInfo(target string) []byte {
	target = strings.ReplaceAll(target, "/", `\`)

	var volumeID bytes.Buffer
	writeLE(&volumeID, uint32(0))
	writeLE(&volumeID, uint32(0x03)) // DRIVE_FIXED
	writeLE(&volumeID, uint32(0))
	writeLE(&volumeID, uint32(0x10))
	volumeID.WriteByte(0)
	volumeIDBytes := volumeID.Bytes()
	binary.LittleEndian.PutUint32(volumeIDBytes[0:4], uint32(len(volumeIDBytes)))

	headerSize := uint32(0x1c)
	volumeIDOffset := uint32(0x1c)
	localBasePathOffset := volumeIDOffset + uint32(len(volumeIDBytes))
	commonPathSuffixOffset := localBasePathOffset + uint32(len(target)+1)
	linkInfoSize := commonPathSuffixOffset + 1

	var out bytes.Buffer
	writeLE(&out, linkInfoSize)
	writeLE(&out, headerSize)
	writeLE(&out, uint32(0x01)) // VolumeIDAndLocalBasePath
	writeLE(&out, volumeIDOffset)
	writeLE(&out, localBasePathOffset)
	writeLE(&out, uint32(0))
	writeLE(&out, commonPathSuffixOffset)
	out.Write(volumeIDBytes)
	out.WriteString(target)
	out.WriteByte(0)
	out.WriteByte(0)
	return out.Bytes()
}

func writeLE(out *bytes.Buffer, value any) {
	_ = binary.Write(out, binary.LittleEndian, value)
}
