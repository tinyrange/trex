package wise

import (
	"encoding/binary"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

var actionLanguageStrings = [...]byte{
	1, 0, 4, 2, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

var actionStaticStrings = [...]byte{
	2, 0, 1, 0, 0, 3, 0, 3, 0, 4, 3, 1, 2, 0, 0, 0,
	0, 1, 3, 0, 2, 2, 1, 1, 0, 3, 2, 0, 1, 2, 1, 0,
	0, 0, 0, 2, 0, 0, 0, 0,
}

// Sizes include the opcode itself. String fields follow the fixed bytes except
// for the separately handled event and include-script records.
var actionFixedSize = [...]byte{
	0x2b, 0, 2, 2, 2, 1, 0x13, 2, 2, 2, 3, 2, 2, 1, 0, 1,
	1, 1, 0x2b, 0, 0x0d, 2, 1, 6, 1, 2, 2, 1, 1, 1, 2, 0,
	0, 0, 0, 2, 1, 1, 0, 0,
}

type scriptAction struct {
	offset  int
	opcode  byte
	fixed   []byte
	strings []string
	file    *scriptFile
}

type scriptFile struct {
	flags       uint16
	start       uint32
	end         uint32
	expanded    uint32
	crc         uint32
	destination string
	source      string
	member      string
}

type wiseScript struct {
	file          starfile.File
	languageCount int
	payloadSize   uint32
	actions       []scriptAction
	files         []*scriptFile
}

func parseScript(file starfile.File) (*wiseScript, error) {
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("wise: read script: %w", err)
	}
	if len(data) < 64 {
		return nil, fmt.Errorf("wise: script is truncated")
	}
	cursor := 43 // Normal WiseScript header used by full 32-bit installers.
	for index := 0; index < 3; index++ {
		if _, err := readCString(data, &cursor); err != nil {
			return nil, fmt.Errorf("wise: script header string %d: %w", index, err)
		}
	}
	if cursor > len(data)-7 {
		return nil, fmt.Errorf("wise: script header metadata is truncated")
	}
	cursor += 6
	languages := int(data[cursor])
	cursor++
	if languages <= 0 || languages > 64 {
		return nil, fmt.Errorf("wise: invalid script language count %d", languages)
	}
	for cursor < len(data) {
		if data[cursor] == 0 && plausibleInstallFile(data, cursor) {
			break
		}
		start := cursor
		value, err := readCString(data, &cursor)
		if err != nil {
			return nil, fmt.Errorf("wise: script header text: %w", err)
		}
		if typicalControlString(value) {
			cursor = start
			break
		}
	}

	actions := make([]scriptAction, 0, 256)
	files := make([]*scriptFile, 0, 64)
	eventPadding := -1
	registryLong := -1
	for cursor < len(data) {
		start := cursor
		opcode := data[cursor]
		cursor++
		if int(opcode) >= len(actionFixedSize) {
			first := len(actions) - 8
			if first < 0 {
				first = 0
			}
			trail := make([]string, 0, len(actions)-first)
			for _, previous := range actions[first:] {
				trail = append(trail, fmt.Sprintf("%#x:%#x", previous.offset, previous.opcode))
			}
			snippetStart := start
			if len(actions) > first {
				snippetStart = actions[first].offset
			}
			snippetEnd := start + 64
			if snippetEnd > len(data) {
				snippetEnd = len(data)
			}
			return nil, fmt.Errorf("wise: unsupported script opcode %#x at %#x after %s; bytes %x", opcode, start, strings.Join(trail, ", "), data[snippetStart:snippetEnd])
		}
		if opcode == 0x1b {
			for cursor < len(data) && data[cursor] == opcode {
				cursor++
			}
			actions = append(actions, scriptAction{offset: start, opcode: opcode})
			continue
		}
		if opcode == 0x18 {
			if eventPadding < 0 {
				eventPadding = 0
				if cursor < len(data) && (data[cursor] == 0 || data[cursor] == 0xff) {
					eventPadding = 6
				}
			}
			if cursor > len(data)-eventPadding {
				return nil, fmt.Errorf("wise: event record at %#x is truncated", start)
			}
			fixed := append([]byte(nil), data[cursor:cursor+eventPadding]...)
			cursor += eventPadding
			actions = append(actions, scriptAction{offset: start, opcode: opcode, fixed: fixed})
			continue
		}
		if opcode == 0x0a {
			if cursor > len(data)-2 {
				return nil, fmt.Errorf("wise: registry action at %#x is truncated", start)
			}
			if registryLong < 0 {
				registryLong = 1
				if cursor <= len(data)-5 && binary.LittleEndian.Uint32(data[cursor+1:cursor+5]) == 0 {
					registryLong = 0
				}
			}
			fixed := append([]byte(nil), data[cursor:cursor+2]...)
			cursor += 2
			count := 3 + registryLong
			stringsValue := make([]string, 0, count)
			for index := 0; index < count; index++ {
				stringStart := cursor
				value, err := readCString(data, &cursor)
				if err != nil {
					return nil, fmt.Errorf("wise: registry action at %#x string %d: %w", start, index, err)
				}
				if registryLong == 1 && index == 3 && value != "" && value[0] <= 0x25 {
					cursor = stringStart
					registryLong = 0
					break
				}
				stringsValue = append(stringsValue, value)
			}
			actions = append(actions, scriptAction{offset: start, opcode: opcode, fixed: fixed, strings: stringsValue})
			continue
		}
		fixedLength := int(actionFixedSize[opcode]) - 1
		if fixedLength < 0 || cursor > len(data)-fixedLength {
			return nil, fmt.Errorf("wise: action %#x at %#x has invalid fixed size", opcode, start)
		}
		fixed := append([]byte(nil), data[cursor:cursor+fixedLength]...)
		cursor += fixedLength
		count := int(actionStaticStrings[opcode]) + int(actionLanguageStrings[opcode])*languages
		stringsValue := make([]string, 0, count)
		for index := 0; index < count; index++ {
			value, err := readCString(data, &cursor)
			if err != nil {
				return nil, fmt.Errorf("wise: action %#x at %#x string %d: %w", opcode, start, index, err)
			}
			stringsValue = append(stringsValue, value)
		}
		if opcode == 0x06 && cursor < len(data) && data[cursor] == 0 {
			fixed = append(fixed, data[cursor])
			cursor++
		}
		action := scriptAction{offset: start, opcode: opcode, fixed: fixed, strings: stringsValue}
		if opcode == 0x00 {
			if len(fixed) != 42 || len(stringsValue) < languages+2 {
				return nil, fmt.Errorf("wise: malformed install-file action at %#x", start)
			}
			entry := &scriptFile{
				flags:       binary.LittleEndian.Uint16(fixed[0:2]),
				start:       binary.LittleEndian.Uint32(fixed[2:6]),
				end:         binary.LittleEndian.Uint32(fixed[6:10]),
				expanded:    binary.LittleEndian.Uint32(fixed[14:18]),
				crc:         binary.LittleEndian.Uint32(fixed[38:42]),
				destination: stringsValue[0],
				source:      stringsValue[len(stringsValue)-1],
			}
			action.file = entry
			files = append(files, entry)
		}
		actions = append(actions, action)
	}
	return &wiseScript{file: file, languageCount: languages, payloadSize: binary.LittleEndian.Uint32(data[5:9]), actions: actions, files: files}, nil
}

func typicalControlString(value string) bool {
	if value == "" {
		return false
	}
	first := value[0]
	if first < 0x0a || first > 0x0a && first < 0x0d || first > 0x0d && first < 0x20 {
		return true
	}
	return (first == 0x0a || first == 0x0d || first > 0x20 && first <= 0x25) && len(value) == 1
}

func plausibleInstallFile(data []byte, cursor int) bool {
	if cursor < 0 || cursor > len(data)-43 || data[cursor] != 0 {
		return false
	}
	start := binary.LittleEndian.Uint32(data[cursor+3 : cursor+7])
	end := binary.LittleEndian.Uint32(data[cursor+7 : cursor+11])
	expanded := binary.LittleEndian.Uint32(data[cursor+15 : cursor+19])
	return end > start && uint64(end-start) < uint64(len(data)) && end-start < expanded
}

func readCString(data []byte, cursor *int) (string, error) {
	if *cursor < 0 || *cursor >= len(data) {
		return "", fmt.Errorf("string starts outside data")
	}
	end := *cursor
	for end < len(data) && data[end] != 0 {
		end++
	}
	if end == len(data) {
		return "", fmt.Errorf("unterminated string")
	}
	value := string(data[*cursor:end])
	*cursor = end + 1
	return value, nil
}

func (s *wiseScript) actionValues() *starlark.List {
	values := make([]starlark.Value, len(s.actions))
	for index, action := range s.actions {
		stringsValue := make([]starlark.Value, len(action.strings))
		for stringIndex, value := range action.strings {
			stringsValue[stringIndex] = starlark.String(value)
		}
		fields := starlark.StringDict{
			"offset":    starlark.MakeInt(action.offset),
			"opcode":    starlark.MakeUint(uint(action.opcode)),
			"operation": starlark.String(actionName(action.opcode)),
			"fixed":     starlark.Bytes(action.fixed),
			"strings":   starlark.NewList(stringsValue),
		}
		if action.file != nil {
			fields["source"] = starlark.String(action.file.member)
			fields["destination"] = starlark.String(action.file.destination)
			fields["expanded_size"] = starlark.MakeUint64(uint64(action.file.expanded))
			fields["crc32"] = starlark.MakeUint64(uint64(action.file.crc))
		}
		values[index] = starfile.NewRecord(fields)
	}
	return starlark.NewList(values)
}

func actionName(opcode byte) string {
	if int(opcode) < len(actionNames) {
		return actionNames[opcode]
	}
	return fmt.Sprintf("opcode_%02x", opcode)
}

var actionNames = [...]string{
	"install_file", "invalid_01", "noop", "display_message", "user_action", "edit_ini",
	"display_billboard", "execute_program", "end_block", "call_dll", "edit_registry", "delete_file",
	"if_while", "else", "invalid_0e", "start_user_action", "end_user_action", "create_directory",
	"copy_local_file", "invalid_13", "custom_dialog", "get_system_information", "get_temp_filename",
	"play_media", "new_event", "install_odbc", "configure_odbc", "include_script", "install_log_text",
	"rename", "open_close_log", "invalid_1f", "invalid_20", "invalid_21", "invalid_22", "else_if",
	"unknown_24", "unknown_25",
}

func expandWiseVariables(value string, variables map[string]string) (string, bool) {
	var expand func(string, int) (string, bool)
	expand = func(input string, depth int) (string, bool) {
		if depth >= 16 {
			return input, false
		}
		var output strings.Builder
		resolved := true
		for cursor := 0; cursor < len(input); {
			if input[cursor] != '%' {
				output.WriteByte(input[cursor])
				cursor++
				continue
			}
			if cursor+1 < len(input) && input[cursor+1] == '%' {
				output.WriteByte('%')
				cursor += 2
				continue
			}
			endRelative := strings.IndexByte(input[cursor+1:], '%')
			if endRelative < 0 {
				output.WriteString(input[cursor:])
				resolved = false
				break
			}
			end := cursor + 1 + endRelative
			name := strings.ToUpper(input[cursor+1 : end])
			replacement, found := variables[name]
			if !found {
				output.WriteString(input[cursor : end+1])
				resolved = false
			} else {
				expanded, replacementResolved := expand(replacement, depth+1)
				output.WriteString(expanded)
				resolved = resolved && replacementResolved
			}
			cursor = end + 1
		}
		return output.String(), resolved
	}
	return expand(value, 0)
}
