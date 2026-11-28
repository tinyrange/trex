// Package pacman reads and writes the section records used by libalpm.
package pacman

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

const recordLimit = 2 << 20

type Fields map[string][]string

func versionParts(value string) (string, string, string) {
	epoch, version, ok := strings.Cut(value, ":")
	if !ok {
		epoch, version = "0", value
	}
	var release string
	if last := strings.LastIndexByte(version, '-'); last != -1 {
		version, release = version[:last], version[last+1:]
	}
	return epoch, version, release
}

func compareVersion(left, right string) int {
	e1, v1, r1 := versionParts(left)
	e2, v2, r2 := versionParts(right)
	if comparison := compareSegments(e1, e2); comparison != 0 {
		return comparison
	}
	if comparison := compareSegments(v1, v2); comparison != 0 {
		return comparison
	}
	if r1 != "" && r2 != "" {
		return compareSegments(r1, r2)
	}
	return 0
}

func digit(c byte) bool  { return c >= '0' && c <= '9' }
func letter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func segments(value string) (int, string, string) {
	i := 0
	for i < len(value) && !digit(value[i]) && !letter(value[i]) {
		i++
	}
	if i == len(value) {
		return i, "", ""
	}
	isDigit := digit(value[i])
	end := i + 1
	for end < len(value) && (isDigit && digit(value[end]) || !isDigit && letter(value[end])) {
		end++
	}
	return i, value[i:end], value[end:]
}

func compareSegments(left, right string) int {
	for left != "" && right != "" {
		skip1, first, remainder1 := segments(left)
		skip2, second, remainder2 := segments(right)
		if first == "" || second == "" {
			break
		}
		if skip1 != skip2 {
			if skip1 < skip2 {
				return -1
			}
			return 1
		}
		number1, number2 := digit(first[0]), digit(second[0])
		if number1 != number2 {
			if number1 {
				return 1
			}
			return -1
		}
		if number1 {
			first, second = strings.TrimLeft(first, "0"), strings.TrimLeft(second, "0")
			if len(first) != len(second) {
				if len(first) < len(second) {
					return -1
				}
				return 1
			}
		}
		if compare := strings.Compare(first, second); compare != 0 {
			return compare
		}
		left, right = remainder1, remainder2
	}
	if left == "" && right == "" {
		return 0
	}
	if left == "" && !letter(right[0]) || left != "" && letter(left[0]) {
		return -1
	}
	return 1
}

func readRecord(source io.Reader, pkginfo bool) (Fields, error) {
	input, err := io.ReadAll(io.LimitReader(source, recordLimit+1))
	if err != nil {
		return nil, err
	}
	if len(input) > recordLimit || bytes.IndexByte(input, 0) >= 0 {
		return nil, fmt.Errorf("pacman: invalid metadata size or content")
	}
	fields := make(Fields)
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 4096), recordLimit)
	var field string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			field = ""
			continue
		}
		if pkginfo {
			if strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, " = ")
			if !ok || key == "" || strings.ContainsAny(key, " \t\r") {
				return nil, fmt.Errorf("pacman: invalid PKGINFO field %q", key)
			}
			fields[key] = append(fields[key], value)
			continue
		}
		if field == "" {
			if len(line) < 3 || line[0] != '%' || line[len(line)-1] != '%' {
				return nil, fmt.Errorf("pacman: expected section header, got %q", line)
			}
			field = line[1 : len(line)-1]
			for _, c := range field {
				if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
					return nil, fmt.Errorf("pacman: invalid section %q", field)
				}
			}
			if _, exists := fields[field]; exists {
				return nil, fmt.Errorf("pacman: repeated section %q", field)
			}
			fields[field] = nil
			continue
		}
		fields[field] = append(fields[field], line)
	}
	return fields, scanner.Err()
}

func encodeFields(fields Fields, order []string) (string, error) {
	var result strings.Builder
	for _, name := range order {
		values := fields[name]
		if len(values) == 0 {
			continue
		}
		fmt.Fprintf(&result, "%%%s%%\n", name)
		for _, value := range values {
			if strings.ContainsAny(value, "\x00\r\n") {
				return "", fmt.Errorf("pacman: invalid line in %s", name)
			}
			fmt.Fprintln(&result, value)
		}
		result.WriteByte('\n')
		if result.Len() > recordLimit {
			return "", fmt.Errorf("pacman: installed record exceeds size limit")
		}
	}
	return result.String(), nil
}

func installedRecords(metadata Fields, paths, backups []string, explicit bool) (string, string, error) {
	for _, key := range []string{"NAME", "VERSION", "ARCH", "ISIZE"} {
		if len(metadata[key]) != 1 || metadata[key][0] == "" {
			return "", "", fmt.Errorf("pacman: missing or ambiguous %s", key)
		}
	}
	metadata["SIZE"] = metadata["ISIZE"]
	metadata["VALIDATION"] = []string{"sha256"}
	metadata["REASON"] = []string{"1"}
	if explicit {
		metadata["REASON"][0] = "0"
	}
	desc, err := encodeFields(metadata, []string{"NAME", "VERSION", "BASE", "DESC", "GROUPS", "URL", "LICENSE", "ARCH", "BUILDDATE", "PACKAGER", "SIZE", "REASON", "VALIDATION", "REPLACES", "DEPENDS", "OPTDEPENDS", "CONFLICTS", "PROVIDES"})
	if err != nil {
		return "", "", err
	}
	files, err := encodeFields(Fields{"FILES": paths, "BACKUP": backups}, []string{"FILES", "BACKUP"})
	return desc, files, err
}
