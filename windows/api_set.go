package windows

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// APISetValue describes one importer-specific or default host in a v6 namespace.
type APISetValue struct {
	Flags          uint32
	Importer, Host string
}
type APISetEntry struct {
	Flags, HashedLength uint32
	Name                string
	Values              []APISetValue
}
type APISetNamespace struct {
	Flags, HashFactor uint32
	Entries           []APISetEntry
}

// ParseAPISetNamespace decodes a raw v6 .apiset section. It performs no loading,
// filesystem access, host substitution or trust validation. Unknown versions
// are rejected, rather than interpreted using another generation's layout.
func ParseAPISetNamespace(data []byte) (*APISetNamespace, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("API set namespace: truncated header")
	}
	u32 := func(offset uint32) uint32 { return binary.LittleEndian.Uint32(data[offset : offset+4]) }
	if u32(0) != 6 {
		return nil, fmt.Errorf("API set namespace: unsupported version %d", u32(0))
	}
	size := u32(4)
	if size < 28 || uint64(size) > uint64(len(data)) {
		return nil, fmt.Errorf("API set namespace: invalid declared size")
	}
	data = data[:size]
	bounded := func(offset, length uint32) bool { return offset <= size && length <= size-offset }
	table := func(offset, count, width uint32) bool { return offset <= size && count <= (size-offset)/width }
	count, entryOffset, hashOffset := u32(12), u32(16), u32(20)
	if !table(entryOffset, count, 24) || count != 0 && (entryOffset < 28 || hashOffset < 28 || !table(hashOffset, count, 8)) {
		return nil, fmt.Errorf("API set namespace: truncated entry/hash table")
	}
	type span struct{ offset, length uint32 }
	texts := map[span]string{}
	stringBudget := uint64(size) * 8
	text := func(offset, length uint32) (string, error) {
		if !bounded(offset, length) || length&1 != 0 {
			return "", fmt.Errorf("API set namespace: invalid UTF-16 range")
		}
		key := span{offset, length}
		if value, ok := texts[key]; ok {
			return value, nil
		}
		if uint64(length) > stringBudget {
			return "", fmt.Errorf("API set namespace: bounded string expansion exceeded")
		}
		stringBudget -= uint64(length)
		// Contract, importer and DLL names in this bounded reader are ASCII
		// UTF-16, not arbitrary paths. Never silently replace malformed UTF-16.
		value := make([]byte, length/2)
		for i := range value {
			c := binary.LittleEndian.Uint16(data[int(offset)+2*i:])
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return "", fmt.Errorf("API set namespace: unsupported name character %#x", c)
			}
			value[i] = byte(c)
		}
		result := strings.ToLower(string(value))
		texts[key] = result
		return result, nil
	}
	result := &APISetNamespace{Flags: u32(8), HashFactor: u32(24)}
	seen := map[string]bool{}
	remainingValues := size / 20
	for index := uint32(0); index < count; index++ {
		offset := entryOffset + 24*index
		nameLength, hashedLength := u32(offset+8), u32(offset+12)
		if nameLength == 0 || hashedLength > nameLength || hashedLength&1 != 0 {
			return nil, fmt.Errorf("API set namespace: invalid contract name/hash length")
		}
		name, err := text(u32(offset+4), nameLength)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(name, "api-") && !strings.HasPrefix(name, "ext-") {
			return nil, fmt.Errorf("API set namespace: unsupported contract name %q", name)
		}
		name = canonicalAPISetModule(name)
		if seen[name] {
			return nil, fmt.Errorf("API set namespace: duplicate contract %q", name)
		}
		seen[name] = true
		valueOffset, valueCount := u32(offset+16), u32(offset+20)
		if !table(valueOffset, valueCount, 20) || valueCount > remainingValues {
			return nil, fmt.Errorf("API set namespace: truncated/excessive value table")
		}
		remainingValues -= valueCount
		entry := APISetEntry{Flags: u32(offset), HashedLength: hashedLength, Name: name}
		importers := map[string]bool{}
		for valueIndex := uint32(0); valueIndex < valueCount; valueIndex++ {
			valueAt := valueOffset + 20*valueIndex
			importer, err := text(u32(valueAt+4), u32(valueAt+8))
			if err != nil {
				return nil, err
			}
			host, err := text(u32(valueAt+12), u32(valueAt+16))
			if err != nil {
				return nil, err
			}
			// Importer selectors are exact stored basenames, not DLL load requests.
			if host != "" {
				host = canonicalAPISetModule(host)
			}
			if importers[importer] {
				return nil, fmt.Errorf("API set namespace: ambiguous host for importer %q", importer)
			}
			importers[importer] = true
			entry.Values = append(entry.Values, APISetValue{Flags: u32(valueAt), Importer: importer, Host: host})
		}
		result.Entries = append(result.Entries, entry)
	}
	indices := make(map[uint32]bool)
	var prior uint32
	for index := uint32(0); index < count; index++ {
		at := hashOffset + index*8
		hash, entryIndex := u32(at), u32(at+4)
		if entryIndex >= count || indices[entryIndex] || index > 0 && hash <= prior {
			return nil, fmt.Errorf("API set namespace: ambiguous/unsorted hash index")
		}
		indices[entryIndex] = true
		entry := result.Entries[entryIndex]
		computed := uint32(0)
		for _, c := range entry.Name[:entry.HashedLength/2] {
			computed = computed*result.HashFactor + uint32(c)
		}
		if hash != computed {
			return nil, fmt.Errorf("API set namespace: inconsistent hash index")
		}
		prior = hash
	}
	return result, nil
}

func canonicalAPISetModule(name string) string {
	name = strings.ToLower(name)
	if !strings.Contains(name, ".") {
		name += ".dll"
	}
	return name
}

// Resolve uses the namespace's hashed contract prefix (which excludes the final
// revision component), not an invented "latest" or nearest-version fallback.
// Value zero is the fallback; later values can override it for an exact importer.
func (n *APISetNamespace) Resolve(contract, importer string) (string, bool) {
	contract = canonicalAPISetModule(contract)
	stem := strings.SplitN(contract, ".", 2)[0]
	length := strings.LastIndexByte(stem, '-')
	if length < 4 {
		return "", false
	}
	if importer != "" {
		importer = canonicalAPISetModule(importer)
	}
	for _, entry := range n.Entries {
		if entry.HashedLength != uint32(length*2) || length > len(entry.Name) || entry.Name[:length] != stem[:length] {
			continue
		}
		if len(entry.Values) == 0 {
			return "", false
		}
		for _, value := range entry.Values[1:] {
			if importer != "" && value.Importer == importer {
				return value.Host, value.Host != ""
			}
		}
		return entry.Values[0].Host, entry.Values[0].Host != ""
	}
	return "", false
}
