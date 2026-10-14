package darwin

import (
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"sort"
	"strings"
	"unicode/utf8"
)

// EmptyARM64NVRAM encodes an Apple CHRP v1 bank with empty variable partitions.
func EmptyARM64NVRAM(size int) ([]byte, error) {
	return ARM64NVRAM(size, nil, nil)
}

// ARM64NVRAM encodes string variables in an Apple CHRP v1 bank's common and
// system namespaces. Records are sorted name=value strings followed by NUL;
// an additional NUL terminates each partition's variable list. The two variable
// partitions divide the space equally, including their 16-byte headers.
//
// ARM64 uses little endian lengths in units of 16 bytes. The Adler checksum
// covers generation through the bank's end. These wire-format facts follow
// Apple's published IONVRAMCHRPHandler.cpp; no external tools are involved.
func ARM64NVRAM(size int, common, system map[string]string) ([]byte, error) {
	if size < 4096 || size > 65536 || size%32 != 0 {
		return nil, fmt.Errorf("NVRAM bank must be 4..64 KiB in 32-byte units")
	}
	b := make([]byte, size)
	header := func(offset, length int, name string) {
		h := b[offset : offset+16]
		h[0] = 0x70
		binary.LittleEndian.PutUint16(h[2:], uint16(length/16))
		copy(h[4:], name)
		sum := uint16(h[0])
		for _, v := range h[2:] {
			sum += uint16(v)
		}
		for sum > 255 {
			sum = (sum & 255) + (sum >> 8)
		}
		h[1] = byte(sum)
	}
	header(0, 32, "nvram")
	partitionSize := (size - 32) / 2
	for i, partition := range []struct {
		name string
		vars map[string]string
	}{{"common", common}, {"system", system}} {
		offset := 32 + i*partitionSize
		header(offset, partitionSize, partition.name)
		data := b[offset+16 : offset+partitionSize]
		if len(partition.vars) > (len(data)-1)/3 {
			return nil, fmt.Errorf("NVRAM %s: variables exceed partition capacity", partition.name)
		}
		keys := make([]string, 0, len(partition.vars))
		for key := range partition.vars {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := partition.vars[key]
			if key == "" || strings.ContainsAny(key, "=\x00") || !utf8.ValidString(key) || strings.ContainsRune(value, 0) || !utf8.ValidString(value) {
				return nil, fmt.Errorf("NVRAM %s: invalid string variable %q", partition.name, key)
			}
			// Keep both the record terminator and the empty next name. Check
			// separately to avoid overflow when given very large strings.
			if len(key) > len(data)-3 || len(value) > len(data)-3-len(key) {
				return nil, fmt.Errorf("NVRAM %s: variables exceed partition capacity", partition.name)
			}
			n := copy(data, key)
			data[n] = '='
			n += 1 + copy(data[n+1:], value)
			data = data[n+1:]
		}
	}
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint32(b[16:], adler32.Checksum(b[20:]))
	return b, nil
}
