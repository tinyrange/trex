// Package lha reads bounded in-memory LHA archives without host extraction.
package lha

import (
	"encoding/binary"
	"fmt"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
)

type Entry struct {
	Path, Method string
	Name, Header []byte
	Timestamp    uint32
	Attributes   byte
	CRC          uint16
	Data, Stored starfile.File
}
type Archive struct{ Entries []Entry }

func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0xa001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}
func Open(file starfile.File, maximumEntries int, maximumBytes int64) (*Archive, error) {
	if maximumEntries < 1 || maximumBytes < 0 {
		return nil, fmt.Errorf("lha: invalid limits")
	}
	a := &Archive{}
	seen := map[string]bool{}
	remaining := maximumBytes
	for offset := int64(0); offset < file.Size(); {
		var first [1]byte
		if _, err := starfile.ReadFullAt(file, first[:], offset); err != nil {
			return nil, err
		}
		if first[0] == 0 {
			if offset+1 != file.Size() {
				return nil, fmt.Errorf("lha: trailing archive data")
			}
			return a, nil
		}
		if len(a.Entries) >= maximumEntries {
			return nil, fmt.Errorf("lha: entry limit")
		}
		header := make([]byte, int(first[0])+2)
		if len(header) < 24 || int64(len(header)) > file.Size()-offset {
			return nil, fmt.Errorf("lha: truncated header")
		}
		if _, err := starfile.ReadFullAt(file, header, offset); err != nil {
			return nil, err
		}
		if header[20] != 0 {
			return nil, fmt.Errorf("lha: unsupported header level %d", header[20])
		}
		var sum byte
		for _, b := range header[2:] {
			sum += b
		}
		if sum != header[1] {
			return nil, fmt.Errorf("lha: header checksum mismatch")
		}
		n := int(header[21])
		if n == 0 || 24+n > len(header) {
			return nil, fmt.Errorf("lha: invalid filename length")
		}
		name := append([]byte(nil), header[22:22+n]...)
		path := strings.ReplaceAll(string(name), "\\", "/")
		for _, part := range strings.Split(path, "/") {
			if part == "" || part == "." || part == ".." || strings.ContainsRune(part, 0) {
				return nil, fmt.Errorf("lha: invalid filename")
			}
		}
		path = "/" + path
		if seen[path] {
			return nil, fmt.Errorf("lha: duplicate path")
		}
		seen[path] = true
		storedSize := int64(binary.LittleEndian.Uint32(header[7:]))
		size := int64(binary.LittleEndian.Uint32(header[11:]))
		offset += int64(len(header))
		if storedSize > file.Size()-offset || storedSize > maximumBytes || size > remaining {
			return nil, fmt.Errorf("lha: payload size or decoded limit")
		}
		stored := &starfile.Slice{Base: file, Offset: offset, Length: storedSize}
		input, err := starfile.ReadAll(stored)
		if err != nil {
			return nil, err
		}
		var data []byte
		method := string(header[2:7])
		switch method {
		case "-lh0-":
			if size != storedSize {
				return nil, fmt.Errorf("lha: stored size mismatch")
			}
			data = input
		case "-lh5-":
			if int64(int(size)) != size {
				return nil, fmt.Errorf("lha: decoded size exceeds platform range")
			}
			data, err = decodeLH5(input, int(size))
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("lha: unsupported method %q", method)
		}
		crc := binary.LittleEndian.Uint16(header[22+n:])
		if crc16(data) != crc {
			return nil, fmt.Errorf("lha: payload CRC mismatch for %q", path)
		}
		a.Entries = append(a.Entries, Entry{Path: path, Method: method, Name: name, Header: header, Timestamp: binary.LittleEndian.Uint32(header[15:]), Attributes: header[19], CRC: crc, Data: &starfile.Bytes{Data: data}, Stored: stored})
		remaining -= size
		offset += storedSize
	}
	return nil, fmt.Errorf("lha: missing end marker")
}
