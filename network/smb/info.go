package smb

import (
	"errors"
	"hash/fnv"
	"io"
	"io/fs"
	"math"
	"strings"
	"time"
)

// wildcard implements bounded Windows wildcard matching without regexp state.
func wildcard(pattern, name string) bool {
	if pattern == "*.*" {
		pattern = "*"
	}
	p, n := []rune(strings.ToUpper(pattern)), []rune(strings.ToUpper(name))
	prev := make([]bool, len(n)+1)
	prev[0] = true
	for _, r := range p {
		next := make([]bool, len(n)+1)
		if r == '*' || r == '<' {
			next[0] = prev[0]
		}
		for j, c := range n {
			switch r {
			case '*', '<':
				next[j+1] = prev[j+1] || next[j]
			case '?', '>':
				next[j+1] = prev[j]
			case '"':
				next[j+1] = prev[j] && c == '.'
			default:
				next[j+1] = prev[j] && r == c
			}
		}
		if r == '>' || r == '"' {
			next[len(n)] = next[len(n)] || prev[len(n)]
		}
		prev = next
	}
	return prev[len(n)]
}
func identity(name string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(strings.ToUpper(name)))
	return h.Sum64()
}
func directoryEntry(info fs.FileInfo, class byte) []byte {
	name := utf16Bytes(info.Name())
	base := 0
	switch class {
	case 1:
		base = 64
	case 2:
		base = 68
	case 3:
		base = 94
	case 12:
		base = 12
	case 37:
		base = 104
	case 38:
		base = 80
	default:
		return nil
	}
	out := make([]byte, base+len(name))
	copy(out[base:], name)
	if class == 12 {
		le.PutUint32(out[8:], uint32(len(name)))
		return out
	}
	t := windowsTime(info.ModTime())
	for i := 0; i < 4; i++ {
		le.PutUint64(out[8+i*8:], t)
	}
	size := fileSize(info)
	le.PutUint64(out[40:], size)
	le.PutUint64(out[48:], (size+4095)&^4095)
	le.PutUint32(out[56:], fileAttributes(info))
	le.PutUint32(out[60:], uint32(len(name)))
	if class == 37 {
		le.PutUint64(out[96:], identity(info.Name()))
	}
	if class == 38 {
		le.PutUint64(out[72:], identity(info.Name()))
	}
	return out
}
func (s *session) queryDirectory(req *request) ([]byte, uint32) {
	if !structure(*req, 33, 32) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	h, _ := s.handle(req, 72)
	if h == nil {
		return nil, 0xc0000128
	}
	class, flags := b[2], b[3]
	switch class {
	case 1, 2, 3, 12, 37, 38:
	default:
		return nil, statusNotSupported
	}
	limit := int(le.Uint32(b[28:]))
	if limit < 1 || limit > maxIO || flags&^byte(0x13) != 0 {
		return nil, statusInvalidParameter
	}
	if flags&0x11 != 0 {
		if e := h.file.Rewind(); e != nil {
			return nil, fileStatus(e)
		}
		h.pending = nil
		h.eof = false
		h.pattern = ""
	}
	if h.pattern == "" {
		h.pattern = "*"
		if size := le.Uint16(b[26:]); size != 0 {
			p, ok := field(req.raw, uint32(le.Uint16(b[24:])), uint32(size), 96)
			if !ok || len(p) > 1024 {
				return nil, statusInvalidParameter
			}
			var e error
			h.pattern, e = utf16String(p)
			if e != nil || strings.ContainsAny(h.pattern, `\/:`) {
				return nil, statusInvalidParameter
			}
		}
	}
	var data []byte
	last := -1
	for examined := 0; examined < 65536; examined++ {
		info := h.pending
		h.pending = nil
		if info == nil {
			if h.eof {
				break
			}
			entries, e := h.file.ReadDir(1)
			if e != nil && !errors.Is(e, io.EOF) {
				return nil, fileStatus(e)
			}
			if errors.Is(e, io.EOF) {
				h.eof = true
			}
			if len(entries) == 0 {
				break
			}
			info = entries[0]
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		if _, e := SharePath(info.Name()); e != nil {
			continue
		}
		if !wildcard(h.pattern, info.Name()) {
			continue
		}
		entry := directoryEntry(info, class)
		pad := (8 - len(data)%8) % 8
		if len(data)+pad+len(entry) > limit {
			h.pending = info
			if len(data) == 0 {
				return nil, 0xc0000023
			}
			break
		}
		if last >= 0 {
			le.PutUint32(data[last:], uint32(len(data)+pad-last))
		}
		data = append(data, make([]byte, pad)...)
		last = len(data)
		data = append(data, entry...)
		if flags&2 != 0 {
			break
		}
	}
	if len(data) == 0 {
		return nil, 0x80000006
	}
	return bufferResponse(data), 0
}
func bufferResponse(data []byte) []byte {
	out := make([]byte, 8)
	le.PutUint16(out, 9)
	le.PutUint16(out[2:], 72)
	le.PutUint32(out[4:], uint32(len(data)))
	return append(out, data...)
}
func basicInfo(info fs.FileInfo) []byte {
	out := make([]byte, 40)
	for i := 0; i < 4; i++ {
		le.PutUint64(out[i*8:], windowsTime(info.ModTime()))
	}
	le.PutUint32(out[32:], fileAttributes(info))
	return out
}
func standardInfo(info fs.FileInfo, deleted bool) []byte {
	out := make([]byte, 24)
	size := fileSize(info)
	le.PutUint64(out, (size+4095)&^4095)
	le.PutUint64(out[8:], size)
	le.PutUint32(out[16:], 1)
	if deleted {
		out[20] = 1
	}
	if info.IsDir() {
		out[21] = 1
	}
	return out
}
func nameInfo(name string) []byte {
	if name == "." {
		name = ""
	}
	raw := utf16Bytes(string(rune(92)) + strings.ReplaceAll(name, "/", string(rune(92))))
	return append(le.AppendUint32(nil, uint32(len(raw))), raw...)
}
func (s *session) queryInfo(req *request) ([]byte, uint32) {
	if !structure(*req, 41, 40) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	h, id := s.handle(req, 88)
	if h == nil {
		return nil, 0xc0000128
	}
	limit := le.Uint32(b[4:])
	if limit > maxIO {
		return nil, statusInvalidParameter
	}
	info, e := h.file.Stat()
	if e != nil {
		return nil, fileStatus(e)
	}
	var out []byte
	switch b[2] {
	case 1:
		switch b[3] {
		case 4:
			out = basicInfo(info)
		case 5:
			out = standardInfo(info, h.deleted)
		case 6:
			out = le.AppendUint64(nil, le.Uint64(id[:]))
		case 7:
			out = make([]byte, 4)
		case 8:
			out = le.AppendUint32(nil, h.access)
		case 9, 48:
			out = nameInfo(h.name)
		case 14:
			out = make([]byte, 8)
		case 16, 17:
			out = make([]byte, 4)
		case 18:
			out = append(basicInfo(info), standardInfo(info, h.deleted)...)
			out = le.AppendUint64(out, le.Uint64(id[:]))
			out = le.AppendUint32(out, 0)
			out = le.AppendUint32(out, h.access)
			out = append(out, make([]byte, 16)...)
			out = append(out, nameInfo(h.name)...)
		case 22:
			out = make([]byte, 24)
			name := utf16Bytes("::$DATA")
			le.PutUint32(out[4:], uint32(len(name)))
			le.PutUint64(out[8:], fileSize(info))
			le.PutUint64(out[16:], (fileSize(info)+4095)&^4095)
			out = append(out, name...)
		case 34:
			out = make([]byte, 56)
			putFileMetadata(out, info)
		case 35:
			out = make([]byte, 8)
			le.PutUint32(out, fileAttributes(info))
		default:
			return nil, statusNotSupported
		}
	case 2:
		switch b[3] {
		case 1:
			label := utf16Bytes(s.share)
			out = make([]byte, 18)
			le.PutUint64(out, windowsTime(s.started))
			le.PutUint32(out[8:], le.Uint32(s.guid[:]))
			le.PutUint32(out[12:], uint32(len(label)))
			out = append(out, label...)
		case 3, 7:
			space, ok := s.files.(interface {
				Space() (uint64, uint64, error)
			})
			if !ok {
				return nil, statusNotSupported
			}
			total, free, e := space.Space()
			if e != nil {
				return nil, fileStatus(e)
			}
			if b[3] == 3 {
				out = make([]byte, 24)
				le.PutUint64(out, total/4096)
				le.PutUint64(out[8:], free/4096)
				le.PutUint32(out[16:], 8)
				le.PutUint32(out[20:], 512)
			} else {
				out = make([]byte, 32)
				le.PutUint64(out, total/4096)
				le.PutUint64(out[8:], free/4096)
				le.PutUint64(out[16:], free/4096)
				le.PutUint32(out[24:], 8)
				le.PutUint32(out[28:], 512)
			}
		case 4:
			out = make([]byte, 8)
			le.PutUint32(out, 7)
			le.PutUint32(out[4:], 0x10)
		case 5:
			name := utf16Bytes("NTFS")
			out = make([]byte, 12)
			le.PutUint32(out, 6)
			le.PutUint32(out[4:], 255)
			le.PutUint32(out[8:], uint32(len(name)))
			out = append(out, name...)
		case 8:
			out = make([]byte, 64)
			copy(out, s.guid[:])
		default:
			return nil, statusNotSupported
		}
	case 3:
		out = securityDescriptor(s.files.ReadOnly())
	default:
		return nil, statusNotSupported
	}
	if uint32(len(out)) > limit {
		return nil, 0xc0000023
	}
	return bufferResponse(out), 0
}
func securityDescriptor(readonly bool) []byte {
	// Authenticated users receive only the rights of this share. No guest ACL.
	owner := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0}
	user := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	acl := make([]byte, 8)
	acl[0] = 2
	le.PutUint16(acl[2:], 28)
	le.PutUint16(acl[4:], 1)
	ace := make([]byte, 8)
	le.PutUint16(ace[2:], 20)
	access := uint32(0x1f01ff)
	if readonly {
		access = 0x1200a9
	}
	le.PutUint32(ace[4:], access)
	acl = append(acl, ace...)
	acl = append(acl, user...)
	out := make([]byte, 20)
	out[0] = 1
	le.PutUint16(out[2:], 0x8004)
	le.PutUint32(out[4:], 20)
	le.PutUint32(out[8:], 20)
	le.PutUint32(out[16:], 36)
	out = append(out, owner...)
	return append(out, acl...)
}
func fromWindowsTime(v uint64) time.Time {
	return time.Unix(int64(v/10000000)-11644473600, int64(v%10000000)*100)
}
func (s *session) setInfo(req *request) ([]byte, uint32) {
	if !structure(*req, 33, 32) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	h, _ := s.handle(req, 80)
	if h == nil {
		return nil, 0xc0000128
	}
	if b[2] != 1 {
		return nil, statusNotSupported
	}
	data, ok := field(req.raw, uint32(le.Uint16(b[8:])), le.Uint32(b[4:]), 96)
	if !ok || len(data) > maxIO {
		return nil, statusInvalidParameter
	}
	var e error
	switch b[3] {
	case 4:
		if len(data) < 40 {
			return nil, statusInvalidParameter
		}
		if h.access&0x100 == 0 || s.files.ReadOnly() {
			return nil, statusAccessDenied
		}
		info, err := h.file.Stat()
		if err != nil {
			return nil, fileStatus(err)
		}
		at, mt := info.ModTime(), info.ModTime()
		a, m := le.Uint64(data[8:]), le.Uint64(data[16:])
		if a != 0 && a != math.MaxUint64 {
			at = fromWindowsTime(a)
		}
		if m != 0 && m != math.MaxUint64 {
			mt = fromWindowsTime(m)
		}
		e = h.file.SetTimes(at, mt)
	case 10:
		if len(data) < 20 || le.Uint64(data[8:]) != 0 {
			return nil, statusInvalidParameter
		}
		size := le.Uint32(data[16:])
		if size > uint32(len(data)-20) {
			return nil, statusInvalidParameter
		}
		name, err := utf16String(data[20 : 20+size])
		if err != nil {
			return nil, statusInvalidParameter
		}
		name, err = SharePath(name)
		if err != nil {
			return nil, fileStatus(err)
		}
		e = h.file.Rename(name, data[0] != 0)
		if e == nil {
			old := h.name
			for _, other := range s.handles {
				if other.name == old || strings.HasPrefix(other.name, old+"/") {
					other.name = name + strings.TrimPrefix(other.name, old)
				}
			}
		}
	case 13:
		if len(data) < 1 {
			return nil, statusInvalidParameter
		}
		e = h.file.SetDeletePending(data[0] != 0)
		if e == nil {
			h.deleted = data[0] != 0
		}
	case 19, 20:
		if len(data) < 8 || le.Uint64(data) > math.MaxInt64 {
			return nil, statusInvalidParameter
		}
		size := int64(le.Uint64(data))
		if b[3] == 19 {
			info, err := h.file.Stat()
			if err != nil {
				return nil, fileStatus(err)
			}
			if size >= info.Size() {
				if h.access&2 == 0 || s.files.ReadOnly() {
					return nil, statusAccessDenied
				}
				return []byte{2, 0}, 0
			}
		}
		e = h.file.Truncate(size)
	case 14:
		if len(data) < 8 {
			return nil, statusInvalidParameter
		} // Explicit-offset I/O does not use a shared cursor.
	default:
		return nil, statusNotSupported
	}
	if e != nil {
		return nil, fileStatus(e)
	}
	return []byte{2, 0}, 0
}
