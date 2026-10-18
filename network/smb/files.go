package smb

import (
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"math"
	"strings"
)

type openFile struct {
	file         File
	name         string
	access       uint32
	pattern      string
	pending      fs.FileInfo
	eof, deleted bool
}

func (s *session) closeFiles() {
	for id, h := range s.handles {
		h.file.Close()
		delete(s.handles, id)
	}
}
func fileStatus(e error) uint32 {
	switch {
	case e == nil:
		return 0
	case errors.Is(e, fs.ErrPermission):
		return statusAccessDenied
	case errors.Is(e, fs.ErrNotExist):
		return 0xc0000034
	case errors.Is(e, fs.ErrExist):
		return 0xc0000035
	case errors.Is(e, fs.ErrInvalid):
		return 0xc0000033
	case errors.Is(e, fs.ErrClosed):
		return 0xc0000128
	case errors.Is(e, ErrSharingViolation):
		return 0xc0000043
	case errors.Is(e, ErrDeletePending):
		return 0xc0000056
	case errors.Is(e, ErrNotDirectory):
		return 0xc0000103
	case errors.Is(e, ErrIsDirectory):
		return 0xc00000ba
	case errors.Is(e, errors.ErrUnsupported):
		return statusNotSupported
	case errors.Is(e, io.EOF):
		return 0xc0000011
	default:
		return 0xc0000185
	}
}
func (s *session) treeConnect(req *request) ([]byte, uint32) {
	if s.files == nil {
		return nil, statusBadNetworkName
	}
	if !structure(*req, 9, 8) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	p, ok := field(req.raw, uint32(le.Uint16(b[4:])), uint32(le.Uint16(b[6:])), 72)
	if !ok {
		return nil, statusInvalidParameter
	}
	name, e := utf16String(p)
	if e != nil {
		return nil, statusInvalidParameter
	}
	parts := strings.Split(name, `\`)
	if len(parts) != 4 || parts[0] != "" || parts[1] != "" || parts[2] == "" || !strings.EqualFold(parts[3], s.share) {
		return nil, statusBadNetworkName
	}
	s.tree = 1
	req.tree = 1
	out := make([]byte, 16)
	le.PutUint16(out, 16)
	out[2] = 1
	le.PutUint32(out[4:], 0x30)
	access := uint32(0x1f01ff)
	if s.files.ReadOnly() {
		access = 0x1200a9
	}
	le.PutUint32(out[12:], access)
	return out, 0
}
func (s *session) handle(req *request, offset int) (*openFile, [16]byte) {
	var id [16]byte
	if offset < 64 || offset > len(req.raw)-16 {
		return nil, id
	}
	copy(id[:], req.raw[offset:offset+16])
	if id == [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255} && req.flags&flagRelated != 0 {
		id = s.related
	}
	return s.handles[id], id
}
func (s *session) fileCommand(req *request) ([]byte, uint32) {
	if s.files == nil || s.tree == 0 || req.tree != s.tree {
		return nil, 0xc00000c9
	}
	switch req.command {
	case 4:
		if !structure(*req, 4, 4) {
			return nil, statusInvalidParameter
		}
		s.closeFiles()
		s.tree = 0
		return []byte{4, 0, 0, 0}, 0
	case 5:
		return s.create(req)
	case 6:
		if !structure(*req, 24, 24) {
			return nil, statusInvalidParameter
		}
		h, id := s.handle(req, 72)
		if h == nil {
			return nil, 0xc0000128
		}
		info, e := h.file.Stat()
		out := make([]byte, 60)
		le.PutUint16(out, 60)
		if e == nil && le.Uint16(req.raw[66:])&1 != 0 {
			le.PutUint16(out[2:], 1)
			putFileMetadata(out[8:], info)
		}
		e = h.file.Close()
		delete(s.handles, id)
		return out, fileStatus(e)
	case 7:
		if !structure(*req, 24, 24) {
			return nil, statusInvalidParameter
		}
		h, _ := s.handle(req, 72)
		if h == nil {
			return nil, 0xc0000128
		}
		return []byte{4, 0, 0, 0}, fileStatus(h.file.Sync())
	case 8:
		return s.read(req)
	case 9:
		return s.write(req)
	case 11:
		return s.ioctl(req)
	case 14:
		return s.queryDirectory(req)
	case 15:
		if !structure(*req, 32, 32) {
			return nil, statusInvalidParameter
		}
		h, _ := s.handle(req, 72)
		if h == nil {
			return nil, 0xc0000128
		}
		return nil, statusNotSupported // No fabricated pending watch or rescan loop.
	case 16:
		return s.queryInfo(req)
	case 17:
		return s.setInfo(req)
	default:
		return nil, statusNotSupported
	}
}
func desiredAccess(a uint32, readonly bool) uint32 {
	if a&0x80000000 != 0 {
		a = a&^0x80000000 | 0x120089
	}
	if a&0x40000000 != 0 {
		a = a&^0x40000000 | 0x120116
	}
	if a&0x20000000 != 0 {
		a = a&^0x20000000 | 0x1200a0
	}
	if a&0x10000000 != 0 {
		a = a&^0x10000000 | 0x1f01ff
	}
	if a&0x02000000 != 0 {
		a &^= 0x02000000
		if readonly {
			a |= 0x1200a9
		} else {
			a |= 0x1f01ff
		}
	}
	return a
}
func (s *session) create(req *request) (result []byte, status uint32) {
	if !structure(*req, 57, 56) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	var raw []byte
	if le.Uint16(b[46:]) != 0 {
		var ok bool
		raw, ok = field(req.raw, uint32(le.Uint16(b[44:])), uint32(le.Uint16(b[46:])), 120)
		if !ok {
			return nil, statusInvalidParameter
		}
	}
	name, e := utf16String(raw)
	if e != nil {
		return nil, statusInvalidParameter
	}
	name, e = SharePath(name)
	if e != nil {
		return nil, fileStatus(e)
	}
	// Contexts are bounded and checked even when optional extensions are ignored.
	if size := le.Uint32(b[52:]); size != 0 {
		contexts, ok := field(req.raw, le.Uint32(b[48:]), size, 120)
		if !ok {
			return nil, statusInvalidParameter
		}
		for count := 0; ; count++ {
			if count >= 32 || len(contexts) < 16 {
				return nil, statusInvalidParameter
			}
			next := int(le.Uint32(contexts))
			length := len(contexts)
			if next != 0 {
				if next < 16 || next%8 != 0 || next > len(contexts)-16 {
					return nil, statusInvalidParameter
				}
				length = next
			}
			if _, ok := field(contexts[:length], uint32(le.Uint16(contexts[4:])), uint32(le.Uint16(contexts[6:])), 16); !ok {
				return nil, statusInvalidParameter
			}
			if n := le.Uint32(contexts[12:]); n != 0 {
				if _, ok := field(contexts[:length], uint32(le.Uint16(contexts[10:])), n, 16); !ok {
					return nil, statusInvalidParameter
				}
			}
			if next == 0 {
				break
			}
			contexts = contexts[next:]
		}
	}
	if len(s.handles) >= 256 {
		return nil, 0xc000011f
	}
	access := desiredAccess(le.Uint32(b[24:]), s.files.ReadOnly())
	opts := le.Uint32(b[40:])
	if s.traceCreate != nil {
		defer func() {
			s.traceCreate(CreateTrace{Root: name == ".", Access: access, Share: le.Uint32(b[32:]), Disposition: le.Uint32(b[36:]), Options: opts, Status: status, OpenHandles: len(s.handles)})
		}()
	}
	if opts&0x00012000 != 0 {
		return nil, statusNotSupported
	}
	o := OpenOptions{Share: Access(le.Uint32(b[32:])), Disposition: le.Uint32(b[36:]), Directory: opts&1 != 0, NonDirectory: opts&0x40 != 0, DeleteOnClose: opts&0x1000 != 0, AppendOnly: access&4 != 0 && access&2 == 0}
	if le.Uint32(b[32:]) > 7 {
		return nil, statusInvalidParameter
	}
	if access&0x21 != 0 {
		o.Access |= AccessRead
	}
	if access&6 != 0 {
		o.Access |= AccessWrite
	}
	if access&0x10000 != 0 {
		o.Access |= AccessDelete
	}
	if access&0x110 != 0 {
		o.Access |= AccessMetadataWrite
	}
	f, action, e := s.files.Open(name, o)
	if e != nil {
		return nil, fileStatus(e)
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, fileStatus(e)
	}
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		f.Close()
		return nil, statusNotSupported
	}
	if s.handles == nil {
		s.handles = make(map[[16]byte]*openFile)
	}
	s.handles[id] = &openFile{file: f, name: name, access: access, deleted: o.DeleteOnClose}
	s.related = id
	out := make([]byte, 88)
	le.PutUint16(out, 89)
	le.PutUint32(out[4:], action)
	putFileMetadata(out[8:], info)
	copy(out[64:80], id[:])
	return out, 0
}
func fileAttributes(info fs.FileInfo) uint32 {
	if info.IsDir() {
		return 0x10
	}
	if info.Mode().Perm()&0222 == 0 {
		return 0x21
	}
	return 0x20
}
func fileSize(info fs.FileInfo) uint64 {
	if info.IsDir() || info.Size() < 0 {
		return 0
	}
	return uint64(info.Size())
}
func putFileMetadata(b []byte, info fs.FileInfo) {
	t := windowsTime(info.ModTime())
	for i := 0; i < 4; i++ {
		le.PutUint64(b[i*8:], t)
	}
	size := fileSize(info)
	le.PutUint64(b[32:], (size+4095)&^4095)
	le.PutUint64(b[40:], size)
	le.PutUint32(b[48:], fileAttributes(info))
}
func (s *session) read(req *request) ([]byte, uint32) {
	if !structure(*req, 49, 48) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	h, _ := s.handle(req, 80)
	if h == nil {
		return nil, 0xc0000128
	}
	size, offset := le.Uint32(b[4:]), le.Uint64(b[8:])
	if size > maxIO || offset > math.MaxInt64 || le.Uint32(b[36:]) != 0 {
		return nil, statusInvalidParameter
	}
	data := make([]byte, int(size))
	n, e := h.file.ReadAt(data, int64(offset))
	if e != nil && !(errors.Is(e, io.EOF) && n > 0) {
		return nil, fileStatus(e)
	}
	if n < int(le.Uint32(b[32:])) {
		return nil, 0xc0000011
	}
	out := make([]byte, 16)
	le.PutUint16(out, 17)
	out[2] = 80
	le.PutUint32(out[4:], uint32(n))
	return append(out, data[:n]...), 0
}
func (s *session) write(req *request) ([]byte, uint32) {
	if !structure(*req, 49, 48) {
		return nil, statusInvalidParameter
	}
	b := req.raw[64:]
	h, _ := s.handle(req, 80)
	if h == nil {
		return nil, 0xc0000128
	}
	size, offset := le.Uint32(b[4:]), le.Uint64(b[8:])
	if size > maxIO || offset > math.MaxInt64 || le.Uint32(b[32:]) != 0 {
		return nil, statusInvalidParameter
	}
	data, ok := field(req.raw, uint32(le.Uint16(b[2:])), size, 112)
	if !ok {
		return nil, statusInvalidParameter
	}
	n, e := h.file.WriteAt(data, int64(offset))
	if e != nil {
		return nil, fileStatus(e)
	}
	if le.Uint32(b[44:])&1 != 0 {
		if e := h.file.Sync(); e != nil {
			return nil, fileStatus(e)
		}
	}
	out := make([]byte, 16)
	le.PutUint16(out, 17)
	le.PutUint32(out[4:], uint32(n))
	return out, 0
}
func (s *session) ioctl(req *request) ([]byte, uint32) {
	if !structure(*req, 57, 56) {
		return nil, statusInvalidParameter
	}
	return nil, statusNotSupported
}
