// Package native implements SMB storage using a confined native directory.
package native

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/network/smb"
)

// Root is a share rooted at the directory opened by OpenRoot, not at the
// process's later working directory. Open handles and metadata operations are
// serialized so share permissions cannot race other SMB clients.
type Root struct {
	mu               sync.Mutex
	root             *os.Root
	readonly, closed bool
	handles          map[*file]bool
}
type object struct {
	deleteName string
	info       fs.FileInfo
	refs       int
	pending    bool
}
type file struct {
	name    string
	root    *Root
	file    *os.File
	object  *object
	options smb.OpenOptions
	closed  bool
}

var _ smb.FileSystem = (*Root)(nil)
var _ smb.File = (*file)(nil)

func OpenRoot(path string, readOnly bool) (*Root, error) {
	if !supportedHost {
		return nil, errors.ErrUnsupported
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &Root{root: r, readonly: readOnly, handles: make(map[*file]bool)}, nil
}
func (r *Root) ReadOnly() bool { return r.readonly }
func validName(name string) bool {
	if name == "." {
		return true
	}
	clean, err := smb.SharePath(name)
	return err == nil && clean == name
}
func (r *Root) resolve(name string) (string, error) {
	if !validName(name) {
		return "", fs.ErrInvalid
	}
	if name == "." {
		return name, nil
	}
	parts := strings.Split(name, "/")
	parent := "."
	for i, part := range parts {
		candidate := parent + "/" + part
		info, err := r.root.Lstat(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			d, e := r.root.OpenFile(parent, os.O_RDONLY|safeOpenFlags, 0)
			if e != nil {
				return "", e
			}
			found := ""
			for {
				entries, e := d.ReadDir(128)
				for _, entry := range entries {
					if strings.EqualFold(entry.Name(), part) {
						if found != "" {
							d.Close()
							return "", fs.ErrInvalid
						}
						found = entry.Name()
					}
				}
				if e == io.EOF {
					break
				}
				if e != nil {
					d.Close()
					return "", e
				}
			}
			d.Close()
			if found == "" {
				if i == len(parts)-1 {
					return candidate, nil
				}
				return "", fs.ErrNotExist
			}
			candidate = parent + "/" + found
			info, err = r.root.Lstat(candidate)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fs.ErrPermission
		}
		if i < len(parts)-1 && !info.IsDir() {
			return "", smb.ErrNotDirectory
		}
		parent = candidate
	}
	return parent, nil
}

// Metadata-only opens do not participate in data sharing checks, in either
// direction. Explorer probes a volume with READ_ATTRIBUTES|SYNCHRONIZE and
// ShareAccess=0 while a directory enumeration handle is still open.
func sharingConflict(a, b smb.OpenOptions) bool {
	const data = smb.AccessRead | smb.AccessWrite | smb.AccessDelete
	if a.Access&data == 0 || b.Access&data == 0 {
		return false
	}
	return a.Access&data & ^b.Share != 0 || b.Access&data & ^a.Share != 0
}

func (r *Root) Open(name string, o smb.OpenOptions) (smb.File, uint32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, 0, fs.ErrClosed
	}
	if len(r.handles) >= 256 {
		return nil, 0, smb.ErrSharingViolation
	}
	if o.Disposition > smb.OverwriteIf || o.Access & ^smb.Access(15) != 0 || o.Share & ^smb.Access(7) != 0 || (o.Directory && o.NonDirectory) {
		return nil, 0, fs.ErrInvalid
	}
	if o.DeleteOnClose && o.Access&smb.AccessDelete == 0 {
		return nil, 0, fs.ErrPermission
	}
	if r.readonly && (o.Access&(smb.AccessWrite|smb.AccessDelete|smb.AccessMetadataWrite) != 0 || o.DeleteOnClose) {
		return nil, 0, fs.ErrPermission
	}
	path, err := r.resolve(name)
	if err != nil {
		return nil, 0, err
	}
	info, err := r.root.Lstat(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, 0, err
	}
	if exists && !info.Mode().IsRegular() && !info.IsDir() {
		return nil, 0, fs.ErrPermission
	}
	if !exists && (o.Disposition == smb.OpenExisting || o.Disposition == smb.Overwrite) {
		return nil, 0, fs.ErrNotExist
	}
	if exists && o.Disposition == smb.CreateNew {
		return nil, 0, fs.ErrExist
	}
	truncate := exists && (o.Disposition == smb.Supersede || o.Disposition == smb.Overwrite || o.Disposition == smb.OverwriteIf)
	if (!exists || truncate) && r.readonly {
		return nil, 0, fs.ErrPermission
	}
	if truncate && o.Access&smb.AccessWrite == 0 {
		return nil, 0, fs.ErrPermission
	}
	if exists && o.Directory && !info.IsDir() {
		return nil, 0, smb.ErrNotDirectory
	}
	if exists && (o.NonDirectory || truncate) && info.IsDir() {
		return nil, 0, smb.ErrIsDirectory
	}
	if path == "." && o.DeleteOnClose {
		return nil, 0, fs.ErrPermission
	}
	var obj *object
	if exists {
		for h := range r.handles {
			if !os.SameFile(info, h.object.info) {
				continue
			}
			obj = h.object
			if obj.pending {
				return nil, 0, smb.ErrDeletePending
			}
			if sharingConflict(o, h.options) {
				return nil, 0, smb.ErrSharingViolation
			}
		}
	}
	created := false
	if !exists && o.Directory {
		if err := r.root.Mkdir(path, 0777); err != nil {
			return nil, 0, err
		}
		created = true
	}
	flags := os.O_RDONLY | safeOpenFlags
	if o.Access&smb.AccessWrite != 0 && !o.Directory {
		flags = os.O_RDWR | safeOpenFlags
	}
	if !exists && !o.Directory {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := r.root.OpenFile(path, flags, 0666)
	if err != nil {
		return nil, 0, err
	}
	info, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	if (!info.Mode().IsRegular() && !info.IsDir()) || (o.Directory && !info.IsDir()) || (o.NonDirectory && info.IsDir()) {
		f.Close()
		return nil, 0, fs.ErrPermission
	}
	// Recheck identity and share permissions after opening, before truncation.
	for h := range r.handles {
		if !os.SameFile(info, h.object.info) {
			continue
		}
		obj = h.object
		if obj.pending {
			f.Close()
			return nil, 0, smb.ErrDeletePending
		}
		if sharingConflict(o, h.options) {
			f.Close()
			return nil, 0, smb.ErrSharingViolation
		}
	}
	if obj != nil && !os.SameFile(info, obj.info) {
		obj = nil
	}
	if truncate {
		if err := f.Truncate(0); err != nil {
			f.Close()
			return nil, 0, err
		}
	}
	if obj == nil {
		obj = &object{info: info}
	}
	obj.refs++
	if o.DeleteOnClose {
		obj.pending = true
		obj.deleteName = path
	}
	h := &file{name: path, root: r, file: f, object: obj, options: o}
	r.handles[h] = true
	action := uint32(1) // FILE_OPENED
	if !exists || created {
		action = 2
	} else if truncate {
		action = 3
		if o.Disposition == smb.Supersede {
			action = 0
		}
	}
	return h, action, nil
}
func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	for h := range r.handles {
		result = errors.Join(result, h.closeLocked())
	}
	return errors.Join(result, r.root.Close())
}
func (f *file) check(access smb.Access) error {
	if f.closed || f.root.closed {
		return fs.ErrClosed
	}
	if f.options.Access&access != access {
		return fs.ErrPermission
	}
	if access&(smb.AccessWrite|smb.AccessDelete|smb.AccessMetadataWrite) != 0 && f.root.readonly {
		return fs.ErrPermission
	}
	return nil
}
func (f *file) Stat() (fs.FileInfo, error) {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(0); e != nil {
		return nil, e
	}
	return f.file.Stat()
}
func (f *file) ReadAt(b []byte, off int64) (int, error) {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessRead); e != nil {
		return 0, e
	}
	return f.file.ReadAt(b, off)
}
func (f *file) WriteAt(b []byte, off int64) (int, error) {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessWrite); e != nil {
		return 0, e
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if f.options.AppendOnly {
		info, e := f.file.Stat()
		if e != nil {
			return 0, e
		}
		off = info.Size()
	}
	return f.file.WriteAt(b, off)
}
func (f *file) Truncate(size int64) error {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessWrite); e != nil {
		return e
	}
	if size < 0 || f.options.AppendOnly {
		return fs.ErrPermission
	}
	return f.file.Truncate(size)
}
func (f *file) Sync() error {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(0); e != nil {
		return e
	}
	return f.file.Sync()
}
func (f *file) ReadDir(count int) ([]fs.FileInfo, error) {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessRead); e != nil {
		return nil, e
	}
	if count < 1 || count > 128 {
		return nil, fs.ErrInvalid
	}
	return f.file.Readdir(count)
}
func (f *file) Rewind() error {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessRead); e != nil {
		return e
	}
	_, e := f.file.Seek(0, 0)
	return e
}
func (f *file) current() error { return f.matches(f.name) }
func (f *file) matches(name string) error {
	info, e := f.root.root.Lstat(name)
	if e != nil {
		return e
	}
	if !os.SameFile(info, f.object.info) {
		return fs.ErrNotExist
	}
	return nil
}
func (f *file) SetTimes(access, modified time.Time) error {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessMetadataWrite); e != nil {
		return e
	}
	if e := f.current(); e != nil {
		return e
	}
	return f.root.root.Chtimes(f.name, access, modified)
}
func (f *file) SetDeletePending(pending bool) error {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessDelete); e != nil {
		return e
	}
	if f.name == "." {
		return fs.ErrPermission
	}
	for h := range f.root.handles {
		if h != f && h.object == f.object && h.options.Share&smb.AccessDelete == 0 {
			return smb.ErrSharingViolation
		}
	}
	if e := f.current(); e != nil {
		return e
	}
	f.object.pending = pending
	if pending {
		f.object.deleteName = f.name
	}
	return nil
}
func (f *file) Rename(name string, replace bool) error {
	f.root.mu.Lock()
	defer f.root.mu.Unlock()
	if e := f.check(smb.AccessDelete); e != nil {
		return e
	}
	if f.name == "." || name == "." {
		return fs.ErrPermission
	}
	if e := f.current(); e != nil {
		return e
	}
	for h := range f.root.handles {
		if h != f && h.object == f.object && h.options.Share&smb.AccessDelete == 0 {
			return smb.ErrSharingViolation
		}
	}
	target, e := f.root.resolve(name)
	if e != nil {
		return e
	}
	// A case-only rename resolves to the existing spelling. Preserve the
	// requested final component, but only after identifying the same path.
	sameName := target == f.name
	if sameName {
		base := name[strings.LastIndex(name, "/")+1:]
		target = target[:strings.LastIndex(target, "/")+1] + base
		if target == f.name {
			return nil
		}
	}
	info, e := f.root.root.Lstat(target)
	if e == nil && !sameName {
		if !replace {
			return fs.ErrExist
		}
		for h := range f.root.handles {
			if os.SameFile(info, h.object.info) {
				return smb.ErrSharingViolation
			}
		}
	} else if e != nil && !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	for h := range f.root.handles {
		if strings.HasPrefix(h.name, f.name+"/") && h.options.Share&smb.AccessDelete == 0 {
			return smb.ErrSharingViolation
		}
	}
	if e := f.root.root.Rename(f.name, target); e != nil {
		return e
	}
	old := f.name
	for h := range f.root.handles {
		if h.name == old || strings.HasPrefix(h.name, old+"/") {
			h.name = target + strings.TrimPrefix(h.name, old)
		}
		if h.object.deleteName == old || strings.HasPrefix(h.object.deleteName, old+"/") {
			h.object.deleteName = target + strings.TrimPrefix(h.object.deleteName, old)
		}
	}
	return nil
}
func (f *file) closeLocked() error {
	if f.closed {
		return nil
	}
	f.closed = true
	delete(f.root.handles, f)
	f.object.refs--
	result := f.file.Close()
	if f.object.refs == 0 && f.object.pending {
		if e := f.matches(f.object.deleteName); e == nil {
			result = errors.Join(result, f.root.root.Remove(f.object.deleteName))
		} else if e != nil && !errors.Is(e, fs.ErrNotExist) {
			result = errors.Join(result, e)
		}
	}
	return result
}
func (f *file) Close() error { f.root.mu.Lock(); defer f.root.mu.Unlock(); return f.closeLocked() }
