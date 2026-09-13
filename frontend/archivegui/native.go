package archivegui

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/tinyrange/trex/auto"
	_ "github.com/tinyrange/trex/auto/imports"
)

// NativeSource confines host access to an explicitly opened directory. File
// handles are opened on demand and bounded independently of directory size.
type NativeSource struct {
	root   *os.Root
	mu     sync.Mutex
	files  map[string]*os.File
	order  []string
	closed bool
}

func OpenDirectory(name string) (*NativeSource, *auto.Node, error) {
	r, err := os.OpenRoot(name)
	if err != nil {
		return nil, nil, err
	}
	s := &NativeSource{root: r, files: make(map[string]*os.File)}
	return s, s.directory(".", filepath.Base(name)), nil
}

func (s *NativeSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, f := range s.files {
		_ = f.Close()
	}
	s.files = nil
	return s.root.Close()
}

func (s *NativeSource) directory(rel, name string) *auto.Node {
	return auto.Directory(name, func() ([]*auto.Node, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return nil, fs.ErrClosed
		}
		f, err := s.root.Open(filepath.FromSlash(rel))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		entries, err := f.ReadDir(-1)
		if err != nil {
			return nil, err
		}
		var nodes []*auto.Node
		for _, e := range entries {
			// Do not follow links or open device nodes while browsing.
			if e.Type()&os.ModeSymlink != 0 {
				continue
			}
			child := path.Join(rel, e.Name())
			if e.IsDir() {
				nodes = append(nodes, s.directory(child, e.Name()))
				continue
			}
			info, err := e.Info()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", child, err)
			}
			if !info.Mode().IsRegular() {
				continue
			}
			r := &nativeReader{source: s, name: child, size: info.Size(), info: info}
			nodes = append(nodes, auto.Open(r, e.Name(), auto.Options{Source: &auto.SourceContext{Tree: nativeView{s, "."}, Path: child}}))
		}
		return nodes, nil
	}, auto.Options{})
}

type nativeReader struct {
	source *NativeSource
	name   string
	size   int64
	info   fs.FileInfo
}

func (r *nativeReader) Size() int64         { return r.size }
func (r *nativeReader) Modified() time.Time { return r.info.ModTime() }
func (r *nativeReader) ReadAt(p []byte, off int64) (int, error) {
	s := r.source
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, fs.ErrClosed
	}
	f := s.files[r.name]
	if f == nil {
		var err error
		f, err = s.root.Open(filepath.FromSlash(r.name))
		if err != nil {
			return 0, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return 0, err
		}
		if !os.SameFile(info, r.info) || info.Size() != r.size || !info.ModTime().Equal(r.info.ModTime()) {
			f.Close()
			return 0, fmt.Errorf("%s changed; reopen the browser", r.name)
		}
		if len(s.order) == 64 {
			_ = s.files[s.order[0]].Close()
			delete(s.files, s.order[0])
			s.order = s.order[1:]
		}
		s.files[r.name] = f
		s.order = append(s.order, r.name)
	}
	return f.ReadAt(p, off)
}

// Companion lookup stays in the raw host tree, never entering archives.
type nativeView struct {
	source *NativeSource
	rel    string
}

func (v nativeView) Entries() ([]auto.Entry, error) {
	nodes, err := v.source.directory(v.rel, "").Children()
	if err != nil {
		return nil, err
	}
	out := make([]auto.Entry, 0, len(nodes))
	for _, n := range nodes {
		e := auto.Entry{Name: n.Name(), Kind: n.Summary().Kind, Reader: n.Reader()}
		if e.Kind == "directory" {
			e.View = nativeView{v.source, path.Join(v.rel, e.Name)}
		}
		out = append(out, e)
	}
	return out, nil
}
