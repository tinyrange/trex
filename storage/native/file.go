package native

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cabarchive "github.com/tinyrange/trex/archive/cab"
	blockpkg "github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// RandomAccessReader is the portable read-only file contract used at binary
// format and block-device boundaries. Size must remain stable for the lifetime
// of the value.
type RandomAccessReader = storage.Reader

// RandomAccessFile is a writable RandomAccessReader.
type RandomAccessFile = storage.File

// File is trex's Starlark-visible file contract. Go integrations that do
// not need Starlark should implement RandomAccessReader or RandomAccessFile.
type File interface {
	starlark.Value
	RandomAccessFile
}

type BlockExtent = blockpkg.Extent
type blockDeviceExtenter = blockpkg.Extenter

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"open":   starlark.NewBuiltin("open", openBuiltin),
		"stdout": starlark.NewBuiltin("stdout", stdoutBuiltin),
		"write":  starlark.NewBuiltin("write", writeBuiltin),
	}
}

func readSubfileAt(base File, baseOffset, size int64, p []byte, off int64) (int, error) {
	return starfile.ReadSubfileAt(base, baseOffset, size, p, off)
}

type fileRangeWriterTo interface {
	WriteRangeTo(io.Writer, int64, int64) (int64, error)
}

func openBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("open", args, kwargs, "name", &name); err != nil {
		return nil, err
	}

	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	var metrics *lifecycle.Metrics
	if resources, err := lifecycle.ForThread(thread); err == nil {
		metrics = resources.Metrics()
	}
	return &osFile{name: name, file: file, size: info.Size(), metrics: metrics}, nil
}

const defaultFinalOutputLimit = int64(64 << 30)

func writeBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Value
	maxBytes := defaultFinalOutputLimit
	if err := starlark.UnpackArgs("write", args, kwargs, "name", &name, "value", &value, "max_bytes?", &maxBytes); err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("write: max_bytes must be positive")
	}
	if file, ok := value.(File); ok {
		if file.Size() > maxBytes {
			return nil, fmt.Errorf("write: final output size %d exceeds max_bytes %d", file.Size(), maxBytes)
		}
		if err := ensureOutputDirectory(name); err != nil {
			return nil, err
		}
		out, err := os.Create(name)
		if err != nil {
			return nil, err
		}
		if err := writeFileTo(out, file); err != nil {
			_ = out.Close()
			return nil, err
		}
		if err := out.Close(); err != nil {
			return nil, err
		}
		if resources, err := lifecycle.ForThread(thread); err == nil {
			resources.Metrics().Streamed.Add(uint64(file.Size()))
		}
		return starlark.None, nil
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("write: final output size %d exceeds max_bytes %d", len(data), maxBytes)
	}
	if err := ensureOutputDirectory(name); err != nil {
		return nil, err
	}
	if err := os.WriteFile(name, data, 0644); err != nil {
		return nil, err
	}
	if resources, err := lifecycle.ForThread(thread); err == nil {
		resources.Metrics().Streamed.Add(uint64(len(data)))
	}
	return starlark.None, nil
}

func ensureOutputDirectory(name string) error {
	if dir := filepath.Dir(name); dir != "." {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

func stdoutBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("stdout", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	if file, ok := value.(File); ok {
		if err := writeFileTo(os.Stdout, file); err != nil {
			return nil, err
		}
		return starlark.None, nil
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, err
	}
	_, err = os.Stdout.Write(data)
	return starlark.None, err
}

type osFile struct {
	name    string
	file    *os.File
	size    int64
	metrics *lifecycle.Metrics
}

func (f *osFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.file.ReadAt(p, off)
	if f.metrics != nil && n > 0 {
		f.metrics.SourceReadBytes.Add(uint64(n))
	}
	return n, err
}
func (f *osFile) WriteAt(p []byte, off int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *osFile) Size() int64          { return f.size }
func (f *osFile) String() string       { return fmt.Sprintf("<file %q>", f.name) }
func (f *osFile) Type() string         { return "file" }
func (f *osFile) Freeze()              {}
func (f *osFile) Truth() starlark.Bool { return starlark.True }
func (f *osFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *osFile) Attr(name string) (starlark.Value, error) {
	return fileAttr(f, name), nil
}
func (f *osFile) AttrNames() []string {
	return fileAttrNames()
}

func fileAttr(file File, name string) starlark.Value {
	switch name {
	case "read":
		return starlark.NewBuiltin("read", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("read", args, kwargs); err != nil {
				return nil, err
			}
			data, err := readAllFile(file)
			if err != nil {
				return nil, err
			}
			return starlark.String(string(data)), nil
		})
	case "slice":
		return starlark.NewBuiltin("slice", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			off, size, err := unpackFileSliceRange(args, kwargs, file.Size())
			if err != nil {
				return nil, err
			}
			return &sliceFile{name: fmt.Sprintf("%s[%d:%d]", file.String(), off, off+size), base: file, off: off, size: size}, nil
		})
	case "bytes":
		return starlark.NewBuiltin("bytes", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			data, err := readFileRange("bytes", file, args, kwargs)
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(data), nil
		})
	case "hex":
		return starlark.NewBuiltin("hex", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			data, err := readFileRange("hex", file, args, kwargs)
			if err != nil {
				return nil, err
			}
			return starlark.String(hex.Dump(data)), nil
		})
	case "binary":
		return starlark.NewBuiltin("binary", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			data, err := readFileRange("binary", file, args, kwargs)
			if err != nil {
				return nil, err
			}
			return starlark.String(binaryString(data)), nil
		})
	case "size":
		return starlark.MakeInt64(file.Size())
	}
	return nil
}

func fileAttrNames() []string {
	return []string{"binary", "bytes", "hex", "read", "size", "slice"}
}

func unpackFileSliceRange(args starlark.Tuple, kwargs []starlark.Tuple, fileSize int64) (int64, int64, error) {
	var offValue starlark.Int
	sizeValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("slice", args, kwargs, "off", &offValue, "size?", &sizeValue); err != nil {
		return 0, 0, err
	}
	var off int64
	if err := starlark.AsInt(offValue, &off); err != nil || off < 0 {
		return 0, 0, fmt.Errorf("slice: offset must be a non-negative 64-bit integer")
	}
	if off > fileSize {
		return 0, 0, fmt.Errorf("slice: offset exceeds file size")
	}
	size := fileSize - off
	if sizeValue != starlark.None {
		value, ok := sizeValue.(starlark.Int)
		if !ok || starlark.AsInt(value, &size) != nil || size < 0 {
			return 0, 0, fmt.Errorf("slice: size must be a non-negative 64-bit integer")
		}
	}
	if size > fileSize-off {
		size = fileSize - off
	}
	return off, size, nil
}

func unpackFileRange(name string, args starlark.Tuple, kwargs []starlark.Tuple, fileSize int64) (int64, int64, error) {
	var off int
	sizeValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs(name, args, kwargs, "off?", &off, "size?", &sizeValue); err != nil {
		return 0, 0, err
	}
	if off < 0 {
		return 0, 0, fmt.Errorf("%s: offset must be non-negative", name)
	}
	if int64(off) > fileSize {
		return 0, 0, fmt.Errorf("%s: offset exceeds file size", name)
	}
	size := fileSize - int64(off)
	if sizeValue != starlark.None {
		sizeInt, err := starlark.AsInt32(sizeValue)
		if err != nil {
			return 0, 0, fmt.Errorf("%s: got %s for size, want int", name, sizeValue.Type())
		}
		if sizeInt < 0 {
			return 0, 0, fmt.Errorf("%s: size must be non-negative", name)
		}
		size = int64(sizeInt)
	}
	if int64(off)+size > fileSize {
		size = fileSize - int64(off)
	}
	return int64(off), size, nil
}

func readFileRange(name string, file File, args starlark.Tuple, kwargs []starlark.Tuple) ([]byte, error) {
	off, size, err := unpackFileRange(name, args, kwargs, file.Size())
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	if _, err := file.ReadAt(data, off); err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}

func binaryString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	out := make([]byte, 0, len(data)*9-1)
	for i, b := range data {
		if i > 0 {
			out = append(out, ' ')
		}
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<uint(bit)) != 0 {
				out = append(out, '1')
			} else {
				out = append(out, '0')
			}
		}
	}
	return string(out)
}

type sliceFile struct {
	name string
	base File
	off  int64
	size int64
}

func (f *sliceFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	requested := len(p)
	if remaining := f.Size() - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := f.base.ReadAt(p, f.off+off)
	if err != nil {
		return n, err
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
func (f *sliceFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("%s is read-only", f.name)
}
func (f *sliceFile) Extents(off, length int64) ([]BlockExtent, error) {
	if err := validateBlockRange(f.size, off, length); err != nil {
		return nil, err
	}
	provider, ok := f.base.(blockDeviceExtenter)
	if !ok {
		return []BlockExtent{{Offset: off, Length: length, Allocated: true}}, nil
	}
	extents, err := provider.Extents(f.off+off, length)
	if err != nil {
		return nil, err
	}
	for index := range extents {
		extents[index].Offset -= f.off
	}
	return extents, nil
}

func validateBlockRange(size, off, length int64) error {
	if off < 0 || length < 0 || off > size || length > size-off {
		return blockpkg.ErrOutOfRange
	}
	return nil
}
func (f *sliceFile) Size() int64          { return f.size }
func (f *sliceFile) String() string       { return fmt.Sprintf("<file %q>", f.name) }
func (f *sliceFile) Type() string         { return "file" }
func (f *sliceFile) Freeze()              {}
func (f *sliceFile) Truth() starlark.Bool { return starlark.True }
func (f *sliceFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *sliceFile) Attr(name string) (starlark.Value, error) {
	return fileAttr(f, name), nil
}
func (f *sliceFile) AttrNames() []string { return fileAttrNames() }

func bytesForValue(value starlark.Value) ([]byte, error) {
	switch value := value.(type) {
	case File:
		return readAllFile(value)
	case starlark.String:
		return []byte(string(value)), nil
	case starlark.Bytes:
		return []byte(value), nil
	default:
		return nil, fmt.Errorf("write: got %s, want file, string, or bytes", value.Type())
	}
}

func readAllFile(file File) ([]byte, error) {
	if file.Size() < 0 {
		return nil, fmt.Errorf("read: negative file size")
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAt(data, 0); err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}

// readAllFileView returns immutable backing data when a file can provide it.
// Callers must not retain a mutable alias or change the returned bytes.
func readAllFileView(file File) ([]byte, error) {
	switch file := file.(type) {
	case *starfile.Bytes:
		return file.Data, nil
	case *cabarchive.Entry:
		return file.Bytes()
	}
	return readAllFile(file)
}

func writeFileTo(w io.Writer, file File) error {
	if file.Size() < 0 {
		return fmt.Errorf("read: negative file size")
	}
	if wt, ok := file.(io.WriterTo); ok {
		written, err := wt.WriteTo(w)
		if err != nil {
			return err
		}
		if written != file.Size() {
			return io.ErrShortWrite
		}
		return nil
	}
	return writeFileRangeTo(w, file, 0, file.Size())
}

func writeFileRangeTo(w io.Writer, file File, off, size int64) error {
	if off < 0 || size < 0 {
		return fmt.Errorf("read: negative file range")
	}
	if off > file.Size() {
		return fmt.Errorf("read: offset exceeds file size")
	}
	if off+size > file.Size() {
		size = file.Size() - off
	}
	if rwt, ok := file.(fileRangeWriterTo); ok {
		written, err := rwt.WriteRangeTo(w, off, size)
		if err != nil {
			return err
		}
		if written != size {
			return io.ErrShortWrite
		}
		return nil
	}
	if off == 0 && size == file.Size() {
		if wt, ok := file.(io.WriterTo); ok {
			written, err := wt.WriteTo(w)
			if err != nil {
				return err
			}
			if written != size {
				return io.ErrShortWrite
			}
			return nil
		}
	}
	buf := make([]byte, 128*1024)
	for done := int64(0); done < size; {
		limit := size - done
		if limit > int64(len(buf)) {
			limit = int64(len(buf))
		}
		n, err := file.ReadAt(buf[:limit], off+done)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			done += int64(n)
		}
		if err != nil {
			if err == io.EOF && done == size {
				break
			}
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func writeZerosTo(w io.Writer, size int64) (int64, error) {
	buf := make([]byte, 128*1024)
	written := int64(0)
	for written < size {
		limit := size - written
		if limit > int64(len(buf)) {
			limit = int64(len(buf))
		}
		n, err := w.Write(buf[:limit])
		written += int64(n)
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
