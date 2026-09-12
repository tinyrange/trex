package ziparchive

import (
	"archive/zip"
	"bytes"
	"io/fs"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("zip", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("PK\x03\x04")) && !bytes.HasPrefix(prefix, []byte("PK\x05\x06")) && !bytes.HasPrefix(prefix, []byte("PK\x07\x08")) {
			return nil, auto.ErrNoMatch
		}
		z, err := zip.NewReader(source, source.Size())
		if err != nil {
			return nil, err
		}
		if len(z.File) > options.MaxEntries {
			return nil, auto.ErrLimit
		}
		entries := make([]auto.Entry, 0, len(z.File))
		for _, file := range z.File {
			e := auto.Entry{Name: file.Name, Kind: "file", Reader: NewEntry(file), Attributes: map[string]any{"compressed_size": file.CompressedSize64, "crc32": file.CRC32, "modified": file.Modified, "mode": file.Mode().String()}}
			if file.FileInfo().IsDir() {
				e.Kind = "directory"
				e.Reader = nil
			} else if file.Mode()&fs.ModeSymlink != 0 {
				e.Kind = "symlink"
				e.Reader = nil
			}
			entries = append(entries, e)
		}
		return auto.Tree(entries, options)
	})
}
