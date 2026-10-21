package installshield

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
)

// openStringSFX reads the launcher generation whose records are four NUL
// terminated ASCII fields (basename, relative path, version, decimal size),
// followed immediately by the payload. There is no global magic or count.
// Require a cabinet as the first record before claiming an executable.
func openStringSFX(file starfile.File, offset int64) (*sfxArchive, bool, error) {
	start := offset
	a := &sfxArchive{files: map[string]starfile.File{}}
	recognized := false
	for offset < file.Size() {
		if len(a.names) >= 65536 {
			return nil, recognized, fmt.Errorf("installshield SFX: too many records")
		}
		var fields [4]string
		for i := range fields {
			data := make([]byte, min(int64(1024), file.Size()-offset))
			if _, err := io.ReadFull(io.NewSectionReader(file, offset, int64(len(data))), data); err != nil {
				return nil, recognized, err
			}
			n := bytes.IndexByte(data, 0)
			if n <= 0 {
				if !recognized {
					return nil, false, nil
				}
				return nil, true, fmt.Errorf("installshield SFX: invalid record field")
			}
			fields[i] = string(data[:n])
			offset += int64(n + 1)
		}
		name := strings.ReplaceAll(fields[1], `\`, "/")
		size, err := strconv.ParseUint(fields[3], 10, 63)
		validVersion := true
		for _, c := range fields[2] {
			if c != '.' && (c < '0' || c > '9') {
				validVersion = false
			}
		}
		if !recognized {
			if err != nil || !validVersion || !strings.EqualFold(path.Base(name), fields[0]) || !strings.HasSuffix(strings.ToLower(name), ".cab") || file.Size()-offset < 4 {
				return nil, false, nil
			}
			var magic [4]byte
			if _, err := file.ReadAt(magic[:], offset); err != nil {
				return nil, false, err
			}
			if string(magic[:]) != "ISc(" && string(magic[:]) != "MSCF" {
				return nil, false, nil
			}
			recognized = true
		}
		if err != nil || !validVersion || !strings.EqualFold(path.Base(name), fields[0]) || strings.HasPrefix(name, "/") || strings.Contains(name, ":") || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
			return nil, true, fmt.Errorf("installshield SFX: invalid record %q", name)
		}
		if size > uint64(file.Size()-offset) {
			return nil, true, fmt.Errorf("installshield SFX: truncated payload %s", name)
		}
		key := strings.ToLower("/" + name)
		if a.files[key] != nil {
			return nil, true, fmt.Errorf("installshield SFX: duplicate file %s", name)
		}
		a.files[key] = &starfile.Slice{Name: name, Base: file, Offset: offset, Length: int64(size)}
		a.names = append(a.names, "/"+name)
		offset += int64(size)
	}
	a.size = offset - start
	return a, recognized, nil
}
