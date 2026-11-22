package ibmiimd

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

type Procedure struct {
	RecordOffset int64
	Entry        uint64
}

// FindProcedure recognizes the observed kind2 procedure descriptors: a
// big-endian entry pointer at+8 and a NUL-terminated EBCDIC name at+56.
// It matches the entire supplied encoded name, not a substring or code scan.
func FindProcedure(source storage.Reader, name []byte, maximumMatches int, maximumBytes int64) ([]Procedure, error) {
	if source == nil || source.Size() < 0 || maximumBytes < 0 || maximumBytes > 256<<20 || source.Size() > maximumBytes || len(name) < 1 || len(name) > 256 || bytes.IndexByte(name, 0) >= 0 || maximumMatches < 1 || maximumMatches > 1024 {
		return nil, fmt.Errorf("ibmi procedure: invalid source, name or budget")
	}
	data := make([]byte, source.Size())
	if _, err := starfile.ReadFullAt(source, data, 0); err != nil {
		return nil, err
	}
	needle := append(append([]byte(nil), name...), 0)
	var found []Procedure
	for start := 0; start < len(data); {
		at := bytes.Index(data[start:], needle)
		if at < 0 {
			break
		}
		at += start
		start = at + len(needle)
		if at < 56 || at%8 != 0 || binary.BigEndian.Uint64(data[at-56:]) != 0x0200000000000000 {
			continue
		}
		entry := binary.BigEndian.Uint64(data[at-48:])
		if entry>>32 != 0xffffffff || entry%4 != 0 {
			continue
		}
		if len(found) >= maximumMatches {
			return nil, fmt.Errorf("ibmi procedure: match budget")
		}
		found = append(found, Procedure{int64(at - 56), entry})
	}
	return found, nil
}
