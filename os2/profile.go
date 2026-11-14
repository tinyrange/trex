// Package os2 provides native OS/2 installed-state construction.
package os2

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Entry stores uninterpreted profile value bytes. String values include their
// terminating NUL. Application/key names are case-sensitive, as in OS/2 Prf*.
type Entry struct {
	Application, Key string
	Data             []byte
}

// Profile serializes the linked application/key format consumed by OS/2 PM.
// Layout reference: XWorkplace helpers include/helpers/xprf.h INIFILE_*.
// Implementation is independent; no XWorkplace implementation code is used.
func Profile(entries []Entry) ([]byte, error) {
	var apps []string
	groups := map[string][]Entry{}
	positions := map[string]map[string]int{}
	for _, e := range entries {
		if e.Application == "" || e.Key == "" || strings.ContainsRune(e.Application, 0) || strings.ContainsRune(e.Key, 0) || len(e.Application) >= 65535 || len(e.Key) >= 65535 || len(e.Data) > 65535 {
			return nil, fmt.Errorf("invalid OS/2 profile entry")
		}
		list, ok := groups[e.Application]
		if !ok {
			apps = append(apps, e.Application)
			positions[e.Application] = map[string]int{}
		}
		if i, found := positions[e.Application][e.Key]; found {
			list[i] = e
		} else {
			positions[e.Application][e.Key] = len(list)
			list = append(list, e)
		}
		groups[e.Application] = list
	}
	size := 20
	for _, a := range apps {
		size += 20 + len(a) + 1
		for _, e := range groups[a] {
			size += 24 + len(e.Key) + 1 + len(e.Data)
			if size > 64<<20 {
				return nil, fmt.Errorf("OS/2 profile size limit")
			}
		}
		if size > 64<<20 {
			return nil, fmt.Errorf("OS/2 profile size limit")
		}
	}
	out := make([]byte, size)
	le := binary.LittleEndian
	le.PutUint32(out, 0xffffffff)
	le.PutUint32(out[8:], uint32(size))
	pos := 20
	previous := 4
	for _, a := range apps {
		le.PutUint32(out[previous:], uint32(pos))
		previous = pos
		app := pos
		pos += 20
		le.PutUint16(out[app+12:], uint16(len(a)+1))
		le.PutUint16(out[app+14:], uint16(len(a)+1))
		le.PutUint32(out[app+16:], uint32(pos))
		copy(out[pos:], a)
		pos += len(a) + 1
		keyLink := app + 4
		for _, e := range groups[a] {
			le.PutUint32(out[keyLink:], uint32(pos))
			keyLink = pos
			key := pos
			pos += 24
			le.PutUint16(out[key+8:], uint16(len(e.Key)+1))
			le.PutUint16(out[key+10:], uint16(len(e.Key)+1))
			le.PutUint32(out[key+12:], uint32(pos))
			copy(out[pos:], e.Key)
			pos += len(e.Key) + 1
			le.PutUint16(out[key+16:], uint16(len(e.Data)))
			le.PutUint16(out[key+18:], uint16(len(e.Data)))
			le.PutUint32(out[key+20:], uint32(pos))
			copy(out[pos:], e.Data)
			pos += len(e.Data)
		}
	}
	return out, nil
}
