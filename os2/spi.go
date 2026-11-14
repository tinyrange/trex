package os2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// StreamProfile constructs SPI.INI from the packed RT_RCDATA records in an
// original SSMRES module. Handler DLLs and device drivers are not executed.
func StreamProfile(data []byte, maximum uint64) ([]byte, error) {
	image, err := DecodeLX(data, maximum)
	if err != nil {
		return nil, err
	}
	resources := map[uint16][]byte{}
	for _, r := range image.Resources {
		if r.Type != 9 {
			continue
		}
		if _, ok := resources[r.ID]; ok {
			return nil, fmt.Errorf("SPI: duplicate resource %d", r.ID)
		}
		resources[r.ID] = image.Objects[r.Object-1].Data[r.Offset : r.Offset+r.Size]
	}
	return streamProfileResources(resources)
}

func streamProfileResources(resources map[uint16][]byte) ([]byte, error) {
	bad := func(s string) ([]byte, error) { return nil, fmt.Errorf("SPI: %s", s) }
	countData := resources[1]
	if len(countData) != 2 {
		return bad("missing handler count")
	}
	count := int(binary.LittleEndian.Uint16(countData))
	if count == 0 || count > 4096 {
		return bad("handler count limit")
	}
	classes := []string{}
	handlers := map[string][]byte{}
	classCount := map[string]uint16{}
	names := map[string]bool{}
	for id := 2; id < count+2; id++ {
		b := resources[uint16(id)]
		readString := func(max int) (string, error) {
			n := bytes.IndexByte(b, 0)
			if n < 0 || n > max {
				return "", fmt.Errorf("SPI: string bounds in resource %d", id)
			}
			s := string(b[:n])
			b = b[n+1:]
			return s, nil
		}
		class, e := readString(8)
		if e != nil {
			return nil, e
		}
		name, e := readString(8)
		if e != nil {
			return nil, e
		}
		if class == "" || name == "" || len(b) < 2 || names[name] {
			return bad("invalid/duplicate handler")
		}
		names[name] = true
		kind := binary.LittleEndian.Uint16(b)
		b = b[2:]
		if kind > 1 {
			return bad("unknown handler type")
		}
		dll, e := readString(259)
		if e != nil {
			return nil, e
		}
		if dll == "" || len(b) < 2 {
			return bad("missing module/protocol count")
		}
		n := binary.LittleEndian.Uint16(b)
		b = b[2:]
		if len(b) != int(n)*72 {
			return bad("protocol array bounds")
		}
		for off := 0; off < len(b); off += 72 {
			if binary.LittleEndian.Uint32(b[off:]) != 72 {
				return bad("unsupported protocol size")
			}
		}
		if _, ok := handlers[class]; !ok {
			classes = append(classes, class)
		}
		// SHCLASS values contain a USHORT count and packed 273-byte headers,
		// followed immediately by each handler's 72-byte SPCB array. In-memory
		// pointers used by SpiInstall are deliberately not serialized.
		row := make([]byte, 273)
		copy(row, name)
		copy(row[11:], dll)
		binary.LittleEndian.PutUint16(row[9:], kind)
		binary.LittleEndian.PutUint16(row[271:], n)
		handlers[class] = append(handlers[class], row...)
		handlers[class] = append(handlers[class], b...)
		classCount[class]++
	}
	global := make([]byte, 2+9*len(classes))
	binary.LittleEndian.PutUint16(global, uint16(len(classes)))
	entries := []Entry{}
	for i, class := range classes {
		copy(global[2+9*i:2+9*(i+1)], class)
		value := make([]byte, 2, len(handlers[class])+2)
		binary.LittleEndian.PutUint16(value, classCount[class])
		value = append(value, handlers[class]...)
		entries = append(entries, Entry{"SHCLASS", class, value})
	}
	entries = append(entries, Entry{"SHNAME", "GLOBAL", global})
	return Profile(entries)
}

func StreamProfileBuiltin(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := 64 << 20
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs, "source", &source, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum <= 0 || maximum > 1<<30 {
		return nil, fmt.Errorf("stream_profile: invalid expansion limit")
	}
	data, err := starfile.BytesForValue(source, int64(maximum))
	if err != nil {
		return nil, err
	}
	out, err := StreamProfile(data, uint64(maximum))
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: out}, nil
}
