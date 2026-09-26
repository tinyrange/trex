package iso9660

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
)

// SUSP continuation areas are untrusted input. Bound the entire chain, rather
// than just each allocation, and reject cycles before following them.
const maxSUSPBytes = 1 << 20
const maxSUSPAreas = 32

type rockRidge struct {
	attributes                                                         map[string]any
	name, link                                                         string
	hasName, hasLink, nameContinues, linkContinues, componentContinues bool
	relocated                                                          bool
	child                                                              uint32
	extension                                                          bool
}

func systemUse(raw []byte) []byte {
	if len(raw) < 34 {
		return nil
	}
	end := 33 + int(raw[32])
	if end&1 != 0 {
		end++
	}
	if end > len(raw) {
		return nil
	}
	return raw[end:]
}

func (i *isoImage) detectRockRidge(root isoDirRecord) (isoDirRecord, bool, error) {
	sector := make([]byte, 2048)
	if _, err := i.file.ReadAt(sector, int64(root.extent)*2048); err != nil {
		return root, false, err
	}
	length := int(sector[0])
	if length < 34 {
		return root, false, fmt.Errorf("iso: invalid root directory record")
	}
	raw := sector[:length]
	su := systemUse(raw)
	// CD-ROM XA reserves fourteen system-use bytes before SUSP.
	for _, start := range []int{0, 14} {
		if len(su) < start+7 || string(su[start:start+2]) != "SP" {
			continue
		}
		sp := su[start : start+7]
		if sp[2] != 7 || sp[3] != 1 || sp[4] != 0xbe || sp[5] != 0xef {
			continue
		}
		rr, err := i.parseRockRidge(su[start:])
		if err != nil {
			return root, false, err
		}
		if !rr.extension {
			return root, false, nil
		}
		i.suspSkip = int(sp[6])
		root.rr = rr
		return root, true, nil
	}
	return root, false, nil
}

func both32(p []byte) (uint32, error) {
	if len(p) < 8 {
		return 0, fmt.Errorf("iso: short both-endian field")
	}
	n := binary.LittleEndian.Uint32(p[:4])
	if n != binary.BigEndian.Uint32(p[4:8]) {
		return 0, fmt.Errorf("iso: inconsistent both-endian field")
	}
	return n, nil
}

func (i *isoImage) parseRockRidge(data []byte) (*rockRidge, error) {
	rr := &rockRidge{attributes: make(map[string]any)}
	seen := map[[3]uint32]bool{}
	budget := maxSUSPBytes
	var parse func([]byte) error
	parse = func(data []byte) error {
		var continuation []byte
		for len(data) > 0 {
			if data[0] == 0 {
				break
			} // final zero padding
			if len(data) < 4 || int(data[2]) < 4 || int(data[2]) > len(data) {
				return fmt.Errorf("iso: invalid SUSP record length")
			}
			record := data[:int(data[2])]
			data = data[len(record):]
			if record[3] != 1 {
				continue
			}
			tag := string(record[:2])
			payload := record[4:]
			switch tag {
			case "ST":
				data = nil
			case "CE":
				if len(payload) != 24 || continuation != nil {
					return fmt.Errorf("iso: invalid SUSP continuation")
				}
				var area [3]uint32
				for n := range area {
					var err error
					area[n], err = both32(payload[n*8:])
					if err != nil {
						return err
					}
				}
				if seen[area] || len(seen) >= maxSUSPAreas {
					return fmt.Errorf("iso: cyclic or excessive SUSP continuations")
				}
				seen[area] = true
				off := int64(area[0])*2048 + int64(area[1])
				size := int64(area[2])
				if area[1] >= 2048 || size < 4 || size > int64(budget) || off > i.file.Size() || size > i.file.Size()-off {
					return fmt.Errorf("iso: SUSP continuation exceeds source or budget")
				}
				budget -= int(size)
				continuation = make([]byte, int(size))
				if _, err := i.file.ReadAt(continuation, off); err != nil {
					return err
				}
			case "ER":
				if len(payload) < 4 || int(payload[0])+int(payload[1])+int(payload[2])+4 > len(payload) {
					return fmt.Errorf("iso: invalid SUSP extension reference")
				}
				id := string(payload[4 : 4+int(payload[0])])
				if payload[3] == 1 && (id == "RRIP_1991A" || id == "IEEE_P1282" || id == "IEEE_1282") {
					rr.extension = true
				}
			case "PX":
				if len(payload) != 32 && len(payload) != 40 {
					return fmt.Errorf("iso: invalid Rock Ridge PX")
				}
				for n, key := range []string{"mode", "nlink", "uid", "gid", "inode"} {
					if n*8 >= len(payload) {
						break
					}
					v, err := both32(payload[n*8:])
					if err != nil {
						return err
					}
					rr.attributes[key] = int64(v)
				}
			case "PN":
				if len(payload) != 16 {
					return fmt.Errorf("iso: invalid Rock Ridge PN")
				}
				for n, key := range []string{"device_high", "device_low"} {
					v, err := both32(payload[n*8:])
					if err != nil {
						return err
					}
					rr.attributes[key] = int64(v)
				}
			case "NM":
				if len(payload) < 1 {
					return fmt.Errorf("iso: short Rock Ridge NM")
				}
				flags := payload[0]
				if flags == 2 || flags == 4 {
					continue
				} // dot records are filtered by ISO identifier
				if flags & ^byte(1) != 0 || (rr.hasName && !rr.nameContinues) {
					return fmt.Errorf("iso: invalid Rock Ridge NM flags or sequence")
				}
				rr.hasName = true
				rr.nameContinues = flags&1 != 0
				rr.name += string(payload[1:])
				if len(rr.name) > 4096 || strings.ContainsAny(rr.name, "/\x00") {
					return fmt.Errorf("iso: invalid Rock Ridge name")
				}
			case "SL":
				if len(payload) < 1 || payload[0]&^byte(1) != 0 || (rr.hasLink && !rr.linkContinues) {
					return fmt.Errorf("iso: invalid Rock Ridge SL")
				}
				rr.hasLink = true
				rr.linkContinues = payload[0]&1 != 0
				for p := payload[1:]; len(p) > 0; {
					if len(p) < 2 || int(p[1])+2 > len(p) {
						return fmt.Errorf("iso: truncated Rock Ridge link component")
					}
					flags := p[0]
					n := int(p[1])
					component := string(p[2 : 2+n])
					p = p[2+n:]
					special := flags &^ byte(1)
					if special != 0 {
						if n != 0 || flags&1 != 0 || rr.componentContinues {
							return fmt.Errorf("iso: invalid special link component")
						}
						switch special {
						case 2:
							component = "."
						case 4:
							component = ".."
						case 8, 16:
							component = "/"
						default:
							return fmt.Errorf("iso: unsupported Rock Ridge link component flags %#x", flags)
						}
					} else if n == 0 || strings.ContainsAny(component, "/\x00") {
						return fmt.Errorf("iso: invalid Rock Ridge link component")
					}
					if component == "/" {
						if rr.link != "" {
							return fmt.Errorf("iso: misplaced root link component")
						}
						rr.link = "/"
					} else {
						if rr.link != "" && !strings.HasSuffix(rr.link, "/") && !rr.componentContinues {
							rr.link += "/"
						}
						rr.link += component
					}
					rr.componentContinues = flags&1 != 0
					if len(rr.link) > 64<<10 {
						return fmt.Errorf("iso: Rock Ridge link too long")
					}
				}
			case "TF":
				if err := rr.timestamps(payload); err != nil {
					return err
				}
			case "RE":
				if len(payload) != 0 {
					return fmt.Errorf("iso: invalid Rock Ridge RE")
				}
				rr.relocated = true
			case "CL", "PL":
				if len(payload) != 8 {
					return fmt.Errorf("iso: invalid Rock Ridge relocation")
				}
				v, err := both32(payload)
				if err != nil {
					return err
				}
				if tag == "CL" {
					rr.child = v
				}
			}
		}
		if continuation != nil {
			return parse(continuation)
		}
		return nil
	}
	if err := parse(data); err != nil {
		return nil, err
	}
	if rr.nameContinues || rr.linkContinues || rr.componentContinues {
		return nil, fmt.Errorf("iso: unfinished Rock Ridge name or link")
	}
	if rr.hasName && (rr.name == "" || rr.name == "." || rr.name == "..") {
		return nil, fmt.Errorf("iso: invalid Rock Ridge name")
	}
	if rr.hasLink {
		if rr.link == "" {
			return nil, fmt.Errorf("iso: empty Rock Ridge link")
		}
		rr.attributes["link"] = rr.link
	}
	return rr, nil
}

func (r *rockRidge) timestamps(p []byte) error {
	if len(p) < 1 {
		return fmt.Errorf("iso: short Rock Ridge TF")
	}
	flags := p[0]
	p = p[1:]
	width := 7
	if flags&0x80 != 0 {
		width = 17
	}
	for bit, key := range []string{"created", "mtime", "atime", "ctime", "backup_time", "expiration_time", "effective_time"} {
		if flags&(1<<bit) == 0 {
			continue
		}
		if len(p) < width {
			return fmt.Errorf("iso: short Rock Ridge timestamp")
		}
		stamp, err := isoTimestamp(p[:width])
		if err != nil {
			return err
		}
		r.attributes[key] = stamp.Unix()
		p = p[width:]
	}
	if len(p) != 0 {
		return fmt.Errorf("iso: trailing Rock Ridge timestamp bytes")
	}
	return nil
}

func isoTimestamp(p []byte) (time.Time, error) {
	var y, m, d, h, min, s, centi int
	zone := 0
	if len(p) == 7 {
		y = int(p[0]) + 1900
		m = int(p[1])
		d = int(p[2])
		h = int(p[3])
		min = int(p[4])
		s = int(p[5])
		zone = int(int8(p[6]))
	} else if len(p) == 17 {
		fields := []*int{&y, &m, &d, &h, &min, &s, &centi}
		pos := 0
		for j, f := range fields {
			width := 2
			if j == 0 {
				width = 4
			}
			for _, digit := range p[pos : pos+width] {
				if digit < '0' || digit > '9' {
					return time.Time{}, fmt.Errorf("iso: invalid timestamp digits")
				}
			}
			v, err := strconv.Atoi(string(p[pos : pos+width]))
			if err != nil {
				return time.Time{}, fmt.Errorf("iso: invalid timestamp digits")
			}
			*f = v
			pos += width
		}
		zone = int(int8(p[16]))
	} else {
		return time.Time{}, fmt.Errorf("iso: invalid timestamp size")
	}
	if zone < -48 || zone > 52 || m < 1 || m > 12 || d < 1 || d > 31 || h > 23 || min > 59 || s > 59 {
		return time.Time{}, fmt.Errorf("iso: invalid timestamp")
	}
	t := time.Date(y, time.Month(m), d, h, min, s, centi*10000000, time.FixedZone("", zone*15*60))
	if t.Day() != d {
		return time.Time{}, fmt.Errorf("iso: invalid timestamp day")
	}
	return t, nil
}

func (r isoDirRecord) kind() string {
	if r.rr != nil {
		if r.rr.hasLink {
			return "symlink"
		}
		if mode, ok := r.rr.attributes["mode"].(int64); ok {
			switch mode & 0170000 {
			case 0040000:
				return "directory"
			case 0120000:
				return "symlink"
			case 0020000:
				return "character_device"
			case 0060000:
				return "block_device"
			case 0010000:
				return "fifo"
			case 0140000:
				return "socket"
			}
		}
	}
	if r.flags&2 != 0 {
		return "directory"
	}
	return "file"
}
func (r isoDirRecord) attr(name string) starlark.Value {
	if name == "entry_type" {
		return starlark.String(r.kind())
	}
	if r.rr != nil {
		switch v := r.rr.attributes[name].(type) {
		case string:
			return starlark.String(v)
		case int64:
			return starlark.MakeInt64(v)
		}
	}
	return nil
}

var isoMetadataAttrs = []string{"entry_type", "link", "mode", "uid", "gid", "nlink", "inode", "mtime", "atime", "ctime", "created", "backup_time", "expiration_time", "effective_time", "device_high", "device_low"}

func (i *isoImage) parseRecord(raw []byte) (isoDirRecord, error) {
	record, err := parseISODirRecordWithEncoding(raw, i.joliet)
	if err != nil {
		return record, err
	}
	// Ignore the ISO dot/parent entries before interpreting alternate names.
	if !i.rockRidge || record.name == "" {
		return record, nil
	}
	su := systemUse(raw)
	if len(su) < i.suspSkip {
		return record, nil
	}
	rr, err := i.parseRockRidge(su[i.suspSkip:])
	if err != nil {
		return record, err
	}
	record.rr = rr
	if rr.relocated {
		record.name = ""
		return record, nil
	}
	if rr.hasName {
		record.name = "/" + rr.name
	}
	if rr.child != 0 {
		if rr.child == record.extent {
			return record, fmt.Errorf("iso: recursive directory relocation")
		}
		sector := make([]byte, 2048)
		if _, err := i.file.ReadAt(sector, int64(rr.child)*2048); err != nil {
			return record, err
		}
		n := int(sector[0])
		if n < 34 {
			return record, fmt.Errorf("iso: invalid relocated directory")
		}
		moved, err := parseISODirRecordWithEncoding(sector[:n], false)
		if err != nil {
			return record, err
		}
		if !moved.isDir() || moved.extent != rr.child {
			return record, fmt.Errorf("iso: invalid relocated directory location")
		}
		su = systemUse(sector[:n])
		if len(su) >= i.suspSkip {
			metadata, err := i.parseRockRidge(su[i.suspSkip:])
			if err != nil {
				return record, err
			}
			if metadata.child != 0 {
				return record, fmt.Errorf("iso: recursive directory relocation")
			}
			record.rr = metadata
		}
		record.extent = moved.extent
		record.size = moved.size
		record.flags = moved.flags
	}
	return record, nil
}
