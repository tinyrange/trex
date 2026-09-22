package ese

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Revision 2 stores a four-byte little-endian LID in the record. Its separate
// tree uses big-endian LIDs followed by a big-endian chunk offset. A LID-only
// entry contains the reference count and total uncompressed length.
func (d *Database) legacyLongValue(table *Table, reference []byte, cache map[uint32][]byte) ([]byte, error) {
	if len(reference) != 4 || table.longValuePage == 0 {
		return nil, fmt.Errorf("ese: invalid separated long value in %q", table.Name)
	}
	id := binary.LittleEndian.Uint32(reference)
	if value, ok := cache[id]; ok {
		return value, nil
	}
	target := make([]byte, 4)
	binary.BigEndian.PutUint32(target, id)
	var result []byte
	want := int64(-1)
	visited := make(map[uint32]bool)
	var walk func(uint32) error
	walk = func(number uint32) error {
		if number == 0 || (int64(number)+2)*d.info.PageSize > d.source.Size() || visited[number] {
			return fmt.Errorf("ese: invalid long-value page %d", number)
		}
		visited[number] = true
		page, err := d.readPage(number)
		if err != nil {
			return err
		}
		if page.flags&pageFlagLongValue == 0 || page.flags&pageFlagSpaceTree != 0 {
			return fmt.Errorf("ese: page %d is not a long-value tree", number)
		}
		prefix, err := d.pageValue(page, 0)
		if err != nil {
			return err
		}
		for tag := uint16(1); tag < page.tags; tag++ {
			value, err := d.pageValue(page, tag)
			if err != nil {
				return err
			}
			if value.flags&tagFlagDefunct != 0 || len(value.data) == 0 {
				continue
			}
			if page.flags&pageFlagLeaf == 0 {
				child, err := branchChild(value)
				if err != nil {
					return err
				}
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			key, data, err := keyedEntry(value, prefix.data)
			if err != nil {
				return err
			}
			if len(key) < 4 || !bytes.Equal(key[:4], target) {
				continue
			}
			switch len(key) {
			case 4:
				if want >= 0 || len(data) != 8 || binary.LittleEndian.Uint32(data[:4]) == 0 {
					return fmt.Errorf("ese: invalid long-value root %d", id)
				}
				want = int64(binary.LittleEndian.Uint32(data[4:]))
				if want > d.source.Size() {
					return fmt.Errorf("ese: long value %d exceeds database size", id)
				}
			case 8:
				offset := binary.BigEndian.Uint32(key[4:])
				if want < 0 || uint64(offset) != uint64(len(result)) || int64(len(result))+int64(len(data)) > want {
					return fmt.Errorf("ese: invalid long-value chunk %d at %d", id, offset)
				}
				result = append(result, data...)
			default:
				return fmt.Errorf("ese: invalid long-value key length %d", len(key))
			}
		}
		return nil
	}
	if err := walk(table.longValuePage); err != nil {
		return nil, err
	}
	if want < 0 || int64(len(result)) != want {
		return nil, fmt.Errorf("ese: incomplete long value %d: got %d, want %d", id, len(result), want)
	}
	if cache != nil {
		cache[id] = result
	}
	return result, nil
}

func keyedEntry(value pageValue, common []byte) ([]byte, []byte, error) {
	data := value.data
	var key []byte
	if value.flags&tagFlagCommon != 0 {
		if len(data) < 2 {
			return nil, nil, fmt.Errorf("ese: short common key")
		}
		count := int(binary.LittleEndian.Uint16(data[:2]) & 0x1fff)
		if count > len(common) {
			return nil, nil, fmt.Errorf("ese: common key exceeds page prefix")
		}
		key = append(key, common[:count]...)
		data = data[2:]
	}
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("ese: short key suffix")
	}
	count := int(binary.LittleEndian.Uint16(data[:2]) & 0x1fff)
	if count > len(data)-2 {
		return nil, nil, fmt.Errorf("ese: key suffix exceeds record")
	}
	key = append(key, data[2:2+count]...)
	return key, data[2+count:], nil
}
