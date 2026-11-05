package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
)

// Append supports additions only. Existing class/instance replacement requires
// schema migration and is deliberately rejected rather than silently replacing
// a live object's keys. The original object store is kept byte-for-byte.
func (r *wmiRepositoryFile) appendDocuments(documents []*mofDocument, namespace, serverName string) (*wmiRepositoryFile, error) {
	if r.modern == nil {
		return nil, fmt.Errorf("wmi repository: append requires a modern base repository")
	}
	local := map[string]bool{}
	for _, d := range documents {
		for _, c := range d.Classes {
			ns := normalizeWMINamespace(c.Namespace, namespace)
			local[ns+"\x00"+strings.ToUpper(c.Name)] = true
		}
	}
	external := map[string]*wmiClassLayout{}
	var load func(string, string) error
	load = func(ns, name string) error {
		if name == "" {
			return nil
		}
		ns = normalizeWMINamespace(ns, namespace)
		identity := ns + "\x00" + strings.ToUpper(name)
		if local[identity] || external[identity] != nil || external["__SYSTEMCLASS\x00"+strings.ToUpper(name)] != nil {
			return nil
		}
		layout, err := r.classLayout(ns, name)
		if err != nil {
			return err
		}
		external[layout.namespace+"\x00"+strings.ToUpper(name)] = layout
		if err := load(layout.namespace, layout.definition.class.Super); err != nil {
			return err
		}
		for _, p := range layout.properties {
			if p.feature.Type.Reference != "" {
				if err := load(layout.namespace, p.feature.Type.Reference); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, d := range documents {
		for _, c := range d.Classes {
			if err := load(c.Namespace, c.Super); err != nil {
				return nil, err
			}
		}
		for _, instance := range d.Instances {
			if err := load(instance.Namespace, instance.Class); err != nil {
				return nil, err
			}
		}
	}
	return buildWMIRepositoryDocumentsWithOptions(documents, namespace, wmiRepositoryOptions{serverName: serverName, hash: wmiUpperUTF16SHA256, external: external, finish: r.appendPending})
}

func serializeWMIModernMapping(m wmiModernMapping) []byte {
	var out []byte
	word := func(v uint32) { out = binary.LittleEndian.AppendUint32(out, v) }
	for _, s := range []wmiModernSection{m.objects, m.index} {
		for _, v := range []uint32{wmiMappingStart, s.generation, s.first, s.second, s.physical, uint32(len(s.entries))} {
			word(v)
		}
		for _, e := range s.entries {
			for _, v := range []uint32{e.page, e.crc, e.free, e.used, e.first, e.second} {
				word(v)
			}
		}
		word(uint32(len(s.free)))
		for _, v := range s.free {
			word(v)
		}
		word(wmiMappingEnd)
	}
	word(m.clean)
	return out
}
func (r *wmiRepositoryFile) appendPending(pending []wmiPendingRecord) (*wmiRepositoryFile, error) {
	if len(pending) == 0 {
		return r, nil
	}
	records := make([][]byte, len(pending))
	for i, p := range pending {
		records[i] = p.data
	}
	added, locations, err := buildWMIRepositoryObjects(records)
	if err != nil {
		return nil, err
	}
	added = added[wmiRepositoryPageSize:] // Modern stores have no XP metadata page.
	oldObjects, err := readWMIRepositoryFile(r.files["OBJECTS.DATA"].(starfile.File), "OBJECTS.DATA")
	if err != nil {
		return nil, err
	}
	mapping := *r.modern
	if mapping.objects.generation > 0xfffffffc || mapping.objects.first > 0xfffffffc {
		return nil, fmt.Errorf("wmi repository: mapping generation exhausted")
	}
	mapping.objects.entries = append([]wmiModernEntry(nil), mapping.objects.entries...)
	oldLogical := uint32(len(mapping.objects.entries))
	oldPhysical := mapping.objects.physical
	for i := range locations {
		locations[i].logicalPage += oldLogical - 1
	}
	// The XP packer emits per-record CRCs; modern record descriptors store zero.
	continuations := map[uint32]bool{}
	free := map[uint32]uint32{}
	for _, loc := range locations {
		local := loc.logicalPage - oldLogical
		page := added[int(local)*wmiRepositoryPageSize:]
		for pos := 0; pos+16 <= wmiRepositoryPageSize; pos += 16 {
			id := binary.LittleEndian.Uint32(page[pos:])
			if id == 0 {
				break
			}
			if id == loc.id {
				offset := binary.LittleEndian.Uint32(page[pos+4:])
				size := binary.LittleEndian.Uint32(page[pos+8:])
				binary.LittleEndian.PutUint32(page[pos+12:], 0)
				end := uint64(local)*wmiRepositoryPageSize + uint64(offset) + uint64(size)
				for p := local + 1; uint64(p)*wmiRepositoryPageSize < end; p++ {
					continuations[p] = true
				}
				if end <= uint64(local+1)*wmiRepositoryPageSize {
					remaining := uint32(uint64(local+1)*wmiRepositoryPageSize - end)
					previous, ok := free[local]
					if !ok || remaining < previous {
						free[local] = remaining
					}
				}
				break
			}
		}
	}
	mapping.objects.generation += 3
	mapping.index.generation = mapping.objects.generation
	for offset := 0; offset < len(added); offset += wmiRepositoryPageSize {
		local := uint32(offset / wmiRepositoryPageSize)
		available := free[local]
		if continuations[local] {
			available = 0
		}
		mapping.objects.entries = append(mapping.objects.entries, wmiModernEntry{page: oldPhysical + local, crc: wmiModernPageCRC(added[offset : offset+wmiRepositoryPageSize]), free: available, first: mapping.objects.first, second: mapping.objects.first})
	}
	mapping.objects.physical += uint32(len(added) / wmiRepositoryPageSize)
	objects := append(oldObjects, added...)
	var keys []string
	identities := map[string]bool{}
	for _, page := range r.pages {
		for _, key := range page.keys {
			keys = append(keys, key)
			identities[strings.SplitN(key, ".", 2)[0]] = true
		}
	}
	for _, key := range wmiRepositoryKeys(pending, locations, wmiUpperUTF16SHA256) {
		identity := strings.SplitN(key, ".", 2)[0]
		if identities[identity] {
			return nil, fmt.Errorf("wmi repository: append would replace existing key %s", identity)
		}
		identities[identity] = true
		keys = append(keys, key)
	}
	index, err := buildWMIRepositoryIndex(keys)
	if err != nil {
		return nil, err
	}
	root := binary.LittleEndian.Uint32(index[12:16])
	// Unlike XP, modern index page zero is a live page, and only 0xffffffff
	// denotes a null child. Remove the XP admin page and translate every link.
	index = index[wmiRepositoryPageSize:]
	root--
	for offset := 0; offset < len(index); offset += wmiRepositoryPageSize {
		page := index[offset : offset+wmiRepositoryPageSize]
		binary.LittleEndian.PutUint32(page[4:], uint32(offset/wmiRepositoryPageSize))
		count := binary.LittleEndian.Uint32(page[16:])
		for i := uint32(0); i <= count; i++ {
			pos := 20 + count*4 + i*4
			child := binary.LittleEndian.Uint32(page[pos:])
			binary.LittleEndian.PutUint32(page[pos:], child-1)
		}
	}
	mapping.index.entries = make([]wmiModernEntry, len(index)/wmiRepositoryPageSize)
	mapping.index.free = nil
	mapping.index.physical = uint32(len(mapping.index.entries))
	for i := range mapping.index.entries {
		mapping.index.entries[i] = wmiModernEntry{page: uint32(i), crc: wmiModernPageCRC(index[i*wmiRepositoryPageSize : (i+1)*wmiRepositoryPageSize]), first: mapping.index.first, second: mapping.index.first}
	}
	mapping.index.entries[0].used = root
	files := starlark.NewDict(5)
	files.SetKey(starlark.String("OBJECTS.DATA"), &starfile.Bytes{Name: "OBJECTS.DATA", Data: objects})
	files.SetKey(starlark.String("INDEX.BTR"), &starfile.Bytes{Name: "INDEX.BTR", Data: index})
	// Each checkpoint references the same immutable new stores. Only the newest
	// checkpoint is clean; a fallback never points into the discarded old index.
	for i := 1; i <= 3; i++ {
		m := mapping
		m.objects.generation -= uint32(3 - i)
		m.index.generation = m.objects.generation
		// Native checkpoint selection compares the two epoch fields, not just
		// generation. Equal epochs in all three maps have no newest checkpoint
		// and are rejected before any object/index page is read.
		m.objects.first = mapping.objects.first + uint32(i)
		m.objects.second = m.objects.first - 1
		m.index.first, m.index.second = m.objects.first, m.objects.second
		m.objects.entries = append([]wmiModernEntry(nil), mapping.objects.entries...)
		for j := range m.objects.entries {
			m.objects.entries[j].first = m.objects.first
			if uint32(j) >= oldLogical {
				m.objects.entries[j].second = m.objects.first
			}
		}
		m.index.entries = append([]wmiModernEntry(nil), mapping.index.entries...)
		for j := range m.index.entries {
			m.index.entries[j].first, m.index.entries[j].second = m.index.first, m.index.first
		}
		m.clean = 0
		if i == 3 {
			m.clean = 1
		}
		name := fmt.Sprintf("MAPPING%d.MAP", i)
		files.SetKey(starlark.String(name), &starfile.Bytes{Name: name, Data: serializeWMIModernMapping(m)})
	}
	return readWMIModernRepository(files)
}
