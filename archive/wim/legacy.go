package wim

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"path"
	"strings"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

// The 1.10 format uses numeric stream references and a flat root directory.
// Its layouts are recorded in docs/formats/wim-1.10.md from original-media
// observations. Content compression is shared with later WIM generations.
func openLegacyWIM(file storage.Reader, header []byte, cache *bytecache.Cache, source uint64, readImages bool) (*Archive, error) {
	w := &Archive{
		file: file, flags: binary.LittleEndian.Uint32(header[16:20]),
		chunkSize:  int(binary.LittleEndian.Uint32(header[20:24])),
		partNumber: 1, totalParts: 1,
		xml: parseWIMResource(header[48:72]), boot: parseWIMResource(header[72:96]),
		byHash: make(map[string]wimResourceLocation), locationsByHash: make(map[string][]wimResourceLocation),
		legacyIDs: make(map[uint32][20]byte), cacheStore: cache, cacheSource: source,
	}
	if w.chunkSize <= 0 || w.chunkSize&(w.chunkSize-1) != 0 {
		return nil, fmt.Errorf("wim 1.10: invalid chunk size %d", w.chunkSize)
	}
	table, err := w.readResource(parseWIMResource(header[24:48]))
	if err != nil {
		return nil, fmt.Errorf("wim 1.10 lookup: %w", err)
	}
	if len(table)%52 != 0 {
		return nil, fmt.Errorf("wim 1.10: invalid lookup length %d", len(table))
	}
	for offset := 0; offset < len(table); offset += 52 {
		raw := table[offset : offset+52]
		id := binary.LittleEndian.Uint32(raw[24:28])
		if _, exists := w.legacyIDs[id]; exists {
			return nil, fmt.Errorf("wim 1.10: duplicate resource ID %d", id)
		}
		item := wimLookupEntry{resource: parseWIMResource(raw[:24]), part: 1, refCount: binary.LittleEndian.Uint32(raw[28:32])}
		copy(item.hash[:], raw[32:52])
		if item.resource.flags&wimResourceMetadata == 0 && item.hash == ([20]byte{}) {
			return nil, fmt.Errorf("wim 1.10: unsupported unhashed data resource %d", id)
		}
		if item.resource.offset < 96 || item.resource.size < 0 || item.resource.offset > file.Size() || item.resource.size > file.Size()-item.resource.offset {
			return nil, fmt.Errorf("wim 1.10: resource %d exceeds input", id)
		}
		w.legacyIDs[id] = item.hash
		w.lookup = append(w.lookup, item)
		if item.resource.flags&wimResourceMetadata != 0 {
			w.imageCount++
		}
	}
	if err := w.indexLookupResources(); err != nil {
		return nil, err
	}
	if !readImages {
		return w, nil
	}
	for _, item := range w.lookup {
		if item.resource.flags&wimResourceMetadata == 0 {
			continue
		}
		if item.resource.originalSize < 8 || item.resource.originalSize > 128<<20 {
			return nil, fmt.Errorf("wim 1.10: invalid image metadata size")
		}
		data, err := w.readResource(item.resource)
		if err != nil {
			return nil, err
		}
		if item.hash != ([20]byte{}) && sha1.Sum(data) != item.hash {
			return nil, fmt.Errorf("wim 1.10: image metadata SHA-1 mismatch")
		}
		security, rootOffset, err := legacySecurity(data)
		if err != nil {
			return nil, err
		}
		index := len(w.images) + 1
		name := fmt.Sprintf("image%d", index)
		root := entry{name: name, path: "/" + name, isDir: true, attrs: 0x10, securityID: ^uint32(0), subdirOff: uint64(rootOffset)}
		w.images = append(w.images, image{index: index, resource: item.resource, metadata: data, security: security,
			root: root, dirs: make(map[string][]entry), byPath: map[string]entry{wimPathKey(root.path): root}})
	}
	return w, nil
}

func legacySecurity(data []byte) ([][]byte, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("wim 1.10: truncated security table")
	}
	count := uint64(binary.LittleEndian.Uint32(data[4:8]))
	if count > uint64(len(data))/8 {
		return nil, 0, fmt.Errorf("wim 1.10: invalid security descriptor count")
	}
	offset := int(count * 8)
	if count == 0 {
		offset = 8
	}
	var descriptors [][]byte
	for i := 0; i < int(count); i++ {
		length := uint64(binary.LittleEndian.Uint32(data[i*8 : i*8+4]))
		if (i > 0 && binary.LittleEndian.Uint32(data[i*8+4:i*8+8]) != 0) || length > uint64(len(data)-offset) {
			return nil, 0, fmt.Errorf("wim 1.10: invalid security descriptor %d", i)
		}
		descriptors = append(descriptors, data[offset:offset+int(length)])
		offset += int(length)
	}
	offset = align8(offset)
	if offset > len(data)-8 {
		return nil, 0, fmt.Errorf("wim 1.10: missing root directory")
	}
	return descriptors, offset, nil
}

func (w *Archive) readLegacyDir(image *image, dir entry) ([]entry, error) {
	data := image.metadata
	offset := dir.subdirOff
	var children []entry
	for {
		if offset > uint64(len(data)) || uint64(len(data))-offset < 8 || offset%8 != 0 {
			return nil, fmt.Errorf("wim 1.10: invalid directory offset %#x", offset)
		}
		length := binary.LittleEndian.Uint64(data[offset : offset+8])
		if length == 0 {
			break
		}
		if length < 64 || length%8 != 0 || length > uint64(len(data))-offset {
			return nil, fmt.Errorf("wim 1.10: invalid directory record at %#x", offset)
		}
		raw := data[offset : offset+length]
		shortLen := int(binary.LittleEndian.Uint16(raw[58:60]))
		nameLen := int(binary.LittleEndian.Uint16(raw[60:62]))
		if nameLen%2 != 0 || shortLen%2 != 0 || 62+nameLen+2 > len(raw) {
			return nil, fmt.Errorf("wim 1.10: invalid filename at %#x", offset)
		}
		name := utf16LEString(raw[62 : 62+nameLen])
		if !validWIMName(name) || binary.LittleEndian.Uint16(raw[62+nameLen:64+nameLen]) != 0 {
			return nil, fmt.Errorf("wim 1.10: invalid filename at %#x", offset)
		}
		child := entry{name: name, path: path.Join(dir.path, name),
			attrs: binary.LittleEndian.Uint32(raw[8:12]), securityID: binary.LittleEndian.Uint32(raw[12:16]),
			creationTime: binary.LittleEndian.Uint64(raw[24:32]), lastAccessTime: binary.LittleEndian.Uint64(raw[32:40]),
			lastWriteTime: binary.LittleEndian.Uint64(raw[40:48]), streamCount: binary.LittleEndian.Uint16(raw[56:58])}
		child.isDir = child.attrs&0x10 != 0
		if shortLen > 0 {
			start := 64 + nameLen
			if start+shortLen+2 > len(raw) || binary.LittleEndian.Uint16(raw[start+shortLen:start+shortLen+2]) != 0 {
				return nil, fmt.Errorf("wim 1.10: invalid short filename")
			}
			child.shortName = utf16LEString(raw[start : start+shortLen])
		}
		if child.securityID != ^uint32(0) && uint64(child.securityID) >= uint64(len(image.security)) {
			return nil, fmt.Errorf("wim 1.10: invalid security ID for %s", child.path)
		}
		id := binary.LittleEndian.Uint32(raw[16:20])
		offset += length
		for stream := 0; stream < int(child.streamCount); stream++ {
			if offset > uint64(len(data)) || uint64(len(data))-offset < 24 {
				return nil, fmt.Errorf("wim 1.10: truncated stream for %s", child.path)
			}
			streamLength := binary.LittleEndian.Uint64(data[offset : offset+8])
			if streamLength < 24 || streamLength%8 != 0 || streamLength > uint64(len(data))-offset {
				return nil, fmt.Errorf("wim 1.10: invalid stream length for %s", child.path)
			}
			s := data[offset : offset+streamLength]
			streamID := binary.LittleEndian.Uint32(s[8:12])
			nameLength := int(binary.LittleEndian.Uint16(s[16:18]))
			if nameLength%2 != 0 || 20+nameLength > len(s) || binary.LittleEndian.Uint16(s[18+nameLength:20+nameLength]) != 0 {
				return nil, fmt.Errorf("wim 1.10: invalid stream name for %s", child.path)
			}
			streamName := utf16LEString(s[18 : 18+nameLength])
			if streamName == "" {
				id = streamID
			} else {
				hash, found := w.legacyIDs[streamID]
				if !found || !validWIMName(streamName) {
					return nil, fmt.Errorf("wim 1.10: invalid named stream for %s", child.path)
				}
				if child.namedStreams == nil {
					child.namedStreams = make(map[string]starfile.File)
				}
				if _, exists := child.namedStreams[streamName]; exists {
					return nil, fmt.Errorf("wim 1.10: duplicate stream name")
				}
				child.namedStreams[streamName] = w.newFile(entry{path: child.path + ":" + streamName, hash: hash, size: w.byHash[string(hash[:])].blobSize})
			}
			offset += streamLength
		}
		if child.isDir {
			child.subdirOff = binary.LittleEndian.Uint64(raw[16:24])
		} else {
			if id != 0 {
				hash, found := w.legacyIDs[id]
				if !found {
					return nil, fmt.Errorf("wim 1.10: missing resource ID %d for %s", id, child.path)
				}
				child.hash = hash
				child.size = w.byHash[string(hash[:])].blobSize
			}
		}
		children = append(children, child)
	}
	for _, child := range children {
		key := wimPathKey(child.path)
		if _, exists := image.byPath[key]; exists {
			return nil, fmt.Errorf("wim 1.10: duplicate path %s", child.path)
		}
		image.byPath[key] = child
	}
	image.dirs[strings.ToLower(dir.path)] = children
	return children, nil
}
