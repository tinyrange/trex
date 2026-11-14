package fat

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	filesystemapi "github.com/tinyrange/trex/filesystem"
)

// OS/2 FAT12/16 uses dirent word 20 as an EA handle, not a cluster high
// word. EA DATA. SF holds a 512-byte header, 128-handle offset tables,
// and cluster-aligned EA sets. Layout: Microsoft's fastfat/fat.h EA_FILE_HEADER,
// EA_SET_HEADER and easup.c. Independently serialized; no driver code copied.
func (b *fat16Build) buildOS2EAs(clusterSize int64) error {
	var nodes []*fat32Node
	for _, n := range b.nodes {
		eas := b.eaMetadata[n.fullPath].ExtendedAttributes
		if len(eas) == 0 {
			continue
		}
		if n == b.root {
			return fmt.Errorf("fat: root EAs have no directory-entry handle")
		}
		if err := filesystemapi.ValidateExtendedAttributes(eas); err != nil {
			return fmt.Errorf("fat %s: %w", n.fullPath, err)
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) > 30719 {
		return fmt.Errorf("fat: OS/2 EA handle limit exceeded")
	}
	for _, n := range b.root.children {
		if strings.EqualFold(n.name, "EA DATA. SF") || string(n.short[:]) == "EA DATA  SF" {
			return fmt.Errorf("fat: generated EA DATA. SF conflicts with input")
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].fullPath < nodes[j].fullPath })
	groups := (len(nodes) + 1 + 127) / 128
	tableEnd := int64(512 + groups*256)
	dataStart := (tableEnd + clusterSize - 1) / clusterSize * clusterSize
	data := make([]byte, dataStart)
	for i := 512; i < len(data); i++ {
		data[i] = 0xff
	}
	binary.LittleEndian.PutUint16(data, 0x4445)
	b.eaHandles = make(map[*fat32Node]uint16, len(nodes))
	nextBase := 0
	baseCluster := int(dataStart / clusterSize)
	for i, n := range nodes {
		handle := i + 1
		group := handle / 128
		cluster := len(data) / int(clusterSize)
		if cluster > 65535 {
			return fmt.Errorf("fat: EA file exceeds 16-bit cluster offsets")
		}
		for nextBase <= group {
			binary.LittleEndian.PutUint16(data[32+nextBase*2:], uint16(cluster))
			nextBase++
			baseCluster = cluster
		}
		binary.LittleEndian.PutUint16(data[512+handle*2:], uint16(cluster-baseCluster))
		eas := b.eaMetadata[n.fullPath].ExtendedAttributes
		size := 30
		need := uint32(0)
		for _, ea := range eas {
			size += 5 + len(ea.Name) + len(ea.Value)
			if ea.Flags&0x80 != 0 {
				need++
			}
		}
		if size-26 > 65535 {
			return fmt.Errorf("fat %s: EA set exceeds 64 KiB", n.fullPath)
		}
		padded := (int64(size) + clusterSize - 1) / clusterSize * clusterSize
		if int64(len(data))+padded > 65535*clusterSize {
			return fmt.Errorf("fat: EA file exceeds 16-bit cluster offsets")
		}
		set := make([]byte, padded)
		binary.LittleEndian.PutUint16(set, 0x4145)
		binary.LittleEndian.PutUint16(set[2:], uint16(handle))
		binary.LittleEndian.PutUint32(set[4:], need)
		owner := strings.TrimRight(string(n.short[:8]), " ")
		if ext := strings.TrimRight(string(n.short[8:]), " "); ext != "" {
			owner += "." + ext
		}
		copy(set[8:22], owner)
		binary.LittleEndian.PutUint32(set[26:], uint32(size-26))
		off := 30
		for _, ea := range eas {
			set[off], set[off+1] = ea.Flags, byte(len(ea.Name))
			binary.LittleEndian.PutUint16(set[off+2:], uint16(len(ea.Value)))
			copy(set[off+4:], ea.Name)
			copy(set[off+5+len(ea.Name):], ea.Value)
			off += 5 + len(ea.Name) + len(ea.Value)
		}
		data = append(data, set...)
		b.eaHandles[n] = uint16(handle)
	}
	end := len(data) / int(clusterSize)
	for ; nextBase < 240; nextBase++ {
		binary.LittleEndian.PutUint16(data[32+nextBase*2:], uint16(end))
	}
	n := &fat32Node{name: "EA DATA. SF", fullPath: "/EA DATA. SF", parent: b.root, data: data, size: int64(len(data)), attr: 7}
	copy(n.short[:], "EA DATA  SF")
	b.root.children = append(b.root.children, n)
	b.nodes = append(b.nodes, n)
	return nil
}
