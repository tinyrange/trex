package mbr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const maxLogicalPartitions = 128

func extendedType(kind byte) bool { return kind == 0x05 || kind == 0x0f || kind == 0x85 }

type partitionSpec struct {
	file                starfile.File
	start, ebr, sectors int64
	kind                byte
	bootable            bool
}

func parsePartitionSpecs(value starlark.Value, logical bool) ([]partitionSpec, error) {
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("mbr: partition specifications must be iterable")
	}
	iter := iterable.Iterate()
	defer iter.Done()
	result := []partitionSpec{}
	var item starlark.Value
	for iter.Next(&item) {
		if len(result) >= maxLogicalPartitions {
			return nil, fmt.Errorf("mbr: too many partition specifications")
		}
		d, ok := item.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("mbr: partition specification must be a dictionary")
		}
		var source starlark.Value
		var start, ebr int64
		kind := 0x07
		bootable := false
		kwargs := []starlark.Tuple{}
		for _, pair := range d.Items() {
			kwargs = append(kwargs, pair)
		}
		if err := starlark.UnpackArgs("mbr partition specification", nil, kwargs,
			"filesystem", &source, "start_lba", &start, "type?", &kind, "bootable?", &bootable, "ebr_lba?", &ebr); err != nil {
			return nil, err
		}
		file, ok := source.(starfile.File)
		if !ok || file.Size() <= 0 {
			return nil, fmt.Errorf("mbr: filesystem must be a nonempty file")
		}
		if kind < 1 || kind > 255 || extendedType(byte(kind)) {
			return nil, fmt.Errorf("mbr: data partition type must be nonzero and not an extended type")
		}
		if start < 1 || start > 0xffffffff || file.Size() > int64(0xffffffff)*512 {
			return nil, fmt.Errorf("mbr: data partition exceeds 32-bit LBA bounds")
		}
		sectors := fsinternal.CeilDiv(file.Size(), 512)
		if start+sectors > 0x100000000 {
			return nil, fmt.Errorf("mbr: data partition exceeds 32-bit LBA bounds")
		}
		if logical && (ebr < 1 || ebr >= start) || !logical && ebr != 0 {
			return nil, fmt.Errorf("mbr: logical partitions require 0 < ebr_lba < start_lba; primary partitions have no EBR")
		}
		result = append(result, partitionSpec{file: file, start: start, ebr: ebr, sectors: sectors, kind: byte(kind), bootable: bootable})
	}
	return result, nil
}

type lbaRange struct{ start, end int64 }

func disjointRanges(ranges []lbaRange) error {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	for i := 1; i < len(ranges); i++ {
		if ranges[i].start < ranges[i-1].end {
			return fmt.Errorf("mbr: overlapping partition or EBR extents")
		}
	}
	return nil
}

// partitionsBuiltin writes all table bytes natively. Logical start_lba and
// ebr_lba are absolute disk LBAs: only their on-disk encodings are relative.
func (b *mbrBuilder) partitionsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var primaryValue starlark.Value
	var logicalValue starlark.Value = starlark.Tuple{}
	kind := 0x05
	if err := starlark.UnpackArgs("partitions", args, kwargs, "primary", &primaryValue, "logical?", &logicalValue, "extended_type?", &kind); err != nil {
		return nil, err
	}
	if kind < 0 || kind > 255 || !extendedType(byte(kind)) {
		return nil, fmt.Errorf("mbr: extended_type must be 05, 0F or 85")
	}
	primary, err := parsePartitionSpecs(primaryValue, false)
	if err != nil {
		return nil, err
	}
	logical, err := parsePartitionSpecs(logicalValue, true)
	if err != nil {
		return nil, err
	}
	slots := len(primary)
	if len(logical) > 0 {
		slots++
	}
	if slots == 0 || slots > 4 {
		return nil, fmt.Errorf("mbr: one to four primary table slots required, including the extended container")
	}
	ranges := []lbaRange{{0, 1}}
	rootRanges := []lbaRange{{0, 1}}
	end := int64(1)
	for _, p := range primary {
		ranges = append(ranges, lbaRange{p.start, p.start + p.sectors})
		rootRanges = append(rootRanges, lbaRange{p.start, p.start + p.sectors})
		if p.start+p.sectors > end {
			end = p.start + p.sectors
		}
	}
	base, extEnd := int64(0), int64(0)
	if len(logical) > 0 {
		base = logical[0].ebr
		for n, p := range logical {
			if n > 0 && p.ebr <= logical[n-1].ebr {
				return nil, fmt.Errorf("mbr: logical EBRs must be in increasing absolute LBA order")
			}
			ranges = append(ranges, lbaRange{p.ebr, p.ebr + 1}, lbaRange{p.start, p.start + p.sectors})
			if p.start+p.sectors > extEnd {
				extEnd = p.start + p.sectors
			}
		}
		rootRanges = append(rootRanges, lbaRange{base, extEnd})
		if extEnd > end {
			end = extEnd
		}
	}
	if err = disjointRanges(ranges); err != nil {
		return nil, err
	}
	if err = disjointRanges(rootRanges); err != nil {
		return nil, err
	}
	size := b.size
	if size < end*512 {
		size = fsinternal.Align(end*512, 1024*1024)
	}
	if size%512 != 0 || size/512 > 0xffffffff {
		return nil, fmt.Errorf("mbr: disk size must be sector aligned and fit in 32-bit sector count")
	}
	sector := b.mbrSector(false, 0, 0, 0)
	clear(sector[446:510])
	total := uint32(size / 512)
	extents := []filesystemapi.ExtentSpec{}
	for n, p := range primary {
		b.writeEntry(sector[446+n*16:462+n*16], p.bootable, p.kind, p.start, p.sectors, p.start, total)
		extents = append(extents, filesystemapi.ExtentSpec{Start: p.start * 512, Size: p.file.Size(), File: p.file})
	}
	if len(logical) > 0 {
		n := len(primary)
		b.writeEntry(sector[446+n*16:462+n*16], false, byte(kind), base, extEnd-base, base, total)
		for n, p := range logical {
			ebr := make([]byte, 512)
			ebr[510], ebr[511] = 0x55, 0xaa
			b.writeEntry(ebr[446:462], p.bootable, p.kind, p.start-p.ebr, p.sectors, p.start, total)
			if n+1 < len(logical) {
				next := logical[n+1].ebr
				b.writeEntry(ebr[462:478], false, byte(kind), next-base, extEnd-next, next, total)
			}
			extents = append(extents, filesystemapi.ExtentSpec{Start: p.ebr * 512, Size: 512, Data: ebr}, filesystemapi.ExtentSpec{Start: p.start * 512, Size: p.file.Size(), File: p.file})
		}
	}
	extents = append(extents, filesystemapi.ExtentSpec{Start: 0, Size: 512, Data: sector})
	return filesystemapi.NewGeneratedImage("mbr.raw", size, extents), nil
}

// relativeStart is the entry's LBA field; CHS always describes absolute disk LBAs.
func (b *mbrBuilder) writeEntry(out []byte, bootable bool, kind byte, relativeStart, sectors, absoluteStart int64, total uint32) {
	if bootable {
		out[0] = 0x80
	}
	out[1], out[2], out[3] = mbrCHSForGeometry(uint32(absoluteStart), total, b.chs)
	out[4] = kind
	out[5], out[6], out[7] = mbrCHSForGeometry(uint32(absoluteStart+sectors-1), total, b.chs)
	binary.LittleEndian.PutUint32(out[8:12], uint32(relativeStart))
	binary.LittleEndian.PutUint32(out[12:16], uint32(sectors))
}

// readExtended follows disk-relative containers, EBR-relative data and
// container-relative links. All tables and payloads stay within the container.
func (v *mbrVolume) readExtended() error {
	ranges := []lbaRange{{0, 1}}
	containers := []mbrReadPartition{}
	for _, p := range v.partitions {
		ranges = append(ranges, lbaRange{p.startLBA, p.startLBA + p.sectors})
		if extendedType(p.kind) {
			containers = append(containers, p)
		}
	}
	if err := disjointRanges(ranges); err != nil {
		return err
	}
	if len(containers) > 1 {
		return fmt.Errorf("mbr: multiple extended containers are unsupported")
	}
	if len(containers) == 0 {
		return nil
	}
	container := containers[0]
	base, end := container.startLBA, container.startLBA+container.sectors
	current := base
	seen := map[int64]bool{}
	payloads := []lbaRange{}
	tables := []int64{}
	count := 0
	for {
		if current < base || current >= end || seen[current] {
			return fmt.Errorf("mbr: extended chain escapes container or cycles at LBA %d", current)
		}
		if len(seen) >= maxLogicalPartitions {
			return fmt.Errorf("mbr: extended chain exceeds %d EBRs", maxLogicalPartitions)
		}
		seen[current] = true
		tables = append(tables, current)
		sector, err := fsinternal.ReadBytesAt(v.file, current*512, 512)
		if err != nil {
			return fmt.Errorf("mbr: read EBR: %w", err)
		}
		if sector[510] != 0x55 || sector[511] != 0xaa {
			return fmt.Errorf("mbr: invalid EBR signature at LBA %d", current)
		}
		if !bytes.Equal(sector[478:510], make([]byte, 32)) {
			return fmt.Errorf("mbr: EBR has unsupported third/fourth entries")
		}
		entry := sector[446:462]
		kind := entry[4]
		sectors := int64(binary.LittleEndian.Uint32(entry[12:16]))
		if kind != 0 || sectors != 0 {
			rel := int64(binary.LittleEndian.Uint32(entry[8:12]))
			start := current + rel
			if kind == 0 || extendedType(kind) || sectors == 0 || rel == 0 || start < base || start >= end || sectors > end-start || entry[0] != 0 && entry[0] != 0x80 {
				return fmt.Errorf("mbr: invalid logical partition at EBR LBA %d", current)
			}
			index := 5 + count
			count++
			file := &starfile.Slice{Name: fmt.Sprintf("%s logical partition %d", v.file.String(), index), Base: v.file, Offset: start * 512, Length: sectors * 512}
			v.partitions = append(v.partitions, mbrReadPartition{index: index, bootable: entry[0] == 0x80, kind: kind, startLBA: start, sectors: sectors, partition: file, ebrLBA: current})
			path := fmt.Sprintf("/partition%d", index)
			v.paths[path] = file
			if err := v.files.Append(starlark.String(path)); err != nil {
				return err
			}
			payloads = append(payloads, lbaRange{start, start + sectors})
		} else if !bytes.Equal(entry, make([]byte, 16)) {
			return fmt.Errorf("mbr: malformed empty logical entry")
		}
		link := sector[462:478]
		if bytes.Equal(link, make([]byte, 16)) {
			break
		}
		rel := int64(binary.LittleEndian.Uint32(link[8:12]))
		sectors = int64(binary.LittleEndian.Uint32(link[12:16]))
		next := base + rel
		if !extendedType(link[4]) || link[0] != 0 || sectors == 0 || next < base || next >= end || sectors > end-next {
			return fmt.Errorf("mbr: invalid extended link at EBR LBA %d", current)
		}
		current = next
	}
	for _, table := range tables {
		payloads = append(payloads, lbaRange{table, table + 1})
	}
	return disjointRanges(payloads)
}
