package mbr

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

func partitionDict(start, ebr int64, fill byte, size int) *starlark.Dict {
	d := starlark.NewDict(5)
	d.SetKey(starlark.String("filesystem"), &starfile.Bytes{Data: bytes.Repeat([]byte{fill}, size)})
	d.SetKey(starlark.String("start_lba"), starlark.MakeInt64(start))
	d.SetKey(starlark.String("type"), starlark.MakeInt(6))
	if ebr != 0 {
		d.SetKey(starlark.String("ebr_lba"), starlark.MakeInt64(ebr))
	}
	return d
}

func TestMultiPartitionWriterUsesDifferentEBRAddressOrigins(t *testing.T) {
	b := &mbrBuilder{size: 16384 * 512, chs: &vmm.CHSGeometry{Cylinders: 64, Heads: 16, Sectors: 63}}
	primary := partitionDict(63, 0, 0x11, 512)
	primary.SetKey(starlark.String("bootable"), starlark.True)
	value, err := b.partitionsBuiltin(nil, nil, starlark.Tuple{
		starlark.NewList([]starlark.Value{primary}),
		starlark.NewList([]starlark.Value{partitionDict(4159, 4096, 0x22, 1024), partitionDict(8255, 8192, 0x33, 512)}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	image := value.(starfile.File)
	read := func(lba int64) []byte {
		out := make([]byte, 512)
		if _, err := image.ReadAt(out, lba*512); err != nil {
			t.Fatal(err)
		}
		return out
	}
	mbr, first, second := read(0), read(4096), read(8192)
	// Independent format expectations: extended table is disk-relative,
	// each data entry is current-EBR-relative, links are container-relative.
	for _, expect := range []struct {
		entry        []byte
		start, count uint32
	}{
		{mbr[446:462], 63, 1}, {mbr[462:478], 4096, 4160},
		{first[446:462], 63, 2}, {first[462:478], 4096, 64},
		{second[446:462], 63, 1},
	} {
		if binary.LittleEndian.Uint32(expect.entry[8:12]) != expect.start || binary.LittleEndian.Uint32(expect.entry[12:16]) != expect.count {
			t.Fatalf("wrong relative origin/extent: %x", expect.entry)
		}
	}
	if mbr[446] != 0x80 || mbr[466] != 5 || first[466] != 5 || !bytes.Equal(second[462:478], make([]byte, 16)) {
		t.Fatal("boot/container/terminal-link encoding")
	}
	// LBA 4159 is C/H/S 4/2/2, not C/H/S of relative LBA 63.
	if !bytes.Equal(first[447:450], []byte{2, 2, 4}) {
		t.Fatalf("logical CHS must be disk absolute: %x", first[447:450])
	}
	parsed, err := newMBRVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.partitions) != 4 || parsed.partitions[2].index != 5 || parsed.partitions[2].startLBA != 4159 || parsed.partitions[3].index != 6 || parsed.partitions[3].startLBA != 8255 {
		t.Fatalf("logical discovery: %+v", parsed.partitions)
	}
	for _, p := range parsed.partitions[2:] {
		got := make([]byte, 512)
		if _, err := p.partition.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
		fill := byte(0x22)
		if p.index == 6 {
			fill = 0x33
		}
		if !bytes.Equal(got, bytes.Repeat([]byte{fill}, 512)) {
			t.Fatalf("wrong logical payload for partition%d", p.index)
		}
	}
}

// Hand-built chain, independent of the writer: container [10,90),
// EBRs 10/30, data at 12 and 33. Its two relative bases are deliberately unequal.
func manualExtendedFixture() []byte {
	out := make([]byte, 100*512)
	entry := func(table, slot int, kind byte, start, count uint32) {
		e := out[table*512+446+slot*16 : table*512+462+slot*16]
		e[4] = kind
		binary.LittleEndian.PutUint32(e[8:12], start)
		binary.LittleEndian.PutUint32(e[12:16], count)
	}
	for _, lba := range []int{0, 10, 30} {
		out[lba*512+510], out[lba*512+511] = 0x55, 0xaa
	}
	entry(0, 0, 5, 10, 80)
	entry(10, 0, 6, 2, 2)
	entry(10, 1, 5, 20, 60)
	entry(30, 0, 6, 3, 2)
	copy(out[12*512:], []byte("first logical"))
	copy(out[33*512:], []byte("second logical"))
	return out
}

func TestExtendedReaderRejectsHostileAndOverlappingChains(t *testing.T) {
	good, err := newMBRVolume(&starfile.Bytes{Data: manualExtendedFixture()})
	if err != nil || len(good.partitions) != 3 || good.partitions[1].startLBA != 12 || good.partitions[2].startLBA != 33 {
		t.Fatalf("hand-built chain: %v %v", good, err)
	}
	tests := []struct {
		name, want string
		mutate     func([]byte)
	}{
		{"cycle", "cycles", func(b []byte) {
			e := b[30*512+462 : 30*512+478]
			e[4] = 5
			binary.LittleEndian.PutUint32(e[8:12], 20)
			binary.LittleEndian.PutUint32(e[12:16], 60)
		}},
		{"link escape", "invalid extended link", func(b []byte) { binary.LittleEndian.PutUint32(b[10*512+470:], 90) }},
		{"data escape", "invalid logical", func(b []byte) { binary.LittleEndian.PutUint32(b[30*512+454:], 0xffffffff) }},
		{"bad EBR signature", "signature", func(b []byte) { b[30*512+511] = 0 }},
		{"EBR inside data", "overlapping", func(b []byte) {
			binary.LittleEndian.PutUint32(b[10*512+454:], 20)
			binary.LittleEndian.PutUint32(b[10*512+458:], 4)
		}},
		{"data overlap", "overlapping", func(b []byte) {
			binary.LittleEndian.PutUint32(b[10*512+454:], 22)
			binary.LittleEndian.PutUint32(b[10*512+458:], 4)
		}},
		{"unsupported extra entry", "third/fourth", func(b []byte) { b[10*512+482] = 6 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := manualExtendedFixture()
			tt.mutate(b)
			if _, err := newMBRVolume(&starfile.Bytes{Data: b}); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %s", err, tt.want)
			}
		})
	}
}

func TestExtendedReaderBoundsChainLength(t *testing.T) {
	b := make([]byte, 400*512)
	b[510], b[511] = 0x55, 0xaa
	b[450] = 5
	binary.LittleEndian.PutUint32(b[454:], 10)
	binary.LittleEndian.PutUint32(b[458:], 390)
	for n := 0; n < 130; n++ {
		lba := 10 + n*2
		table := b[lba*512 : (lba+1)*512]
		table[510], table[511] = 0x55, 0xaa
		table[450] = 6
		binary.LittleEndian.PutUint32(table[454:], 1)
		binary.LittleEndian.PutUint32(table[458:], 1)
		if n < 129 {
			table[466] = 5
			binary.LittleEndian.PutUint32(table[470:], uint32((n+1)*2))
			binary.LittleEndian.PutUint32(table[474:], uint32(390-(n+1)*2))
		}
	}
	if _, err := newMBRVolume(&starfile.Bytes{Data: b}); err == nil || !strings.Contains(err.Error(), "exceeds 128") {
		t.Fatalf("unbounded chain: %v", err)
	}
}

func TestMultiPartitionWriterRejectsOverlapAndUnorderedTables(t *testing.T) {
	for _, tt := range []struct {
		name             string
		primary, logical []starlark.Value
	}{
		{"logical data overlap", nil, []starlark.Value{partitionDict(102, 100, 1, 1024), partitionDict(103, 101, 2, 512)}},
		{"primary in container gap", []starlark.Value{partitionDict(150, 0, 1, 512)}, []starlark.Value{partitionDict(102, 100, 2, 512), partitionDict(202, 200, 3, 512)}},
		{"unordered EBRs", nil, []starlark.Value{partitionDict(202, 200, 1, 512), partitionDict(102, 100, 2, 512)}},
		{"missing EBR", nil, []starlark.Value{partitionDict(102, 0, 1, 512)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := &mbrBuilder{size: 1 << 20}
			if _, err := b.partitionsBuiltin(nil, nil, starlark.Tuple{starlark.NewList(tt.primary), starlark.NewList(tt.logical)}, nil); err == nil {
				t.Fatal("invalid layout accepted")
			}
		})
	}
}
