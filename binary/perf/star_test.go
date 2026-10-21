package perf

import (
	"encoding/binary"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Construct the file from the documented on-disk offsets independently of the
// reader. Its zero-valued IP must remain distinct from an absent sample field.
func starFixture() *starfile.Bytes {
	var records []byte
	put := binary.LittleEndian
	u64 := func(value uint64) []byte { return put.AppendUint64(nil, value) }
	tid := append(put.AppendUint32(nil, 101), put.AppendUint32(nil, 102)...)
	trailer := append(append([]byte(nil), tid...), u64(9001)...)
	record := func(kind uint32, misc uint16, payload []byte) {
		header := make([]byte, 8)
		put.PutUint32(header, kind)
		put.PutUint16(header[4:], misc)
		put.PutUint16(header[6:], uint16(8+len(payload)))
		records = append(records, header...)
		records = append(records, payload...)
	}
	comm := append(append([]byte(nil), tid...), []byte("worker\x00\x00")...)
	record(3, 2, append(comm, trailer...))
	mapping := append(append([]byte(nil), tid...), u64(0xfedcba9876543000)...)
	mapping = append(mapping, u64(4096)...)
	mapping = append(mapping, u64(8192)...)
	mapping = append(mapping, []byte("/anon\x00\x00\x00")...)
	record(1, 2, append(mapping, trailer...))
	for _, buildID := range []bool{false, true} {
		mapping2 := make([]byte, 72)
		copy(mapping2, tid)
		put.PutUint64(mapping2[8:], 0x4000)
		put.PutUint64(mapping2[16:], 0x1000)
		put.PutUint64(mapping2[24:], 0x2000)
		misc := uint16(2)
		if buildID {
			misc |= 1 << 14
			mapping2[32] = 3
			copy(mapping2[36:], []byte{1, 2, 255})
		} else {
			put.PutUint32(mapping2[32:], 8)
			put.PutUint32(mapping2[36:], 1)
			put.PutUint64(mapping2[40:], 1234)
			put.PutUint64(mapping2[48:], 5678)
		}
		put.PutUint32(mapping2[56:], 5)
		put.PutUint32(mapping2[60:], 2)
		copy(mapping2[64:], "/code\x00")
		record(10, misc, append(mapping2, trailer...))
	}
	for _, ip := range []uint64{0, 0xfedcba9876543210} {
		sample := append(u64(ip), tid...)
		sample = append(sample, u64(9002)...)
		sample = append(sample, u64(777)...)
		record(9, 2, sample)
	}
	lost := append(u64(42), u64(3)...)
	record(2, 0, append(lost, trailer...))
	record(13, 0, append(u64(5), trailer...))
	record(0x7fffffff, 0, nil)
	const headerSize, attributeSize = 104, 144
	data := make([]byte, headerSize+attributeSize)
	copy(data, "PERFILE2")
	put.PutUint64(data[8:], headerSize)
	put.PutUint64(data[16:], attributeSize)
	put.PutUint64(data[24:], headerSize)
	put.PutUint64(data[32:], attributeSize)
	put.PutUint64(data[40:], uint64(len(data)))
	put.PutUint64(data[48:], uint64(len(records)))
	attr := data[headerSize:]
	put.PutUint32(attr, 1)
	put.PutUint32(attr[4:], 128)
	put.PutUint64(attr[16:], 1000)
	put.PutUint64(attr[24:], 0x107)       // IP | TID | TIME | PERIOD
	put.PutUint64(attr[40:], 1<<18|1<<25) // sample_id_all | use_clockid
	put.PutUint32(attr[92:], 1)           // CLOCK_MONOTONIC
	return &starfile.Bytes{Name: "profile", Data: append(data, records...)}
}

func TestBuiltinPreservesPresenceAndProfileRecords(t *testing.T) {
	value, err := Builtin(nil, nil, starlark.Tuple{starFixture()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = starlark.ExecFile(&starlark.Thread{Name: "perf binding"}, "perf.star", `
def check(condition):
    if not condition:
        fail("profile projection mismatch")
check(p.little_endian and p.records == 9)
check(len(p.attributes) == 1)
a = p.attributes[0]
check(a.type == 1 and a.size == 128 and a.sample_period == 1000)
check(a.sample_type == 0x107 and a.sample_id_all and a.use_clock_id and a.clock_id == 1)
check(a.ids == [])
check(len(p.samples) == 2)
s = p.samples[0]
check(s.ip == 0 and s.cpu == None and s.address == None and s.id == None)
check(s.pid == 101 and s.tid == 102 and s.time == 9002 and s.period == 777)
check(s.present == 0x107 and s.misc == 2)
check(p.samples[1].ip == 0xfedcba9876543210)
m = p.mappings[0]
check(m.address == 0xfedcba9876543000 and m.length == 4096 and m.page_offset == 8192)
check(m.filename == "/anon" and m.type == 1 and m.inode == None and m.prot == None and m.build_id == None)
check(m.sample_id.time == 9001 and m.sample_id.pid == 101 and m.sample_id.ip == None)
check(len(p.mappings) == 3)
check(p.mappings[1].major == 8 and p.mappings[1].minor == 1 and p.mappings[1].inode == 1234 and p.mappings[1].inode_generation == 5678)
check(p.mappings[1].prot == 5 and p.mappings[1].flags == 2 and p.mappings[1].build_id == None)
check(p.mappings[2].build_id == b"\x01\x02\xff" and p.mappings[2].inode == None and p.mappings[2].major == None)
check(p.mappings[2].prot == 5 and p.mappings[2].flags == 2)
check(p.comms[0].name == "worker" and p.comms[0].sample_id.time == 9001)
check(p.comms[0].offset < m.offset and m.offset < s.offset and s.offset < p.samples[1].offset)
check(p.total_lost == 8 and len(p.lost) == 2)
check(p.lost[0].type == 2 and p.lost[0].id == 42 and p.lost[0].count == 3)
check(p.lost[1].type == 13 and p.lost[1].id == None and p.lost[1].count == 5)
check(p.lost[1].sample_id.time == 9001)
check(p.unknown_records == {0x7fffffff: 1})
`, starlark.StringDict{"p": value})
	if err != nil {
		t.Fatal(err)
	}
	file := starFixture()
	binary.LittleEndian.PutUint64(file.Data[104+40:], 1<<18)
	value, err = Builtin(nil, nil, starlark.Tuple{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attribute := value.(*starfile.Record).Get("attributes").(*starlark.List).Index(0).(*starfile.Record)
	if attribute.Get("clock_id") != starlark.None || attribute.Get("use_clock_id") != starlark.False {
		t.Fatal("implicit clock was presented as an explicit clock ID")
	}
}

func TestBuiltinRejectsInvalidArgumentsAndBounds(t *testing.T) {
	for _, name := range []string{"maximum_records", "maximum_samples", "maximum_string_bytes"} {
		for _, maximum := range []int{0, -1} {
			_, err := Builtin(nil, nil, starlark.Tuple{starFixture()}, []starlark.Tuple{{starlark.String(name), starlark.MakeInt(maximum)}})
			if err == nil || !strings.Contains(err.Error(), "positive") {
				t.Fatal(name, maximum, err)
			}
		}
		if _, err := Builtin(nil, nil, starlark.Tuple{starFixture()}, []starlark.Tuple{{starlark.String(name), starlark.MakeInt(1)}}); err == nil {
			t.Fatal(name, "did not reach reader limit")
		}
	}
	if _, err := Builtin(nil, nil, starlark.Tuple{starlark.String("profile.data")}, nil); err == nil {
		t.Fatal("accepted a host path instead of a file")
	}
}
