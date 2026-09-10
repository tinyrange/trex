package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRegistryLargeValueIgnoresCellPadding(t *testing.T) {
	const chunk = 0x3fd8
	w := &hiveWriter{format: registryHiveFormat{major: 1, minor: 5}}
	wanted := bytes.Repeat([]byte{0x7b}, chunk+19)
	first := w.writeCell(wanted[:chunk])
	last := bytes.Repeat([]byte{0xa5}, chunk)
	copy(last, wanted[chunk:])
	second := w.writeCell(last)
	list := make([]byte, 8)
	binary.LittleEndian.PutUint32(list, first)
	binary.LittleEndian.PutUint32(list[4:], second)
	desc := make([]byte, 8)
	copy(desc, "db")
	binary.LittleEndian.PutUint16(desc[2:], 2)
	binary.LittleEndian.PutUint32(desc[4:], w.writeCell(list))
	cell := w.writeCell(desc)
	w.finishBin()
	data := append(make([]byte, hiveBaseBlockSize), w.data...)
	binary.LittleEndian.PutUint32(data[24:], 5)
	h := &registryHive{file: testHiveFile(data)}
	got, err := h.readValueData(uint32(len(wanted)), cell)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wanted) {
		t.Fatal("large value included segment alignment padding")
	}
}

func TestRegistryLargeValueWriterUsesSegments(t *testing.T) {
	for _, minor := range []uint32{3, 4, 5} {
		w := &hiveWriter{format: registryHiveFormat{major: 1, minor: minor}}
		wanted := bytes.Repeat([]byte{0x71}, 20592)
		cell, err := w.writeValue("ProductPolicy", registryData{typ: regBinary, data: wanted})
		if err != nil {
			t.Fatal(err)
		}
		w.finishBin()
		dataCell := binary.LittleEndian.Uint32(w.data[int(cell)+12:])
		body := w.data[int(dataCell)+4:]
		if minor >= 4 {
			if string(body[:2]) != "db" {
				t.Fatalf("hive 1.%d large value is not segmented", minor)
			}
			if binary.LittleEndian.Uint16(body[2:]) != 2 {
				t.Fatal("wrong segment count")
			}
			listCell := binary.LittleEndian.Uint32(body[4:])
			for i := 0; i < 2; i++ {
				segment := binary.LittleEndian.Uint32(w.data[int(listCell)+4+i*4:])
				capacity := -int32(binary.LittleEndian.Uint32(w.data[segment:])) - 4
				// Windows 11 CmpCheckValueList checks every segment, including
				// the final partial payload, against the full segment capacity.
				if capacity < hiveBigDataSegmentSize {
					t.Fatalf("hive 1.%d segment %d capacity %d, want >= %d", minor, i, capacity, hiveBigDataSegmentSize)
				}
			}
		} else if !bytes.Equal(body[:len(wanted)], wanted) {
			t.Fatal("legacy hive must retain direct data")
		}
	}
}

func TestRegistryLargeValuePatchTransitions(t *testing.T) {
	for _, minor := range []uint32{3, 4, 5} {
		root := newRegistryTree("SYSTEM")
		setRegistryValue(root, "/Test", "Data", registryDWORD(1))
		data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: minor})
		if err != nil {
			t.Fatal(err)
		}
		h := &mutableHive{data: data}
		for _, size := range []int{5, 0x3fd8, 0x3fd9, 20592, 0x3fd8*2 + 7, 7, 0, 20592} {
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i*31 + 17)
			}
			if err := h.patchValue("/Test", "Data", registryData{typ: regBinary, data: want}); err != nil {
				t.Fatal(err)
			}
			r, err := newRegistryHive(testHiveFile(h.data))
			if err != nil {
				t.Fatal(err)
			}
			key, err := r.lookup("/Test")
			if err != nil {
				t.Fatal(err)
			}
			values, err := r.readRawValues(key)
			if err != nil {
				t.Fatalf("1.%d size %d: %v", minor, size, err)
			}
			if len(values) != 1 || !bytes.Equal(values[0].value.data, want) {
				t.Fatalf("1.%d size %d round trip differs", minor, size)
			}
		}
	}
}

func TestRegistryModernHiveRejectsDirectLargeValue(t *testing.T) {
	w := &hiveWriter{format: registryHiveFormat{major: 1, minor: 3}}
	cell := w.writeCell(bytes.Repeat([]byte{0x71}, 20592))
	w.finishBin()
	data := append(make([]byte, hiveBaseBlockSize), w.data...)
	binary.LittleEndian.PutUint32(data[24:], 5)
	h := &registryHive{file: testHiveFile(data)}
	if _, err := h.readValueData(20592, cell); err == nil {
		t.Fatal("modern large value accepted a direct cell instead of db")
	}
}

func TestRegistryLargeValueMutableInsertion(t *testing.T) {
	data, err := buildRegistryHive(newRegistryTree("SYSTEM"))
	if err != nil {
		t.Fatal(err)
	}
	h := &mutableHive{data: data}
	want := bytes.Repeat([]byte{0x53}, hiveBigDataSegmentSize*3+1)
	cell, err := h.writeValue("Large", registryData{typ: regBinary, data: want})
	if err != nil {
		t.Fatal(err)
	}
	r, err := newRegistryHive(testHiveFile(h.data))
	if err != nil {
		t.Fatal(err)
	}
	value, err := r.readValue(cell)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value.raw, want) {
		t.Fatal("mutable insertion changed large value")
	}
}

func TestRegistryLargeValueRejectsMalformedSegments(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     uint16
		firstSize int
		lastSize  int
	}{
		{"missing", 1, hiveBigDataSegmentSize, hiveBigDataSegmentSize},
		{"extra", 3, hiveBigDataSegmentSize, hiveBigDataSegmentSize},
		{"short", 2, hiveBigDataSegmentSize - 8, hiveBigDataSegmentSize},
		{"short-final", 2, hiveBigDataSegmentSize, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &hiveWriter{}
			first := w.writeCell(make([]byte, tc.firstSize))
			second := w.writeCell(make([]byte, tc.lastSize))
			list := make([]byte, 8)
			binary.LittleEndian.PutUint32(list, first)
			binary.LittleEndian.PutUint32(list[4:], second)
			desc := make([]byte, 8)
			copy(desc, "db")
			binary.LittleEndian.PutUint16(desc[2:], tc.count)
			binary.LittleEndian.PutUint32(desc[4:], w.writeCell(list))
			cell := w.writeCell(desc)
			w.finishBin()
			data := append(make([]byte, hiveBaseBlockSize), w.data...)
			binary.LittleEndian.PutUint32(data[24:], 5)
			h := &registryHive{file: testHiveFile(data)}
			if _, err := h.readValueData(hiveBigDataSegmentSize+1, cell); err == nil {
				t.Fatal("accepted malformed segmentation")
			}
		})
	}
}
