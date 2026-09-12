package rms

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestVariableRecords(t *testing.T) {
	attrs := make([]byte, 32)
	attrs[0], attrs[1], attrs[2] = 2, 8, 3
	data := make([]byte, 516)
	copy(data, []byte{3, 0, 'a', 'b', 'c', 0x77, 0, 0, 0xff, 0xff})
	copy(data[512:], []byte{2, 0, 'x', 'y'})
	records, err := VariableRecords(bytes.NewReader(data), attrs, 3)
	if err != nil || len(records) != 3 {
		t.Fatal(records, err)
	}
	for i, want := range []string{"abc", "", "xy"} {
		r := records[i]
		got, err := io.ReadAll(io.NewSectionReader(r.Data, 0, r.Data.Size()))
		if err != nil || string(got) != want || r.Control.Size() != 0 {
			t.Fatal(i, string(got), err)
		}
	}
	if records[2].Offset != 512 {
		t.Fatal("padding included")
	}
	data[2] = 'z'
	var b [1]byte
	_, _ = records[0].Data.ReadAt(b[:], 0)
	if b[0] != 'z' {
		t.Fatal("copied payload")
	}
	if _, err := VariableRecords(bytes.NewReader(data), attrs, 2); err == nil {
		t.Fatal("limit")
	}
}

func TestVFC(t *testing.T) {
	attrs := make([]byte, 32)
	attrs[0], attrs[1], attrs[2], attrs[15] = 3, 4, 3, 2
	data := []byte{5, 0, 1, 0x8d, 'a', 'b', 'c', 0}
	r, err := VariableRecords(bytes.NewReader(data), attrs, 1)
	if err != nil || len(r) != 1 {
		t.Fatal(r, err)
	}
	control, _ := io.ReadAll(io.NewSectionReader(r[0].Control, 0, 2))
	payload, _ := io.ReadAll(io.NewSectionReader(r[0].Data, 0, 3))
	if !bytes.Equal(control, []byte{1, 0x8d}) || string(payload) != "abc" {
		t.Fatal(control, payload)
	}
	attrs[15] = 6
	if _, err := VariableRecords(bytes.NewReader(data), attrs, 1); err == nil {
		t.Fatal("short control")
	}
}

func TestVariableBounds(t *testing.T) {
	attrs := make([]byte, 32)
	attrs[0] = 2
	for _, data := range [][]byte{{0}, {3, 0, 'a'}, {1, 0, 'a'}, {255, 255}} {
		if _, err := VariableRecords(bytes.NewReader(data), attrs, 10); err == nil {
			t.Fatal("accepted truncation", data)
		}
	}
	data := make([]byte, 514)
	binary.LittleEndian.PutUint16(data, 512)
	if _, err := VariableRecords(bytes.NewReader(data), attrs, 1); err != nil {
		t.Fatal("valid span", err)
	}
	attrs[1] = 8
	if _, err := VariableRecords(bytes.NewReader(data), attrs, 1); err == nil {
		t.Fatal("forbidden span")
	}
	attrs[1] = 0
	attrs[2] = 10
	if _, err := VariableRecords(bytes.NewReader(data), attrs, 1); err == nil {
		t.Fatal("maximum size")
	}
	for _, format := range []byte{0, 1, 4, 5, 0x22} {
		attrs[0] = format
		if _, err := VariableRecords(bytes.NewReader(nil), attrs, 1); err == nil {
			t.Fatal("unsupported format", format)
		}
	}
}

func FuzzVariableRecords(f *testing.F) {
	attrs := make([]byte, 32)
	attrs[0] = 2
	f.Add(attrs, []byte{3, 0, 'a', 'b', 'c', 0})
	attrs = bytes.Clone(attrs)
	attrs[0], attrs[15] = 3, 2
	f.Add(attrs, []byte{3, 0, 1, 0x8d, 'x', 0})
	f.Fuzz(func(t *testing.T, attributes, data []byte) {
		records, err := VariableRecords(bytes.NewReader(data), attributes, 1000)
		if err != nil {
			return
		}
		for _, r := range records {
			if r.Offset < 0 || r.Offset+2+r.Control.Size()+r.Data.Size() > int64(len(data)) {
				t.Fatal("record outside source")
			}
		}
	})
}
