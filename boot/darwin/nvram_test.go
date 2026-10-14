package darwin

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"strings"
	"testing"
)

func TestEmptyARM64NVRAM(t *testing.T) {
	b, err := EmptyARM64NVRAM(8192)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(b[16:]) != adler32.Checksum(b[20:]) {
		t.Fatal("invalid bank checksum")
	}
	offset := 0
	for j, name := range []string{"nvram", "common", "system"} {
		h := b[offset : offset+16]
		if string(h[4:4+len(name)]) != name {
			t.Fatal("wrong partition", j)
		}
		// Independent one's-complement sum: checksum and the other header
		// bytes must have equal residues modulo 255.
		sum := int(h[0])
		for _, v := range h[2:] {
			sum += int(v)
		}
		if sum%255 != int(h[1])%255 {
			t.Fatal("invalid CHRP header checksum")
		}
		n := int(binary.LittleEndian.Uint16(h[2:])) * 16
		if n < 16 || n > len(b)-offset {
			t.Fatal("partition outside bank")
		}
		offset += n
	}
	if offset != len(b) {
		t.Fatal("partitions do not cover bank")
	}
	for _, n := range []int{0, 4095, 65568} {
		if _, e := EmptyARM64NVRAM(n); e == nil {
			t.Fatal("accepted invalid size", n)
		}
	}
}

func TestARM64NVRAMStringPartitions(t *testing.T) {
	common := map[string]string{"zeta": "a==", "empty": "", "alpha": "line one\nline two"}
	system := map[string]string{"fixture-config": `{"mode":"test","unicode":"héllo"}`}
	b, err := ARM64NVRAM(8192, common, system)
	if err != nil {
		t.Fatal(err)
	}
	for _, partition := range []struct {
		offset int
		data   string
	}{{48, "alpha=line one\nline two\x00empty=\x00zeta=a==\x00"}, {4128, "fixture-config=" + system["fixture-config"] + "\x00"}} {
		end := partition.offset + len(partition.data)
		if string(b[partition.offset:end]) != partition.data || b[end] != 0 {
			t.Fatalf("wrong or unterminated partition records at %d", partition.offset)
		}
	}
	if binary.LittleEndian.Uint32(b[16:]) != adler32.Checksum(b[20:]) || binary.LittleEndian.Uint32(b[20:]) != 1 {
		t.Fatal("variable contents missing from generation/checksum")
	}
	common["alpha"] = "changed"
	if !bytes.Contains(b, []byte("alpha=line one\nline two\x00")) {
		t.Fatal("input mutation changed encoded bank")
	}
}

func TestARM64NVRAMVariableBounds(t *testing.T) {
	// A 4096-byte bank has 2016 bytes in each partition after its header.
	// Keep the record's NUL and the empty name that terminates the list.
	maximum := strings.Repeat("x", 2012)
	if _, err := ARM64NVRAM(4096, map[string]string{"x": maximum}, nil); err != nil {
		t.Fatal("largest terminated record rejected", err)
	}
	for _, vars := range []map[string]string{
		{"": "value"}, {"a=b": "value"}, {"bad\x00name": "value"}, {"bad\xff": "value"},
		{"x": "bad\x00value"}, {"x": "bad\xffvalue"}, {"x": maximum + "x"},
		{"x": maximum, "y": ""},
	} {
		for _, system := range []bool{false, true} {
			commonVars, systemVars := vars, map[string]string(nil)
			if system {
				commonVars, systemVars = nil, vars
			}
			if _, err := ARM64NVRAM(4096, commonVars, systemVars); err == nil {
				t.Fatalf("invalid variable map accepted: system=%v", system)
			}
		}
	}
	for _, size := range []int{4096, 65536} {
		empty, err := EmptyARM64NVRAM(size)
		if err != nil {
			t.Fatal(err)
		}
		explicit, err := ARM64NVRAM(size, map[string]string{}, map[string]string{})
		if err != nil || !bytes.Equal(empty, explicit) {
			t.Fatal("empty constructor changed default encoding", err)
		}
	}
}
