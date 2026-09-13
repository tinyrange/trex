package cc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMemoryChannelWrapAndOwnership(t *testing.T) {
	memory := make([]byte, channelSize)
	// Exercise both ring wrap and uint32 sequence wrap.
	start := uint32(0xfffffff0)
	binary.LittleEndian.PutUint32(memory[32:], start)
	binary.LittleEndian.PutUint32(memory[36:], start)
	data := bytes.Repeat([]byte{0xab}, 80)
	if n, err := transfer(memory, data, true); err != nil || n != len(data) {
		t.Fatalf("%d %v", n, err)
	}
	if binary.LittleEndian.Uint32(memory[36:]) != start {
		t.Fatal("host changed guest consumer")
	}
	for i, v := range data {
		if memory[64+int((start+uint32(i))%1024)] != v {
			t.Fatal("wrapped payload")
		}
	}
	// Reverse direction: guest published a response across the same wrap.
	binary.LittleEndian.PutUint32(memory[40:], start+80)
	binary.LittleEndian.PutUint32(memory[44:], start)
	copy(memory[1088:2112], memory[64:1088])
	read := make([]byte, 80)
	if n, err := transfer(memory, read, false); err != nil || n != 80 || !bytes.Equal(read, data) {
		t.Fatalf("%d %v %x", n, err, read)
	}
	if binary.LittleEndian.Uint32(memory[40:]) != start+80 {
		t.Fatal("host changed guest producer")
	}
	binary.LittleEndian.PutUint32(memory[40:], 2000)
	binary.LittleEndian.PutUint32(memory[44:], 0)
	if _, err := transfer(memory, read, false); err == nil {
		t.Fatal("accepted corrupt producer")
	}
}
