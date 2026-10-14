package udf

import (
	"bytes"
	"encoding/binary"
	_ "github.com/tinyrange/trex/archive/ibmiimd"
	"github.com/tinyrange/trex/auto"
	_ "github.com/tinyrange/trex/binary/xcoff"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func nestedBootFixture() ([]byte, int) {
	be := binary.BigEndian
	object := make([]byte, 68)
	be.PutUint16(object, 0x01df)
	be.PutUint16(object[2:], 1)
	copy(object[20:], ".data")
	be.PutUint32(object[32:], 0x2000)
	be.PutUint32(object[36:], 4)
	be.PutUint32(object[40:], 64)
	be.PutUint32(object[56:], 0x40)
	copy(object[64:], "ABCD")
	var bits []byte
	for _, b := range object {
		bits = append(bits, 0)
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1)
		}
	}
	bits = append(bits, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1)
	payload := make([]byte, ((len(bits)+31)/32)*4)
	for i, b := range bits {
		payload[i/8] |= b << uint(7-i%8)
	}
	frame := make([]byte, 12+len(payload))
	be.PutUint32(frame, 0x03000080)
	be.PutUint32(frame[4:], uint32(len(frame)))
	be.PutUint32(frame[8:], uint32(len(object)))
	copy(frame[12:], payload)
	packed := make([]byte, 16+len(frame))
	be.PutUint32(packed, uint32(len(packed)))
	be.PutUint32(packed[4:], uint32(len(object)))
	be.PutUint32(packed[8:], 1)
	copy(packed[16:], frame)
	imd := make([]byte, 65536+512)
	copy(imd, []byte{0xc9, 0xd4, 0xc4, 0xf1})
	be.PutUint32(imd[4096:], 0x80000001)
	copy(imd[4100:], []byte{0xd3, 0xc9, 0xc4, 0xc4, 0xc9, 0xd9, 0x40, 0x40})
	be.PutUint32(imd[4128:], 0x8ff00010)
	be.PutUint32(imd[4132:], 128)
	be.PutUint32(imd[4136:], 1)
	be.PutUint32(imd[4140:], 0x80000000)
	copy(imd[4160:], []byte{0xc5, 0xd5, 0xc4, 0x40})
	copy(imd[65536:], packed)
	raw := make([]byte, 64*2048+len(imd))
	copy(raw, bootFixture())
	binary.LittleEndian.PutUint32(raw[18*2048+76:], uint32(len(imd)))
	copy(raw[64*2048:], imd)
	return raw, 64*2048 + 65536 + len(packed) - 1
}
func nestedNode(t *testing.T, raw []byte) *auto.Node {
	t.Helper()
	source := &starfile.Bytes{Data: raw}
	descriptors, err := ReadBootDescriptors(source)
	if err != nil {
		t.Fatal(err)
	}
	image := &udfImage{file: source, bootDescriptors: descriptors}
	return auto.Open(image.virtualFile("/$metadata/boot0.extent.bin"), "boot", auto.Options{})
}
func TestNestedBootIMDPackedXCOFFAndLazyFailure(t *testing.T) {
	raw, tail := nestedBootFixture()
	node := nestedNode(t, raw)
	data, err := node.Resolve("components/8ff00010.bin/expanded.bin/sections/1.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(data.Reader())
	if err != nil || !bytes.Equal(got, []byte("ABCD")) {
		t.Fatal(got, err)
	}
	// Fresh parsing must surface a corrupt packed tail before presenting an object.
	raw[tail] |= 1
	node = nestedNode(t, raw)
	if _, err := node.Resolve("components/8ff00010.bin/expanded.bin/sections/1.bin"); err == nil {
		t.Fatal("nested lazy decode swallowed tail corruption")
	}
}
