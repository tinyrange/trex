package registry

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestHiveSubkeyValues(t *testing.T) {
	data := make([]byte, 4096)
	copy(data, "regf")
	appendCell := func(body []byte) uint32 {
		offset := uint32(len(data) - 4096)
		size := len(body) + 4
		header := make([]byte, 4)
		binary.LittleEndian.PutUint32(header, uint32(-int32(size)))
		data = append(data, header...)
		data = append(data, body...)
		return offset
	}
	keyBody := func(name string) []byte {
		body := make([]byte, 0x4c+len(name))
		copy(body, "nk")
		binary.LittleEndian.PutUint16(body[2:4], 0x20)
		binary.LittleEndian.PutUint32(body[0x1c:0x20], 0xffffffff)
		binary.LittleEndian.PutUint32(body[0x28:0x2c], 0xffffffff)
		binary.LittleEndian.PutUint16(body[0x48:0x4a], uint16(len(name)))
		copy(body[0x4c:], name)
		return body
	}
	rootBody := keyBody("ROOT")
	root := appendCell(rootBody)
	childBody := keyBody("Package")
	child := uint32(len(data)-4096) + 12
	indexBody := make([]byte, 8)
	copy(indexBody, "li")
	binary.LittleEndian.PutUint16(indexBody[2:4], 1)
	binary.LittleEndian.PutUint32(indexBody[4:8], child)
	index := appendCell(indexBody)
	binary.LittleEndian.PutUint32(data[4096+root+4+0x14:], 1)
	binary.LittleEndian.PutUint32(data[4096+root+4+0x1c:], index)
	child = appendCell(childBody)
	valueListOffset := uint32(len(data)-4096) + 8
	valueOffset := valueListOffset
	valueList := make([]byte, 4)
	binary.LittleEndian.PutUint32(valueList, valueOffset)
	list := appendCell(valueList)
	valueOffset = uint32(len(data) - 4096)
	binary.LittleEndian.PutUint32(data[4096+list+4:], valueOffset)
	valueBody := make([]byte, 0x14+len("CurrentState"))
	copy(valueBody, "vk")
	binary.LittleEndian.PutUint16(valueBody[2:4], uint16(len("CurrentState")))
	binary.LittleEndian.PutUint32(valueBody[4:8], 0x80000004)
	binary.LittleEndian.PutUint32(valueBody[8:12], 0x70)
	binary.LittleEndian.PutUint32(valueBody[12:16], 4)
	binary.LittleEndian.PutUint16(valueBody[16:18], 1)
	copy(valueBody[0x14:], "CurrentState")
	appendCell(valueBody)
	binary.LittleEndian.PutUint32(data[4096+child+4+0x24:], 1)
	binary.LittleEndian.PutUint32(data[4096+child+4+0x28:], list)
	binary.LittleEndian.PutUint32(data[0x24:0x28], root)

	hive, err := Open(&starfile.Bytes{Name: "test", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	children, err := hive.Subkeys("/")
	if err != nil || len(children) != 1 || children[0] != "Package" {
		t.Fatalf("subkeys = %#v, err=%v", children, err)
	}
	values, err := hive.SubkeyValues("/", "CurrentState")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || !values[0].Found || values[0].Value.Type != 4 || binary.LittleEndian.Uint32(values[0].Value.Data) != 0x70 {
		t.Fatalf("values = %#v", values)
	}
}
