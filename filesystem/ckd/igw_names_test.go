package ckd

import (
	"bytes"
	"testing"
)

func testND() []byte {
	b := make([]byte, 4096)
	b[0], b[1], b[11], b[12], b[25], b[30] = 52, 1, 0xd5, 0xc4, 64, 1
	pos := 121
	for _, name := range []string{"ALIAS", "MEMBER"} {
		n := len(name)
		size := 5 + n + 20
		be.PutUint16(b[pos:], uint16(size))
		b[pos+2], b[pos+4] = 0xc0, byte(64-n)
		copy(b[pos+5:], eb(name, n))
		value := b[pos+5+n : pos+size]
		value[0], value[5], value[11] = 1, 1, 4
		value[12], value[13] = 0x40, 0x40 // These bytes are not the name length.
		be.PutUint16(value[14:], uint16(n))
		pos += size
	}
	be.PutUint16(b[116:], uint16(pos-116))
	be.PutUint16(b[118:], uint16(pos-116))
	b[120] = 2
	be.PutUint16(b[48:], uint16(3950-pos))
	be.PutUint16(b[50:], 3950)
	be.PutUint16(b[4094:], 0xa55a)
	return b
}
func TestNamePageBoundsAndPadding(t *testing.T) {
	b := testND()
	p, err := ParseNamePage(b)
	if err != nil || len(p.Cells) != 2 || !bytes.Equal(p.Cells[0].Name[:5], eb("ALIAS", 5)) || p.Cells[0].Name[5] != 0x40 {
		t.Fatal(p, err)
	}
	for _, offset := range []int{0, 11, 25, 50, 116, 118, 122, 124, 125, 4095} {
		bad := bytes.Clone(b)
		bad[offset] = 255
		if _, err := ParseNamePage(bad); err == nil {
			t.Fatal("bad ND accepted", offset)
		}
	}
}
func TestProgramMemberAliasAndDeclaredSize(t *testing.T) {
	b := make([]byte, 4*4096)
	testVDF(b, 1)
	descriptor := make([]byte, 64)
	descriptor[0] = 1
	nd := testND()
	copy(descriptor[1:20], nd[2:21])
	dirKey := testKey(3, 0x4002)
	dirKey[5] = 1
	allocationKey := dirKey
	be.PutUint16(allocationKey[14:], 0x7003)
	canonical := append([]byte{1, 0, 0, 8}, eb("MEMBER", 8)...)
	storageInfo := make([]byte, 85)
	storageInfo[0] = 1
	be.PutUint32(storageInfo[56:], 1)
	cells := []AttributeCell{
		{Key: dirKey, Value: descriptor},
		{Key: allocationKey, Value: testRun(2, 1)},
		{Key: testKey(4, 0x1001), Value: canonical},
		{Key: testKey(4, 0x4004), Value: storageInfo},
		{Key: testKey(4, 0x7003), Value: testRun(3, 1)},
	}
	copy(b[4096:], testAD(1, cells))
	copy(b[8192:], nd)
	program := b[3*4096:]
	copy(program, eb("IEWPLMH", 8))
	be.PutUint32(program[8:], 36)
	program[12] = 4
	be.PutUint32(program[20:], 1)
	be.PutUint16(program[24:], 7)
	be.PutUint32(program[28:], 128)
	be.PutUint32(program[32:], 16)
	be.PutUint32(program[16:], 4096)
	g, err := OpenIGW(raw(b))
	if err != nil {
		t.Fatal(err)
	}
	members, err := g.programMembers(2)
	if err != nil || len(members) != 2 || members[0].Name != "ALIAS" || !members[0].Alias || members[1].Alias {
		t.Fatal(members, err)
	}
	got := make([]byte, 4096)
	if _, err := members[0].Data.ReadAt(got, 0); err != nil || !bytes.Equal(got, program) {
		t.Fatal(err)
	}
	if _, err := g.programMembers(1); err == nil {
		t.Fatal("member limit ignored")
	}
	// E5 is accepted only for the directory allocation, not as an arbitrary
	// liveness/inline flag on other program attributes.
	allocationFlag := 4096 + 77 + 25 + len(descriptor) + 2
	b[allocationFlag] = 0xe5
	if _, err := g.programMembers(2); err != nil {
		t.Fatal(err)
	}
	canonicalFlag := allocationFlag + 25 + len(cells[1].Value)
	b[canonicalFlag] = 0xe5
	if _, err := g.programMembers(2); err == nil {
		t.Fatal("unqualified E5 accepted")
	}
	b[canonicalFlag] = 0xc0
	be.PutUint32(program[16:], 8192)
	stored, err := g.programMembers(2)
	if err != nil || stored[0].Data.Size() != 4096 || stored[0].DeclaredSize != 8192 {
		t.Fatal(stored, err)
	}
	// Alter the independently stored page count, not the PLMH image-size field.
	storageCellOffset := 4096 + 77 + (25 + len(descriptor)) + (25 + len(cells[1].Value)) + (25 + len(canonical))
	be.PutUint32(b[storageCellOffset+25+56:], 2)
	if _, err := g.programMembers(2); err == nil {
		t.Fatal("stored size mismatch accepted")
	}
}
