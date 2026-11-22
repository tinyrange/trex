package ibmiimd

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestQualifiedProcedureNamesAndBudgets(t *testing.T) {
	b := make([]byte, 512)
	name := []byte{0x81, 0x82, 0x83}
	for _, at := range []int{64, 192} {
		binary.BigEndian.PutUint64(b[at:], 0x0200000000000000)
		binary.BigEndian.PutUint64(b[at+8:], 0xffffffff82001000)
		copy(b[at+56:], name)
	}
	copy(b[16:], name) // An unqualified string must not become a procedure.
	source := &starfile.Bytes{Data: b}
	p, err := FindProcedure(source, name, 2, 512)
	if err != nil || len(p) != 2 || p[0].RecordOffset != 64 || p[1].RecordOffset != 192 || p[0].Entry != 0xffffffff82001000 {
		t.Fatal(p, err)
	}
	if _, err := FindProcedure(source, name, 1, 512); err == nil {
		t.Fatal("match budget ignored")
	}
	if _, err := FindProcedure(source, name, 2, 511); err == nil {
		t.Fatal("byte budget ignored")
	}
	if p, err := FindProcedure(source, name[:2], 2, 512); err != nil || len(p) != 0 {
		t.Fatal("substring matched", p, err)
	}
	b[64+7] = 1
	b[192+15] = 1
	if p, err := FindProcedure(source, name, 2, 512); err != nil || len(p) != 0 {
		t.Fatal("invalid descriptor accepted", p, err)
	}
}
