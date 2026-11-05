package uup

import (
	"encoding/binary"
	"testing"
)

func TestCBSDeploymentSourceInspection(t *testing.T) {
	primary := "Package_11_for_KB5126052~31bf3856ad364e35~amd64~~10.0.9347.1.update.with.dots"
	data := make([]byte, 8+len(primary)+3)
	binary.LittleEndian.PutUint32(data, uint32(len(primary)))
	binary.LittleEndian.PutUint32(data[4:], 3)
	copy(data[8:], primary)
	copy(data[8+len(primary):], []byte{0, 255, 8})
	got, err := ParseCBSDeploymentSource(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Primary != primary || got.Update != "update.with.dots" || got.Package.Version != "10.0.9347.1" || string(got.Secondary) != string([]byte{0, 255, 8}) {
		t.Fatalf("source boundary lost: %+v", got)
	}
	key := got.SourceKey
	data[len(data)-1] = 9
	if got.Secondary[2] != 8 {
		t.Fatal("result aliases input")
	}
	other, err := ParseCBSDeploymentSource(data)
	if err != nil || other.SourceKey != key {
		t.Fatalf("opaque secondary changed identity: %+v %v", other, err)
	}
	binary.LittleEndian.PutUint32(data, ^uint32(0))
	if _, err := ParseCBSDeploymentSource(data); err == nil {
		t.Fatal("accepted overflowing primary length")
	}
}
