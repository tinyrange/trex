package star

import (
	"errors"
	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestObservedDevicePreservesLeaseAndCapabilities(t *testing.T) {
	base, _ := newOverlayBlockDevice(testBlockDevice(t, 4096), 4096, 4096)
	d := &observedDevice{base: base, readCoverage: byteCoverage{limit: 8}, writeCoverage: byteCoverage{limit: 8}}
	if d.Capabilities() != base.Capabilities() || d.Geometry() != base.Geometry() {
		t.Fatal("changed device contract")
	}
	release, err := d.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.Commit(); err == nil {
		t.Fatal("lease was hidden")
	}
	release()
	for i := 0; i < 2; i++ {
		if _, err := d.WriteAt([]byte{3, 4}, 10); err != nil {
			t.Fatal(err)
		}
	}
	b := make([]byte, 2)
	if _, err := d.ReadAt(b, 10); err != nil || b[0] != 3 || b[1] != 4 {
		t.Fatalf("read: %v %v", b, err)
	}
	if _, err := d.ReadAt(b, 4096); !errors.Is(err, block.ErrOutOfRange) {
		t.Fatalf("changed error: %v", err)
	}
	s := d.Stats()
	if s["unique_write_bytes"].String() != "2" || s["write_bytes"].String() != "4" || s["unique_read_bytes"].String() != "2" || s["errors"].String() != "1" {
		t.Fatal(s)
	}
}
func TestObservedReadOnlyDoesNotGrantWrites(t *testing.T) {
	base, _ := block.NewFileDevice(&starfile.Bytes{Data: make([]byte, 512)}, block.FileDeviceOptions{})
	d := &observedDevice{base: base, readCoverage: byteCoverage{limit: 8}, writeCoverage: byteCoverage{limit: 8}}
	if d.Capabilities().Writable {
		t.Fatal("observer granted writes")
	}
	if _, err := d.WriteAt([]byte{1}, 0); !errors.Is(err, block.ErrReadOnly) {
		t.Fatalf("write: %v", err)
	}
}
