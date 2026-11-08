package cc

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/vmm"
)

type failingNVMeBacking struct {
	block.Device
	err error
}

func (d failingNVMeBacking) ReadAt(b []byte, off int64) (int, error) {
	b[0] = 0x71
	return 1, d.err
}
func (d failingNVMeBacking) WriteAt(b []byte, off int64) (int, error) { return 2, d.err }

func TestNVMeBackingFailurePreservesIO(t *testing.T) {
	failure := errors.New("source identity mismatch")
	diagnostics := new(diskIOFailures)
	disk := nvmeDisk{disk: vmm.Disk{Device: failingNVMeBacking{err: failure}}, failures: diagnostics}
	b := make([]byte, 4)
	if n, err := disk.ReadAt(b, 8192); n != 1 || err != failure || b[0] != 0x71 {
		t.Fatalf("read changed: n=%d err=%v bytes=%x", n, err, b)
	}
	if n, err := disk.WriteAt(b, 12288); n != 2 || err != failure {
		t.Fatalf("write changed: n=%d err=%v", n, err)
	}
	count, rows := diagnostics.snapshot()
	if count != 2 || len(rows) != 2 {
		t.Fatalf("diagnostics %d %#v", count, rows)
	}
	read := rows[0].(map[string]any)
	if read["offset"] != int64(8192) || read["requested"] != 4 || read["completed"] != 1 || read["error"] != failure.Error() {
		t.Fatalf("read diagnostic: %#v", read)
	}
	read["offset"] = int64(0)
	_, next := diagnostics.snapshot()
	if next[0].(map[string]any)["offset"] != int64(8192) {
		t.Fatal("snapshot aliases stored diagnostics")
	}
	var absent *diskIOFailures
	absent.record("read", 0, 4, 0, io.EOF)
}

func TestNVMeBackingDiagnosticsConcurrentBound(t *testing.T) {
	d := new(diskIOFailures)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 50; n++ {
				d.record("read", int64(n), 4, 0, io.EOF)
				d.snapshot()
				d.record("read", 0, 4, 4, nil)
			}
		}()
	}
	wg.Wait()
	d.record("write", 9999, 4, 1, errors.New(strings.Repeat("x", 2048)))
	count, rows := d.snapshot()
	if count != 401 || len(rows) != 16 {
		t.Fatalf("unbounded/lost diagnostics: %d %d", count, len(rows))
	}
	last := rows[15].(map[string]any)
	if last["offset"] != int64(9999) || len(last["error"].(string)) != 1024 {
		t.Fatalf("last diagnostic: %#v", last)
	}
}
