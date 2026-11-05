package native

import (
	"errors"
	"io/fs"
	"testing"
)

func TestWindowsRootVolumeSpace(t *testing.T) {
	r, _ := rootFixture(t, false)
	total, available, err := r.Space()
	if err != nil || total == 0 || available > total {
		t.Fatalf("volume space total=%d available=%d err=%v", total, available, err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.Space(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("closed volume query: %v", err)
	}
}
