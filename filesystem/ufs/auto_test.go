package ufs

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"sync"
	"testing"
)

func TestAutoView(t *testing.T) {
	source := &starfile.Bytes{Data: fixture(binary.LittleEndian)}
	root := auto.Open(source, "no-extension", auto.Options{})
	meta, err := root.Metadata()
	if err != nil || meta.Format != "ufs" {
		t.Fatalf("%+v %v", meta, err)
	}
	children, err := root.Children()
	if err != nil || len(children) == 0 {
		t.Fatalf("%v %v", children, err)
	}

}

func TestAutoDoesNotWalkUnrequestedDirectory(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := fixture(order)
		// The child has a valid inode, but deliberately malformed directory data.
		inode := b[32*512+3*128:]
		order.PutUint16(inode, 0x41ed)
		order.PutUint64(inode[8:], 512)
		source := &starfile.Bytes{Data: b}
		root := auto.Open(source, "", auto.Options{})
		children, err := root.Children()
		if err != nil || len(children) != 1 {
			t.Fatalf("eager traversal: %v", err)
		}
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := root.Children(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if _, err := children[0].Children(); err == nil {
			t.Fatal("invalid visited directory accepted")
		}
		if _, err := Open(source, 10, 100); err == nil {
			t.Fatal("full traversal no longer validates descendants")
		}
	}
}

func TestAutoDirectoryLimitsAndCycles(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		b := fixture(binary.LittleEndian)
		opts := auto.Options{MaxEntries: 1}
		if cycle {
			opts.MaxEntries = 10
			binary.LittleEndian.PutUint32(b[48*512+24:], 2)
		}
		if _, err := auto.Open(&starfile.Bytes{Data: b}, "", opts).Children(); err == nil {
			t.Fatal("accepted cycle or exceeded entry budget")
		}
	}
}
