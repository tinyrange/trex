package ultrix

import (
	"encoding/binary"
	"errors"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestPartitionRetainsParentLabel(t *testing.T) {
	data := fixture(binary.LittleEndian)
	binary.LittleEndian.PutUint32(data[9564:], 0x11954)
	binary.LittleEndian.PutUint32(data[31*512+440+24:], 1000)
	// UFS magic is a candidate, not proof: its parser must reject this
	// synthetic invalid superblock after the parent label is skipped.
	_, err := auto.Identify(&starfile.Bytes{Data: data}, auto.Options{})
	if err == nil || errors.Is(err, auto.ErrNoMatch) {
		t.Fatal("invalid UFS accepted", err)
	}
	if !strings.Contains(err.Error(), "auto ufs:") {
		t.Fatal("parent label claimed a partition", err)
	}
}

func TestAutoLabel(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		root := auto.Open(&starfile.Bytes{Data: fixture(order)}, "", auto.Options{})
		meta, err := root.Metadata()
		if err != nil || meta.Format != "ultrix_label" {
			t.Fatal(meta, err)
		}
		children, err := root.Children()
		if err != nil || len(children) != 8 {
			t.Fatal(children, err)
		}
		for _, node := range children {
			if node.Reader() != nil {
				if _, err := node.Metadata(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
