package ufs_test

import (
	"context"
	"github.com/tinyrange/trex/filesystem/openbsd"
	"github.com/tinyrange/trex/filesystem/ufs"
	"github.com/tinyrange/trex/filesystem/unixfs"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestFFSOpenBSDDiskPartitionRoundTrip(t *testing.T) {
	image, err := ufs.Build(context.Background(), []unixfs.Entry{{Path: "etc/proof", Mode: unixfs.Regular | 0644, Data: &starfile.Bytes{Data: []byte("disk-root")}}}, ufs.BuildOptions{Layout: "openbsd", Size: 8 << 20, Timestamp: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	label, err := openbsd.Open(image, 1024*512+512)
	if err != nil {
		t.Fatal(err)
	}
	root := label.Partitions[0]
	if root.Start != 1024 || root.Type != 7 || root.Data == nil {
		t.Fatalf("root partition: %+v", root)
	}
	volume, err := ufs.Open(starfile.NewReader("partition", root.Data), 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range volume.Entries {
		if entry.Path == "/etc/proof" {
			payload, err := starfile.ReadAll(entry.Data)
			if err != nil || string(payload) != "disk-root" {
				t.Fatalf("proof: %s %v", payload, err)
			}
			return
		}
	}
	t.Fatal("missing root proof")
}
