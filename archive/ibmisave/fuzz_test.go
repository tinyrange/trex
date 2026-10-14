package ibmisave

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func FuzzOpticalSave(f *testing.F) {
	f.Add(fixture())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		for _, profile := range []string{"catalog", "boot750"} {
			a, err := OpenProfile(&starfile.Bytes{Data: b}, 64, profile)
			if err != nil {
				continue
			}
			if len(a.Objects) > 64 || a.Groups < 1 {
				t.Fatal("unbounded archive")
			}
			for _, o := range a.Objects {
				v := &objectMetadataView{object: o}
				v.Metadata()
				v.Entries()
				for _, s := range o.Sections {
					r, err := s.LogicalReader()
					if err != nil {
						t.Fatal(err)
					}
					var p [16]byte
					r.ReadAt(p[:], 0)
					o.StoredAt(s.Address, min(uint64(s.Data.Size()), 16))
				}
			}
		}
	})
}
