package ibmisave

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

type watchedFile struct {
	*starfile.Bytes
	reads int
}

func (w *watchedFile) ReadAt(p []byte, off int64) (int, error) {
	w.reads++
	return w.Bytes.ReadAt(p, off)
}

func TestLibraryPlan(t *testing.T) {
	f := &watchedFile{Bytes: &starfile.Bytes{Data: fixture()}}
	tree, err := auto.Tree([]auto.Entry{{Name: "QLANGID", Kind: "directory"}, {Name: "QUSRLIBS/Q7500024/QUSRSYS", Kind: "file", Reader: f}, {Name: "QUSRLIBS/Q7500030/QGPL", Kind: "file", Reader: f}}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := auto.FromView(tree, "", auto.Options{}).WithPlans()
	if err != nil {
		t.Fatal(err)
	}
	plans, err := n.Plans()
	if err != nil || len(plans) != 1 {
		t.Fatal(plans, err)
	}
	if f.reads != 0 {
		t.Fatal("proposal read contents")
	}
	base, err := n.Resolve("$plans/ibmi-libraries")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.Children(); err != nil {
		t.Fatal(err)
	}
	if f.reads != 0 {
		t.Fatal("library listing parsed bodies")
	}
	result, err := base.Resolve("QUSRSYS/V7R5M0/level00/language2924/QSRDSSPC.1/type-19db/trailer.bin")
	if err != nil {
		t.Fatal(err)
	}
	if result.Reader().Size() != 4096 {
		t.Fatal("wrong trailer")
	}
	if f.reads == 0 {
		t.Fatal("never validated input")
	}
	if _, err := base.Resolve("QGPL/V7R5M0/level00/language2930/QSRDSSPC.1/type-19db/stored.bin"); err != nil {
		t.Fatal(err)
	}
}

func TestLibraryVariants(t *testing.T) {
	for _, n := range []string{"../x", "Q75000M_", "Q75", "Q75000/4"} {
		if _, err := libraryVariant(n); err == nil {
			t.Fatal(n)
		}
	}
}
