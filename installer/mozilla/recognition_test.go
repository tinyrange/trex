package mozilla

import (
	"errors"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestUnrelatedFileResource(t *testing.T) {
	for _, signature := range []string{"SZDD", "BM", "ordinary resource"} {
		b := resourcePE(t)
		copy(b[768:], signature+"xxxxxxxxxxxxxxxx")
		if _, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{}); !errors.Is(err, auto.ErrNoMatch) {
			t.Fatalf("%q: %v", signature, err)
		}
	}
}
