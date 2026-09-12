package macresource

import (
	"fmt"

	"github.com/tinyrange/trex/archive/internal/instacomp"
)

func (d *resourceDecoder) instacomp() error {
	var err error
	d.output, d.pos, err = instacomp.Decode(d.input, d.output, d.limit, d.limit, 0)
	if err != nil {
		return err
	}
	if d.pos != len(d.input) {
		return fmt.Errorf("trailing dcmp3 bytes: consumed %d of %d", d.pos, len(d.input))
	}
	return nil
}
