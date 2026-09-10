package windows

import (
	"io"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type deltaLimitProbe struct {
	starfile.Bytes
	size  int64
	reads int
}

func TestDeltaTraceSignatureInspectionRequiresRange(t *testing.T) {
	_, err := deltaTraceBuiltin(nil, nil,
		starlark.Tuple{starlark.Bytes(""), starlark.Bytes(""), starlark.MakeInt(0), starlark.MakeInt(1)},
		[]starlark.Tuple{{starlark.String("inspect_signatures"), starlark.True}})
	if err == nil || !strings.Contains(err.Error(), "requires a prepared-source range") {
		t.Fatalf("missing signature range: %v", err)
	}
}

func (p *deltaLimitProbe) Size() int64 { return p.size }
func (p *deltaLimitProbe) ReadAt([]byte, int64) (int, error) {
	p.reads++
	return 0, io.ErrUnexpectedEOF
}

func TestDeltaInspectionAndApplyExplicitBounds(t *testing.T) {
	for _, info := range []bool{true, false} {
		limit := int64(deltaApplyLimit)
		if info {
			limit = deltaInfoLimit
		}
		for _, maximum := range []int64{-1, 0, deltaMaximumLimit + 1, limit, limit + 1} {
			probe := &deltaLimitProbe{size: limit + 1}
			kwargs := []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt64(maximum)}}
			var err error
			if info {
				_, err = deltaInfoBuiltin(nil, nil, starlark.Tuple{probe}, kwargs)
			} else {
				_, err = deltaApplyBuiltin(nil, nil, starlark.Tuple{probe, starlark.Bytes("")}, kwargs)
			}
			if err == nil {
				t.Fatalf("info=%t maximum=%d accepted invalid probe", info, maximum)
			}
			wantRead := maximum == limit+1
			if (probe.reads != 0) != wantRead {
				t.Fatalf("info=%t maximum=%d reads=%d err=%v", info, maximum, probe.reads, err)
			}
			if wantRead && !strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()) {
				t.Fatal(err)
			}
		}
	}
}
