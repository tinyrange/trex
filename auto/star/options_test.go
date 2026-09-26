package star

import (
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func TestOptionalExpandedLimit(t *testing.T) {
	var got auto.Options
	auto.Register("test-star-stream-limit", -100, func(p []byte, _ storage.Reader, o auto.Options) (auto.View, error) {
		if string(p) != "test-star-stream-limit" {
			return nil, auto.ErrNoMatch
		}
		got = o
		return auto.ViewFunc(func() ([]auto.Entry, error) { return nil, nil }), nil
	})
	for _, maximum := range []int64{0, 512 << 20} {
		var kwargs []starlark.Tuple
		if maximum != 0 {
			kwargs = []starlark.Tuple{{starlark.String("maximum"), starlark.MakeInt64(maximum)}}
		}
		v, err := Builtin(nil, nil, starlark.Tuple{starlark.Bytes("test-star-stream-limit")}, kwargs)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.(*Value).Node.Metadata(); err != nil {
			t.Fatal(err)
		}
		if got.StreamingMaximum() != maximum || got.MaxExpandedBytes != 512<<20 {
			t.Fatal(got.StreamingMaximum(), got.MaxExpandedBytes)
		}
	}
	for _, maximum := range []starlark.Value{starlark.MakeInt(0), starlark.MakeInt(-1), starlark.None} {
		if _, err := Builtin(nil, nil, starlark.Tuple{starlark.Bytes("test-star-stream-limit")}, []starlark.Tuple{{starlark.String("maximum"), maximum}}); err == nil {
			t.Fatal("invalid explicit limit", maximum)
		}
	}
}
