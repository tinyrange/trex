package star

import (
	"math"
	"testing"

	"go.starlark.net/starlark"
)

type lazyTestFile struct {
	Bytes
	sizes int
}

func (*lazyTestFile) KnownSize() (int64, bool) { return 0, false }
func (f *lazyTestFile) Size() int64            { f.sizes++; return f.Bytes.Size() }

func TestBoundedLazyFileRanges(t *testing.T) {
	for _, attr := range []string{"bytes", "hex", "binary", "slice"} {
		t.Run(attr, func(t *testing.T) {
			f := &lazyTestFile{Bytes: Bytes{Data: []byte("0123456789")}}
			method := Attr(f, attr)
			v, err := starlark.Call(&starlark.Thread{}, method, starlark.Tuple{starlark.MakeInt(2), starlark.MakeInt(3)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if f.sizes != 0 {
				t.Fatal("bounded range discovered full length")
			}
			if attr == "bytes" && string(v.(starlark.Bytes)) != "234" {
				t.Fatal(v)
			}
			if attr == "slice" {
				got, err := ReadAll(v.(File))
				if err != nil || string(got) != "234" {
					t.Fatal(string(got), err)
				}
			}
			_, err = starlark.Call(&starlark.Thread{}, method, nil, nil)
			if err != nil || f.sizes != 1 {
				t.Fatal("unbounded range", f.sizes, err)
			}
		})
	}
	f := &lazyTestFile{Bytes: Bytes{Data: []byte("short")}}
	if _, err := starlark.Call(&starlark.Thread{}, Attr(f, "bytes"), starlark.Tuple{starlark.MakeInt(4), starlark.MakeInt(3)}, nil); err == nil {
		t.Fatal("short read accepted")
	}
	for _, attr := range []string{"bytes", "slice"} {
		if _, err := starlark.Call(&starlark.Thread{}, Attr(f, attr), starlark.Tuple{starlark.MakeInt(6), starlark.MakeInt(0)}, nil); err == nil {
			t.Fatal("empty range beyond end accepted", attr)
		}
	}
	if _, err := starlark.Call(&starlark.Thread{}, Attr(f, "slice"), starlark.Tuple{starlark.MakeInt(4), starlark.MakeInt(3)}, nil); err == nil {
		t.Fatal("slice beyond end accepted")
	}
	if _, _, err := fileRangeArgs("bytes", starlark.Tuple{starlark.MakeInt64(math.MaxInt64), starlark.MakeInt(2)}, nil, f); err == nil {
		t.Fatal("overflow accepted")
	}
}
