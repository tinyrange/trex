package auto

import (
	"errors"
	"github.com/tinyrange/trex/storage"
	"io/fs"
	"testing"
)

type sourceBytes []byte

func (b sourceBytes) Size() int64 { return int64(len(b)) }
func (b sourceBytes) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, fs.ErrInvalid
	}
	return copy(p, b[off:]), nil
}

func init() {
	Register("test-companion-context", -100, func(p []byte, r storage.Reader, o Options) (View, error) {
		if string(p) != "companion-test" {
			return nil, ErrNoMatch
		}
		if o.Source == nil || o.Source.Path != "part1/input" {
			return nil, fs.ErrInvalid
		}
		companion, err := o.Source.File("part2/data", o)
		if err != nil {
			return nil, err
		}
		return ViewFunc(func() ([]Entry, error) { return []Entry{{Name: "joined", Kind: "file", Reader: companion}}, nil }), nil
	})
}

func TestCompanionContext(t *testing.T) {
	opts := Options{}
	tree, err := Tree([]Entry{{Name: "part1/input", Kind: "file", Reader: sourceBytes("companion-test")}, {Name: "part2/data", Kind: "file", Reader: sourceBytes("payload")}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	root := FromView(tree, "", opts)
	for _, paged := range []bool{false, true} {
		if paged {
			if _, _, _, _, err := root.ChildPage(0, 10); err != nil {
				t.Fatal(err)
			}
		}
		n, err := root.Resolve("part1/input/joined")
		if err != nil {
			t.Fatal(err)
		}
		p := make([]byte, 7)
		_, err = n.Reader().ReadAt(p, 0)
		if err != nil || string(p) != "payload" {
			t.Fatal(string(p), err)
		}
	}
	c, err := root.SourceTree("part1/input")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../part2/data", "part2/../data", "/part2/data", "part2\\data"} {
		if _, err := c.File(path, opts); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal(path, err)
		}
	}
	if _, err := c.File("part1/input/joined", opts); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("lookup entered detected file", err)
	}
	if _, err := c.File("part2/data", Options{MaxEntries: 1}); !errors.Is(err, ErrLimit) {
		t.Fatal("budget", err)
	}
}
