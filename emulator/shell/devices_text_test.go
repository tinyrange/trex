package shell

import (
	"bytes"
	"context"
	"errors"
	"github.com/tinyrange/trex/channel"
	"io/fs"
	"strings"
	"testing"
)

type testTerminal struct{ bytes.Buffer }

func (*testTerminal) IsTerminal() bool { return true }
func TestTerminalDescriptors(t *testing.T) {
	var out testTerminal
	r, e := Run(context.Background(), strings.NewReader(`test -t 1 || exit 1; exec 3>&1; test -t 3 || exit 2; exec 3>&-; if test -t 3; then exit 3; fi; if test -t 1 >file; then exit 4; fi; if test -t 0; then exit 5; fi`), "test", Config{FS: testFS(t), Stdout: &out})
	if e != nil || r.Status != 0 {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestFullDevice(t *testing.T) {
	m := testFS(t)
	st, e := m.Stat("/dev/full")
	if e != nil || st.Mode()&(fs.ModeDevice|fs.ModeCharDevice) != fs.ModeDevice|fs.ModeCharDevice {
		t.Fatalf("%v %v", st, e)
	}
	for _, flags := range []OpenFlags{Read, Write, Read | Write} {
		f, e := m.Open("/dev/full", flags)
		if e != nil {
			t.Fatal(e)
		}
		b := []byte{1, 2, 3}
		n, e := f.Read(b)
		if flags&Read != 0 {
			if e != nil || n != 3 || !bytes.Equal(b, make([]byte, 3)) {
				t.Fatalf("read %d %v %v", n, e, b)
			}
		} else if !errors.Is(e, fs.ErrPermission) {
			t.Fatal(e)
		}
		n, e = f.Write([]byte("x"))
		want := channel.ErrNoSpace
		if flags&Write == 0 {
			want = fs.ErrPermission
		}
		if n != 0 || !errors.Is(e, want) {
			t.Fatalf("write %d %v", n, e)
		}
		f.Close()
	}
}
func TestWCStreaming(t *testing.T) {
	for _, tc := range []struct{ script, input, want string }{
		{`wc`, "one two\nthree", "1 3 13\n"},
		{`wc -lc`, strings.Repeat("x", 32769) + "\n", "1 32770\n"},
		{`printf 'a b\n' >a; printf tail >b; wc -wl a b`, "", "1 2 a\n0 1 b\n1 3 total\n"},
		{`wc -w`, "a\tb\rc\vd\fe", "5\n"},
	} {
		var out bytes.Buffer
		r, e := Run(context.Background(), strings.NewReader(tc.script), "test", Config{FS: testFS(t), Stdin: strings.NewReader(tc.input), Stdout: &out})
		if e != nil || r.Status != 0 || out.String() != tc.want {
			t.Fatalf("%s: %+v %v %q", tc.script, r, e, out.String())
		}
	}
}
