package star

import (
	"bufio"
	"fmt"
	"go.starlark.net/starlark"
	"net"
	"strings"
	"testing"
	"time"
)

const testManifest = "API\t1\t64\nFN\techo\tstr\tsEcho\nARG\tvalue\tstr\tsText\nEND\nDONE\n"

func TestExtensionExchange(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	server := make(chan error, 1)
	go func() {
		rd := bufio.NewReader(b)
		check := func(want string) error {
			got, err := rd.ReadString('\n')
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("got %q, want %q", got, want)
			}
			return nil
		}
		if err := check("?\n"); err != nil {
			server <- err
			return
		}
		// A fragmented discovery must not be confused with EOF or separate messages.
		for _, c := range []byte(testManifest) {
			if _, err := b.Write([]byte{c}); err != nil {
				server <- err
				return
			}
		}
		if err := check("CALL\techo\tsone\\ttwo\\n\\\\\n"); err != nil {
			server <- err
			return
		}
		fmt.Fprint(b, "ERR\tsrejected\tsNo effect\n")
		if err := check("CALL\techo\tsok\n"); err != nil {
			server <- err
			return
		}
		fmt.Fprint(b, "OK\tsok\n")
		if err := check("CALL\techo\tsbad\n"); err != nil {
			server <- err
			return
		}
		fmt.Fprint(b, "OK\tsbad\textra\n")
		one := make([]byte, 1)
		_, err := b.Read(one)
		if err == nil {
			server <- fmt.Errorf("malformed reply did not close client")
			return
		}
		server <- nil
	}()
	v, err := extensionBuiltin(nil, nil, starlark.Tuple{New("test", a)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := v.(*Extension)
	defer e.close()
	echo, _ := e.Attr("echo")
	call := func(s string) error {
		_, err := starlark.Call(&starlark.Thread{}, echo, starlark.Tuple{starlark.String(s)}, nil)
		return err
	}
	if err = call(strings.Repeat("x", 100)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatal("oversize not rejected locally", err)
	}
	if err = call("one\ttwo\n\\"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatal(err)
	}
	if err = call("ok"); err != nil {
		t.Fatal("ERR desynchronized session", err)
	}
	if err = call("bad"); err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatal(err)
	}
	if err = call("retry"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatal("unsafe replay", err)
	}
	if err = <-server; err != nil {
		t.Fatal(err)
	}
}
func TestExtensionTimeoutCloses(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rd := bufio.NewReader(b)
		rd.ReadString('\n')
		fmt.Fprint(b, testManifest)
		rd.ReadString('\n')
		one := make([]byte, 1)
		b.Read(one)
	}()
	v, err := extensionBuiltin(nil, nil, starlark.Tuple{New("test", a)}, []starlark.Tuple{{starlark.String("timeout"), starlark.Float(.1)}})
	if err != nil {
		t.Fatal(err)
	}
	e := v.(*Extension)
	defer e.close()
	fn, _ := e.Attr("echo")
	_, err = starlark.Call(&starlark.Thread{}, fn, starlark.Tuple{starlark.String("x")}, nil)
	if err == nil || !e.closed {
		t.Fatal("timeout did not poison session", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server not closed")
	}
}
func TestExtensionCodec(t *testing.T) {
	valid := []string{"n", "b1", "i-999999999999999999999999999", "f1.25e-2", `sC:\\WINDOWS\ttext\n`, "m1\tsreadings\ta2\ti23\tf24.5"}
	for _, wire := range valid {
		p := strings.Split(wire, "\t")
		v, err := decodeExtensionValue(&p, 0)
		if err != nil || len(p) != 0 {
			t.Fatal(wire, err)
		}
		encoded, err := encodeExtensionValue(v, 0)
		if err != nil {
			t.Fatal(err)
		}
		p = strings.Split(encoded, "\t")
		w, err := decodeExtensionValue(&p, 0)
		if err != nil {
			t.Fatal(err)
		}
		if equal, err := starlark.Equal(v, w); err != nil || !equal {
			t.Fatal("roundtrip", wire, err)
		}
	}
	for _, wire := range []string{"i+1", "fNaN", `sbad\q`, "a2\ti1", "m2\tsk\ti1\tsk\ti2", "m1\ti3\tn", "s\x00", "p1", "m99999999999999999999999"} {
		p := strings.Split(wire, "\t")
		if _, err := decodeExtensionValue(&p, 0); err == nil {
			t.Fatalf("accepted %q", wire)
		}
	}
}
