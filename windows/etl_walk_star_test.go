package windows

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func walkFixture() []byte {
	le := binary.LittleEndian
	event := func(group, op byte, tick uint64, payload []byte) []byte {
		n := 16 + len(payload)
		b := make([]byte, (n+7)&^7)
		b[0], b[2], b[3], b[6], b[7] = 2, 0x11, 0xc0, op, group
		le.PutUint16(b[4:], uint16(n))
		le.PutUint64(b[8:], tick)
		copy(b[16:], payload)
		return b
	}
	buffer := func(records ...[]byte) []byte {
		b := make([]byte, 4096)
		le.PutUint32(b, 4096)
		off := 72
		for _, r := range records {
			copy(b[off:], r)
			off += len(r)
		}
		le.PutUint32(b[48:], uint32(off))
		return b
	}
	h := make([]byte, 280)
	le.PutUint32(h, 4096)
	le.PutUint32(h[12:], 1)
	le.PutUint64(h[16:], 100000000)
	le.PutUint32(h[32:], 1)
	le.PutUint32(h[36:], 3)
	le.PutUint32(h[44:], 8)
	le.PutUint64(h[256:], 1000)
	le.PutUint64(h[264:], 1)
	le.PutUint32(h[272:], 1)
	data := buffer(event(0, 0, 1000, h))
	data = append(data, buffer(event(5, 50, 3000, []byte{0x11}), event(3, 1, 2500, []byte{0x33}))...)
	return append(data, buffer(event(5, 50, 2000, []byte{0x22}))...)
}

func TestETLWalkFiltersOwnershipAndFailures(t *testing.T) {
	resources := lifecycle.New()
	defer resources.Close()
	thread := &starlark.Thread{Name: "etl-walk-test"}
	thread.SetLocal(lifecycle.ResourcesKey, resources)
	data := walkFixture()
	var records []*starfile.Record
	visit := starlark.NewBuiltin("visit", func(_ *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		records = append(records, a[0].(*starfile.Record))
		return starlark.None, nil
	})
	call := func(data []byte, callback starlark.Value, kw ...starlark.Tuple) error {
		_, err := etlWalkBuiltin(thread, nil, starlark.Tuple{starfile.NewReader("trace", &starfile.Bytes{Data: data}), callback}, kw)
		return err
	}
	filter := starlark.Tuple{starlark.String("group"), starlark.MakeInt(5)}
	if err := call(data, visit, filter); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%d", len(records))
	}
	for i, want := range []string{"\x11", "\x22"} {
		payload, _ := records[i].Attr("payload")
		if string(payload.(starlark.Bytes)) != want {
			t.Fatalf("aliased payload: %q", payload)
		}
	}
	tick, _ := records[0].Attr("tick")
	if tick.String() != "3000" {
		t.Fatal("visitor changed file order")
	}
	records = nil
	if err := call(data, visit, filter, starlark.Tuple{starlark.String("max_tick"), starlark.MakeInt(2500)}); err != nil || len(records) != 1 {
		t.Fatalf("tick filter: %v, %d", err, len(records))
	}
	if err := call(data, visit, filter, starlark.Tuple{starlark.String("max_events"), starlark.MakeInt(3)}); err == nil {
		t.Fatal("event bound must count filtered records")
	}
	if err := call(data[:len(data)-1], visit, filter); err == nil {
		t.Fatal("truncation hidden by filter")
	}
	sentinel := errors.New("callback sentinel")
	bad := starlark.NewBuiltin("bad", func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
		return nil, sentinel
	})
	if err := call(data, bad, filter); !errors.Is(err, sentinel) {
		t.Fatalf("callback error: %v", err)
	}
	if err := call(data, visit, starlark.Tuple{starlark.String("opcode"), starlark.MakeInt(256)}); err == nil {
		t.Fatal("invalid filter accepted")
	}
}
