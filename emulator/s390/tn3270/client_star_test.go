package tn3270

import (
	"bytes"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestFeedErrorObservationPreservesRepliesAndPoison(t *testing.T) {
	stream := append([]byte{iac, do, optBin}, frame([]byte{0x40, 0x40})...)
	for _, strict := range []bool{true, false} {
		v := &clientValue{NewClient()}
		feed, _ := v.Attr("feed")
		out, err := starlark.Call(&starlark.Thread{Name: "tn3270-test"}, feed, starlark.Tuple{starlark.Bytes(stream)}, []starlark.Tuple{{starlark.String("raise_error"), starlark.Bool(strict)}})
		if strict {
			if err == nil {
				t.Fatal("strict feed accepted malformed record")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal([]byte(out.(starlark.Bytes)), []byte{iac, will, optBin}) {
				t.Fatal("pre-error negotiation reply lost")
			}
		}
		observed, err := v.Attr("error")
		if err != nil || !strings.Contains(string(observed.(starlark.String)), "command 40 (record 1, length 2, prefix 4040)") {
			t.Fatalf("missing bounded original record evidence: %v %v", observed, err)
		}
		if _, err = v.client.Feed(frame([]byte{1, 0xc3})); err == nil {
			t.Fatal("poisoned client silently recovered")
		}
		if err = v.client.Type("test"); err == nil {
			t.Fatal("poisoned display accepted input")
		}
	}
}

func TestStateExposesFieldsAndMoveRepositionsCursor(t *testing.T) {
	v := &clientValue{NewClient()}
	thread := &starlark.Thread{Name: "tn3270-test"}
	// Erase/Write, WCC restore; SBA 0, protected SF + "A"; SF unprotected; IC.
	record := []byte{0xf5, 0xc2, 0x11, 0x40, 0x40, 0x1d, 0x60, 0xc1, 0x1d, 0x40, 0x13}
	if _, err := v.client.Feed(frame(record)); err != nil {
		t.Fatal(err)
	}
	state, _ := v.Attr("state")
	value, err := starlark.Call(thread, state, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := value.(*starlark.Dict)
	get := func(key string) starlark.Value { x, _, _ := d.Get(starlark.String(key)); return x }
	attr := string(get("attr").(starlark.String))
	if len(attr) != 1920 || attr[:4] != "apau" || get("text").(starlark.String)[1] != 'A' {
		t.Fatalf("unexpected attributes %q / text %q", attr[:8], get("text").(starlark.String)[:8])
	}
	if get("cursor").(starlark.Int).String() != "3" || get("locked") != starlark.False || get("writes").(starlark.Int).String() != "1" {
		t.Fatalf("cursor/lock/writes = %v %v %v", get("cursor"), get("locked"), get("writes"))
	}
	move, _ := v.Attr("move")
	if _, err := starlark.Call(thread, move, starlark.Tuple{starlark.MakeInt(85)}, nil); err != nil {
		t.Fatal(err)
	}
	if row, col := v.client.Display.Cursor(); row != 1 || col != 5 {
		t.Fatalf("cursor = %d,%d", row, col)
	}
	if _, err := starlark.Call(thread, move, starlark.Tuple{starlark.MakeInt(1920)}, nil); err == nil {
		t.Fatal("move accepted a position outside the buffer")
	}
}
