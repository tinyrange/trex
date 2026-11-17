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
