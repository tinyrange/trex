package native

import (
	"crypto/sha256"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestComponentSourceBindingRejectsForeignReaders(t *testing.T) {
	hash := sha256.Sum256([]byte("installed"))
	stage := &uup.CumulativeStage{Graph: &uup.CumulativeGraph{Payloads: []uup.DeltaPayload{{Target: uup.ContentDescriptor{Name: "target", Length: 9, SHA256: hash}}}}}
	plan := uup.StageEffectPlan{Files: []uup.StageFileEffect{{Kind: "component-file", SourceMode: "payload", SourceName: "target", ExpectedSHA256: &hash}}}
	shared, err := newStageContentCache(128 << 20)
	if err != nil {
		t.Fatal(err)
	}
	record, err := componentStagingRecordWithCache(stage, plan, nil, shared)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := componentStagingRecordWithCache(stage, plan, nil, shared)
	if err != nil {
		t.Fatal(err)
	}
	thread := &starlark.Thread{}
	open := func(record starlark.Value) starlark.Value {
		f, _ := record.(starlark.HasAttrs).Attr("open")
		v, err := starlark.Call(thread, f, starlark.Tuple{starlark.MakeInt(0)}, []starlark.Tuple{{starlark.String("lazy"), starlark.True}})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	own := open(record)
	check, _ := record.(starlark.HasAttrs).Attr("is_source")
	reverse, _ := record.(starlark.HasAttrs).Attr("create_recovery")
	for _, row := range []struct {
		file starlark.Value
		want bool
	}{{own, true}, {open(foreign), false}, {starfile.NewReader("equal bytes", &starfile.Bytes{Data: []byte("installed")}), false}, {starlark.None, false}} {
		result, err := starlark.Call(thread, check, starlark.Tuple{starlark.MakeInt(0), row.file}, nil)
		if err != nil || result != starlark.Bool(row.want) {
			t.Fatal("source binding", result, err)
		}
		_, err = starlark.Call(thread, reverse, starlark.Tuple{starlark.MakeInt(0), starlark.MakeInt(0)}, []starlark.Tuple{{starlark.String("lazy"), starlark.True}, {starlark.String("audit"), starlark.False}, {starlark.String("literal"), starlark.True}, {starlark.String("installed"), row.file}})
		// Own provenance advances to edge validation (this fixture deliberately
		// lacks a reverse basis). Foreign readers must fail before that boundary.
		if err == nil || (strings.Contains(err.Error(), "installed reader") == row.want) {
			t.Fatalf("recovery provenance: own=%v error=%v", row.want, err)
		}
	}
}
