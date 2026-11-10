package native

import (
	"crypto/sha256"
	"fmt"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/uup"
	"go.starlark.net/starlark"
)

func TestLazyMetadataOwnsAdmittedSnapshot(t *testing.T) {
	data := []byte("immutable metadata")
	hash := sha256.Sum256(data)
	index := fmt.Sprintf(`<Container name="u.cab" type="CAB" length="%d" version="1"><Files><File id="1" name="target" length="%d"><Hash alg="SHA256" value="%x"/><Delta><Source type="RAW" name="0"><Hash alg="SHA256" value="%x"/></Source></Delta></File></Files></Container>`, len(data), len(data), hash, hash)
	backing := &starfile.Bytes{Data: compositionTestCAB(t, []string{"_manifest_.cix.xml", "0"}, [][]byte{[]byte(index), data})}
	stage, err := uup.OpenCanonicalStage("fixture", backing)
	if err != nil {
		t.Fatal(err)
	}
	plan := uup.StageEffectPlan{Files: []uup.StageFileEffect{{Kind: "manifest", SourceMode: "metadata", SourceName: "0", StorePath: "owned.manifest"}}}
	// A zero-sized content cache forces every read back through the opener.
	cache, err := newStageContentCache(0)
	if err != nil {
		t.Fatal(err)
	}
	record, err := componentStagingRecordWithCache(stage, plan, nil, cache)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := record.(starlark.HasAttrs).Attr("open")
	value, err := starlark.Call(&starlark.Thread{}, open, starlark.Tuple{starlark.MakeInt(0)}, []starlark.Tuple{{starlark.String("lazy"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	stage.ReleaseReadCaches()
	// Destroy the archive only after admission. No later namespace lookup or
	// reconstruction may be needed for the immutable metadata member.
	for i := range backing.Data {
		backing.Data[i] = 0
	}
	for range 2 {
		got, err := starfile.ReadAll(value.(starfile.File))
		if err != nil || string(got) != string(data) {
			t.Fatalf("snapshot read %q %v", got, err)
		}
	}
}
