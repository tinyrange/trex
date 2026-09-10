package uup

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"testing"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestExpressBasisUsesDeclaredContentAliases(t *testing.T) {
	want := []byte("installed driver basis")
	descriptor := ContentDescriptor{Name: "absent-product\\driver.sys", Length: int64(len(want)), SHA256: sha256.Sum256(want)}
	alias := descriptor
	alias.Name = "installed-component\\driver.sys"
	alias.Length += 4080 // History target length differs from the delta input.
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			stage := &CumulativeStage{Graph: &CumulativeGraph{Sources: []ContentDescriptor{descriptor, alias}}}
			stage.assemblyResolver = func(d ContentDescriptor) (storage.Reader, error) {
				if d.Length != int64(len(want)) {
					t.Fatalf("lost authoritative edge length: %d", d.Length)
				}
				if d.Name != alias.Name {
					return nil, fmt.Errorf("absent %s", d.Name)
				}
				data := append([]byte(nil), want...)
				if corrupt {
					data[0] ^= 1
				}
				return &starfile.Bytes{Name: d.Name, Data: data}, nil
			}
			got, err := stage.resolveExpressBasis(&descriptor)
			if corrupt {
				if err == nil {
					t.Fatal("accepted corrupt alias")
				}
			} else if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("declared alias: %q, %v", got, err)
			}
			stage.Graph.Sources[1].SHA256 = sha256.Sum256([]byte("unrelated"))
			if _, err := stage.resolveExpressBasis(&descriptor); err == nil {
				t.Fatal("accepted different-content alias")
			}
		})
	}
}

func TestCanonicalTargetBoundIncludesWebViewWithoutExpandingCaches(t *testing.T) {
	const webViewTarget = int64(331654472)
	if maximumCanonicalTarget < webViewTarget || maximumCanonicalTarget > 512<<20 {
		t.Fatalf("WebView target outside bounded file policy: %d", maximumCanonicalTarget)
	}
	if maximumCanonicalRetainedTarget > 128<<20 || defaultMaximumDeltaRecord > 128<<20 {
		t.Fatal("large target support expanded independent cache or record bounds")
	}
}

func TestPSFRecordRangeAcceptsDefenderDefinitionsWithinTargetBound(t *testing.T) {
	for _, record := range [][2]int64{{199489776, 133705296}, {333195072, 67246677}} {
		if err := validatePSFRecordRange(record[0], record[1], 2324743656); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range [][3]int64{{-1, 1, 2}, {0, -1, 2}, {0, 3, 2}, {2, 1, 2}, {math.MaxInt64, 1, math.MaxInt64}, {0, defaultMaximumDeltaRecord + 1, defaultMaximumDeltaRecord + 1}} {
		if err := validatePSFRecordRange(r[0], r[1], r[2]); err == nil {
			t.Fatalf("invalid record accepted: %v", r)
		}
	}
	if err := validatePSFRecordRange(4, defaultMaximumDeltaRecord, defaultMaximumDeltaRecord+4); err != nil {
		t.Fatal(err)
	}
}

func TestTargetCacheEvictionPreservesReturnedReaders(t *testing.T) {
	stage := &CumulativeStage{}
	first := stage.retainTarget("first", []byte{1, 2, 3, 4}, 6)
	second := stage.retainTarget("second", []byte{5, 6, 7, 8}, 6)
	if stage.canonicalRetained != 4 || len(stage.canonicalCache) != 1 {
		t.Fatalf("unbounded retention: %d bytes, %d entries", stage.canonicalRetained, len(stage.canonicalCache))
	}
	if !bytes.Equal(first, []byte{1, 2, 3, 4}) || !bytes.Equal(second, []byte{5, 6, 7, 8}) {
		t.Fatal("eviction changed returned bytes")
	}
	oversized := stage.retainTarget("large", []byte{1, 2, 3, 4, 5, 6, 7}, 6)
	if len(oversized) != 7 || stage.canonicalRetained != 4 || len(stage.canonicalCache) != 1 {
		t.Fatal("oversized value changed cache retention")
	}
	// Reloading an evicted target must work without growing the cache.
	reloaded := stage.retainTarget("first", []byte{1, 2, 3, 4}, 6)
	if !bytes.Equal(first, reloaded) || stage.canonicalRetained != 4 {
		t.Fatal("reloaded target differs")
	}
	stage.releaseAssemblyFile("first")
	if stage.canonicalRetained != 0 || len(stage.canonicalCache) != 0 {
		t.Fatal("release after eviction retained target")
	}
}

func TestAssemblyEntryKeyUnifiesImageAndContentGraphNames(t *testing.T) {
	left := assemblyEntryKey(`/image1/Microsoft-Windows-Test~token~amd64~~1.0.mum`)
	right := assemblyEntryKey(`Microsoft-Windows-Test~token~amd64~~1.0.mum`)
	if left != right {
		t.Fatalf("keys differ: %q != %q", left, right)
	}
	backslash := assemblyEntryKey(`image1\AMD64_Test_1.0_none_hash.manifest`)
	forward := assemblyEntryKey(`amd64_test_1.0_none_hash.manifest`)
	if backslash != forward {
		t.Fatalf("slash keys differ: %q != %q", backslash, forward)
	}
}

func TestReleaseAssemblyFileEvictsExpressAndDCMTargets(t *testing.T) {
	stage := &CumulativeStage{
		canonicalCache: map[string][]byte{
			"windows\\test.manifest":        {1, 2, 3},
			"dcm\x00windows\\test.manifest": {4, 5},
		},
		canonicalRetained: 5,
	}
	stage.releaseAssemblyFile(`/WINDOWS/test.manifest`)
	if len(stage.canonicalCache) != 0 || stage.canonicalRetained != 0 {
		t.Fatalf("assembly cache after release = %#v, %d bytes", stage.canonicalCache, stage.canonicalRetained)
	}
}

func TestNameExpressBasisUsesPlannedComponentPredecessor(t *testing.T) {
	stage := &CumulativeStage{predecessorByStem: map[string]string{
		"amd64_component_token_2.0_none_new": "amd64_component_token_1.0_none_old",
	}}
	descriptor := &ContentDescriptor{Length: 7}
	got := stage.nameExpressBasis("amd64_component_token_2.0_none_new\\file.dll", descriptor)
	if got == descriptor {
		t.Fatal("basis descriptor was not copied")
	}
	if got.Name != "amd64_component_token_1.0_none_old\\file.dll" {
		t.Fatalf("basis name = %q", got.Name)
	}
	if !got.nameHint {
		t.Fatal("inferred predecessor was treated as an explicit content name")
	}
	if descriptor.Name != "" {
		t.Fatalf("input descriptor was modified: %#v", descriptor)
	}
}
