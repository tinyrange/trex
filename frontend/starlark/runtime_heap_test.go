package starlarkfrontend

import (
	"math"
	"testing"
)

func TestHeapSampleEstimateSmallObjectsNotHiddenByLargeBuffers(t *testing.T) {
	const rate = 512 << 10
	smallObjects, smallBytes := estimateHeapSample(100, 6400, rate)
	_, largeBytes := estimateHeapSample(1, 32<<20, rate)
	if smallBytes <= largeBytes || smallObjects <= 100 {
		t.Fatalf("small-object graph hidden: objects=%g bytes=%g buffer=%g", smallObjects, smallBytes, largeBytes)
	}
	if math.Abs(smallBytes/smallObjects-64) > 1e-9 {
		t.Fatal("estimate changed mean object size")
	}
	if largeBytes != 32<<20 {
		t.Fatalf("large buffer unexpectedly weighted: %g", largeBytes)
	}
	for _, rate := range []int{0, 1} {
		objects, bytes := estimateHeapSample(3, 24, rate)
		if objects != 3 || bytes != 24 {
			t.Fatal("fully sampled counts changed")
		}
	}
	objects, bytes := estimateHeapSample(0, 0, rate)
	if objects != 0 || bytes != 0 {
		t.Fatal("empty sample must be zero")
	}
}
