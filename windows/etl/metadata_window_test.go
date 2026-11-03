package etl

import (
	"bytes"
	"context"
	"testing"
)

func TestMetadataTrailerDoesNotInventSchedulerCapacity(t *testing.T) {
	// Two CPUs with complete three-second switch coverage. Finalization writes
	// static system configuration and EventTrace records six seconds later.
	data := append(testBuffer(0, testHeader(3), testThread(1, 10, 100, 1000),
		testSwitch(0, 100, 1000), testSwitch(100, 0, 4000)),
		testBuffer(1, testSwitch(0, 0, 1000), testSwitch(0, 0, 4000))...)
	data = append(data, testBuffer(0, testEvent(11, 10, 3, 9000, nil), testEvent(0, 8, 2, 10000, nil))...)
	r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	near(t, "activity", r.ElapsedSeconds, 3)
	near(t, "metadata trailer", r.MetadataTrailerSeconds, 6)
	near(t, "uncovered", r.UncoveredSeconds, 0)
	if r.FirstTick != 1000 || r.LastTick != 10000 || r.CapacityLastTick != 4000 || r.Events != 8 {
		t.Fatalf("raw bounds/inventory lost: %+v", r)
	}
	// The trailer is not silently dropped from schema inventory.
	if len(r.Schemas) != 5 {
		t.Fatal(r.Schemas)
	}
}

func TestUnsupportedActivityStillRequiresSchedulerCoverage(t *testing.T) {
	for _, group := range []byte{1, 15, 255} {
		data := testBuffer(0, testHeader(1), testSwitch(0, 0, 1000), testSwitch(0, 0, 4000), testEvent(group, 99, 99, 10000, nil))
		r, err := Analyze(context.Background(), bytes.NewReader(data), int64(len(data)), Limits{})
		if err != nil {
			t.Fatal(err)
		}
		near(t, "unsupported activity capacity", r.ElapsedSeconds, 9)
		near(t, "uncovered second CPU and tail", r.UncoveredSeconds, 15)
		near(t, "no metadata trailer", r.MetadataTrailerSeconds, 0)
	}
}
