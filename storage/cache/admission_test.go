package bytecache

import (
	"math"
	"testing"
)

func TestAdmissionReservesRetainedBudgetWithoutOverflow(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		limit, first, second int64
	}{
		{"full-budget-replacement", 6, 6, 3},
		{"int64-weight-boundary", math.MaxInt64, 1, math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(tc.limit)
			first := Key{Index: 1}
			second := Key{Index: 2}
			held, err := c.GetValue(first, func() (any, int64, error) {
				return "first immutable value", tc.first, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.GetValue(second, func() (any, int64, error) {
				return "second immutable value", tc.second, nil
			})
			if err != nil || got != "second immutable value" {
				t.Fatalf("load: %v %v", got, err)
			}
			s := c.Stats()
			if s.Bytes != tc.second || s.PeakBytes != tc.limit || s.Evictions != 1 || s.Entries != 1 {
				t.Fatalf("admission exceeded or wrapped retained budget: %+v", s)
			}
			if held != "first immutable value" {
				t.Fatal("eviction invalidated held value")
			}
			_, err = c.GetValue(second, func() (any, int64, error) {
				t.Fatal("most-recent admitted value was evicted")
				return nil, 0, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if c.Stats().Loads != 2 {
				t.Fatalf("unexpected reload: %+v", c.Stats())
			}
		})
	}
}
