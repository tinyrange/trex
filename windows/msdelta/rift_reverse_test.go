package msdelta

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

// Preserve the pre-optimization linear interval lookup as a differential
// oracle. Inversion is cyclic and first-covered intervals win; ordinary
// inverse(mapForward(x)) assertions would miss overlapping image ranges.
func reverseRiftLinear(rift riftTable) riftTable {
	n := len(rift.entries)
	if n == 0 {
		return riftTable{}
	}
	allSame := true
	for index := 1; index < n; index++ {
		allSame = allSame && rift.entries[index].source == rift.entries[0].source
	}
	if allSame {
		entry := rift.entries[0]
		return riftTable{entries: []riftEntry{{source: 0, target: entry.target - entry.source}}}
	}
	intervalStart := make([]int64, 2*n)
	intervalEnd := make([]int64, 2*n)
	intervalCount := 0
	result := riftTable{}
	firstPositive := 0
	for firstPositive < n && rift.entries[firstPositive].source <= 0 {
		firstPositive++
	}
	if firstPositive == 0 {
		firstPositive = n
	}
	stop := firstPositive - 1
	sourceCursor := int64(0)
	boundary := 0
	if firstPositive < n {
		boundary = firstPositive
	}
	active := stop
	for {
		for {
			offset := rift.entries[active].target - rift.entries[active].source
			endSegment := boundary
			span := rift.entries[boundary].source - sourceCursor
			imageStart := offset + sourceCursor
			if imageStart != int64(-1<<63) {
				clamped := int64(-1<<63) - offset - sourceCursor
				if uint64(clamped) < uint64(span) {
					span = clamped
				}
			}
			if span != 0 {
				imageEnd := imageStart + span
				firstOverlap := 0
				for firstOverlap < intervalCount && imageStart > intervalEnd[firstOverlap] && intervalEnd[firstOverlap] != int64(-1<<63) {
					firstOverlap++
				}
				insertAt, overlapEnd := firstOverlap, firstOverlap
				newEnd := imageEnd
				if firstOverlap < intervalCount {
					for overlapEnd < intervalCount {
						key := intervalStart[overlapEnd]
						if imageEnd != int64(-1<<63) && imageEnd < key {
							break
						}
						overlapEnd++
					}
					if firstOverlap == overlapEnd {
						result.entries = append(result.entries, riftEntry{source: imageStart, target: sourceCursor})
						replaceReverseInterval(intervalStart, intervalEnd, &intervalCount, insertAt, overlapEnd, imageStart, newEnd)
					} else {
						mergedStart := imageStart
						if imageStart < intervalStart[firstOverlap] {
							result.entries = append(result.entries, riftEntry{source: imageStart, target: sourceCursor})
						} else {
							mergedStart = intervalStart[firstOverlap]
						}
						newEnd = offset
						if insertAt < overlapEnd-1 {
							for index := firstOverlap; index < overlapEnd-1; index++ {
								point := intervalEnd[index]
								result.entries = append(result.entries, riftEntry{source: point, target: point - newEnd})
							}
							insertAt = firstOverlap
						}
						lastEnd := intervalEnd[overlapEnd-1]
						newEnd = lastEnd
						if lastEnd != int64(-1<<63) && (imageEnd == int64(-1<<63) || lastEnd < imageEnd) {
							result.entries = append(result.entries, riftEntry{source: lastEnd, target: lastEnd - offset})
							newEnd = imageEnd
						}
						replaceReverseInterval(intervalStart, intervalEnd, &intervalCount, insertAt, overlapEnd, mergedStart, newEnd)
					}
				} else {
					result.entries = append(result.entries, riftEntry{source: imageStart, target: sourceCursor})
					replaceReverseInterval(intervalStart, intervalEnd, &intervalCount, insertAt, overlapEnd, imageStart, newEnd)
				}
			}
			sourceCursor += span
			if sourceCursor == rift.entries[endSegment].source {
				break
			}
		}
		active = boundary
		if stop == boundary {
			break
		}
		boundary++
		if boundary == n {
			boundary = 0
		}
	}
	sort.SliceStable(result.entries, func(i, j int) bool { return result.entries[i].source < result.entries[j].source })
	filtered := result.entries[:0]
	for _, entry := range result.entries {
		if entry.source == int64(-1<<63) || entry.target == int64(-1<<63) {
			continue
		}
		if len(filtered) != 0 && filtered[len(filtered)-1].source == entry.source {
			filtered[len(filtered)-1] = entry
		} else {
			filtered = append(filtered, entry)
		}
	}
	result.entries = filtered
	return result
}

func TestRiftReverseMatchesLinearIntervals(t *testing.T) {
	rng := rand.New(rand.NewSource(74831))
	cases := []riftTable{
		{},
		{entries: []riftEntry{{0, 0}}},
		{entries: []riftEntry{{0, 10}, {0, 20}}},
		{entries: []riftEntry{{-1 << 63, 50}, {-1, -1 << 63}, {0, 0}, {1<<63 - 1, 42}}},
		{entries: []riftEntry{{-200, 30}, {-100, -40}, {200, 70}}},
	}
	for trial := 0; trial < 500; trial++ {
		entries := make([]riftEntry, 2+rng.Intn(200))
		for i := range entries {
			if trial%3 == 0 {
				entries[i] = riftEntry{int64(rng.Uint64()), int64(rng.Uint64())}
			} else {
				// Force duplicate source points and many overlapping images.
				entries[i] = riftEntry{int64(rng.Intn(400) - 200), int64(rng.Intn(400) - 200)}
			}
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].source < entries[j].source })
		cases = append(cases, riftTable{entries: entries})
	}
	for i, table := range cases {
		before := append([]riftEntry(nil), table.entries...)
		got, want := table.reverse(), reverseRiftLinear(table)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d: got %+v want %+v input %+v", i, got, want, table)
		}
		if len(before) != len(table.entries) {
			t.Fatal("input length changed")
		}
		for j := range before {
			if before[j] != table.entries[j] {
				t.Fatal("inversion mutated its input")
			}
		}
	}
}

var benchmarkReverseResult riftTable

func BenchmarkRiftReverseIntervals(b *testing.B) {
	for _, count := range []int{1024, 16384} {
		table := riftTable{entries: make([]riftEntry, count)}
		for i := range table.entries {
			// Separated target ranges make a repeated linear scan quadratic.
			table.entries[i] = riftEntry{source: int64(i * 16), target: int64(i * 32)}
		}
		for _, linear := range []bool{true, false} {
			b.Run(fmt.Sprintf("n=%d/linear=%t", count, linear), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if linear {
						benchmarkReverseResult = reverseRiftLinear(table)
					} else {
						benchmarkReverseResult = table.reverse()
					}
				}
			})
		}
	}
}
