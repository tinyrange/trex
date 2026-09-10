package lzms

import "testing"

// Microsoft-compatible decoders commonly express the one-item delay as an
// immediate move-to-front update combined with shifting a repeat index when
// the preceding item was a match of the same kind. Keep this equivalence
// checked: it is easy to make the delayed representation select the wrong
// entry on consecutive matches.
func TestRecentOffsetsEquivalentToAdjustedImmediateQueue(t *testing.T) {
	type immediate struct {
		queue         [4]uint32
		previousWasLZ bool
	}
	type state struct {
		delayed   recentOffsets
		immediate immediate
	}

	initial := state{
		delayed:   newRecentOffsets(),
		immediate: immediate{queue: [4]uint32{1, 2, 3, 4}},
	}
	var visit func(state, int, string)
	visit = func(before state, depth int, history string) {
		if depth == 8 {
			return
		}
		for operation := 0; operation < 5; operation++ {
			next := before
			next.delayed.beginItem()
			switch operation {
			case 0: // An item that is not an ordinary LZ match.
				next.immediate.previousWasLZ = false
			case 1: // An explicit ordinary offset.
				value := uint32(100 + depth)
				next.delayed.explicit(value)
				pushOffset(&next.immediate.queue, value)
				next.immediate.previousWasLZ = true
			default: // Repeat indices 0, 1, and 2.
				index := operation - 2
				got, err := next.delayed.repeat(index)
				if err != nil {
					t.Fatalf("%s repeat %d: %v", history, index, err)
				}
				adjusted := index
				if next.immediate.previousWasLZ {
					adjusted++
					if adjusted > 3 {
						adjusted = 3
					}
				}
				want := moveOffsetToFront(&next.immediate.queue, adjusted)
				if got != want {
					t.Fatalf("%s repeat %d selected %d, immediate model selected %d", history, index, got, want)
				}
				next.immediate.previousWasLZ = true
			}
			next.delayed.endItem()
			visit(next, depth+1, history+string(rune('0'+operation)))
		}
	}
	visit(initial, 0, "")
}

func TestRecentDeltaPairsEquivalentToAdjustedImmediateQueue(t *testing.T) {
	type immediate struct {
		queue            [4]deltaPair
		previousWasDelta bool
	}
	type state struct {
		delayed   recentDeltaPairs
		immediate immediate
	}

	initial := state{
		delayed:   newRecentDeltaPairs(),
		immediate: immediate{queue: [4]deltaPair{{0, 1}, {0, 2}, {0, 3}, {0, 4}}},
	}
	var visit func(state, int, string)
	visit = func(before state, depth int, history string) {
		if depth == 8 {
			return
		}
		for operation := 0; operation < 5; operation++ {
			next := before
			next.delayed.beginItem()
			switch operation {
			case 0: // An item that is not a delta match.
				next.immediate.previousWasDelta = false
			case 1: // An explicit delta pair.
				value := deltaPair{power: uint8(depth % 8), rawOffset: uint32(100 + depth)}
				next.delayed.explicit(value)
				pushDeltaPair(&next.immediate.queue, value)
				next.immediate.previousWasDelta = true
			default: // Repeat indices 0, 1, and 2.
				index := operation - 2
				got, err := next.delayed.repeat(index)
				if err != nil {
					t.Fatalf("%s repeat %d: %v", history, index, err)
				}
				adjusted := index
				if next.immediate.previousWasDelta {
					adjusted++
					if adjusted > 3 {
						adjusted = 3
					}
				}
				want := moveDeltaPairToFront(&next.immediate.queue, adjusted)
				if got != want {
					t.Fatalf("%s repeat %d selected %+v, immediate model selected %+v", history, index, got, want)
				}
				next.immediate.previousWasDelta = true
			}
			next.delayed.endItem()
			visit(next, depth+1, history+string(rune('0'+operation)))
		}
	}
	visit(initial, 0, "")
}

func pushOffset(queue *[4]uint32, value uint32) {
	copy(queue[1:], queue[:3])
	queue[0] = value
}

func moveOffsetToFront(queue *[4]uint32, index int) uint32 {
	value := queue[index]
	copy(queue[1:index+1], queue[:index])
	queue[0] = value
	return value
}

func pushDeltaPair(queue *[4]deltaPair, value deltaPair) {
	copy(queue[1:], queue[:3])
	queue[0] = value
}

func moveDeltaPairToFront(queue *[4]deltaPair, index int) deltaPair {
	value := queue[index]
	copy(queue[1:index+1], queue[:index])
	queue[0] = value
	return value
}
