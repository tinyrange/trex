package star

import "sort"

// byteCoverage is an exact union of successful byte ranges. Its caller holds
// the observation lock. Once the bounded range inventory overflows, the union
// is frozen as a lower bound and complete remains false; never claim an
// incomplete observation is exact. Adjacent ranges are coalesced.
type byteCoverage struct {
	limit    int
	ranges   []byteInterval
	bytes    int64
	overflow bool
}
type byteInterval struct{ start, end int64 }

func (c *byteCoverage) add(start, length int64) {
	if c.overflow || length == 0 {
		return
	}
	if start < 0 || length < 0 || start > (1<<63-1)-length {
		c.overflow = true
		return
	}
	end := start + length
	first := sort.Search(len(c.ranges), func(i int) bool { return c.ranges[i].end >= start })
	last := first
	var removed int64
	for last < len(c.ranges) && c.ranges[last].start <= end {
		start = min(start, c.ranges[last].start)
		end = max(end, c.ranges[last].end)
		removed += c.ranges[last].end - c.ranges[last].start
		last++
	}
	if len(c.ranges)-(last-first)+1 > c.limit {
		c.overflow = true
		return
	}
	c.bytes += end - start - removed
	if last == first {
		c.ranges = append(c.ranges, byteInterval{})
		copy(c.ranges[first+1:], c.ranges[first:len(c.ranges)-1])
	} else {
		copy(c.ranges[first+1:], c.ranges[last:])
		c.ranges = c.ranges[:len(c.ranges)-(last-first)+1]
	}
	c.ranges[first] = byteInterval{start, end}
}
