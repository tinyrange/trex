package storage

import (
	"errors"
	"io"
	"math"
	"sort"
)

// Range borrows a range from a stable Reader. Sources must remain open for the
// lifetime of the composed value. Composition never reads or copies payloads.
type Range struct {
	Source         Reader
	Offset, Length int64
}
type Composite struct {
	ranges []Range
	ends   []int64
	size   int64
}

func Compose(ranges ...Range) (*Composite, error) {
	c := &Composite{}
	for _, r := range ranges {
		if r.Source == nil || r.Offset < 0 || r.Length < 0 || r.Source.Size() < 0 || r.Offset > r.Source.Size() || r.Length > r.Source.Size()-r.Offset || r.Length > math.MaxInt64-c.size {
			return nil, errors.New("invalid composed file range")
		}
		if r.Length == 0 {
			continue
		}
		c.size += r.Length
		c.ranges = append(c.ranges, r)
		c.ends = append(c.ends, c.size)
	}
	return c, nil
}
func (c *Composite) Size() int64 { return c.size }
func (c *Composite) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= c.size {
		return 0, io.EOF
	}
	done := 0
	index := sort.Search(len(c.ends), func(i int) bool { return c.ends[i] > off })
	for done < len(p) && index < len(c.ranges) {
		r := c.ranges[index]
		start := int64(0)
		if index > 0 {
			start = c.ends[index-1]
		}
		within := off - start
		count := int(min(int64(len(p)-done), r.Length-within))
		n, e := r.Source.ReadAt(p[done:done+count], r.Offset+within)
		done += n
		off += int64(n)
		if e != nil && !(e == io.EOF && n == count) {
			return done, e
		}
		if n != count {
			return done, io.ErrUnexpectedEOF
		}
		index++
	}
	if done < len(p) {
		return done, io.EOF
	}
	return done, nil
}

// WriteTo streams a full composed file, preserving source fast paths where possible.
func (c *Composite) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for _, r := range c.ranges {
		var n int64
		var err error
		if fast, ok := r.Source.(RangeWriterTo); ok {
			n, err = fast.WriteRangeTo(w, r.Offset, r.Length)
		} else {
			n, err = io.Copy(w, io.NewSectionReader(r.Source, r.Offset, r.Length))
		}
		total += n
		if err != nil {
			return total, err
		}
		if n != r.Length {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// RangeWriterTo optionally streams a range without forcing whole-file allocation.
type RangeWriterTo interface {
	WriteRangeTo(io.Writer, int64, int64) (int64, error)
}
