package irix

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
)

// A Mark names a subsystem pattern and an inclusive image version range.
type Mark struct {
	Product, Image, Subsystem string
	Low, High                 int64
}
type Subsystem struct {
	Name, Description, Expression, Alternate string
	Flags                                    uint16
	Installed                                uint32
	Replacements                             []Mark
	Prerequisites                            [][]Mark
	Extensions                               []Mark
	Additional                               []Mark
	Final                                    []Mark
	Attributes                               []string
}
type ProductImage struct {
	Name, Description, Alternate string
	Flags, Format, Order         uint16
	Version, Length, Padding     uint32
	Subsystems                   []Subsystem
	Extensions                   []Mark
	Attributes                   []string
}
type Product struct {
	Name, Description, Alternate string
	Flags, Format                uint16
	Date                         uint32
	Extensions                   []Mark
	Attributes                   []string
	Images                       []ProductImage
}
type pdReader struct {
	b              []byte
	off, remaining int
	err            error
}

func (c *pdReader) take(n int) []byte {
	if c.err != nil {
		return make([]byte, n)
	}
	if n < 0 || n > len(c.b)-c.off {
		c.err = fmt.Errorf("irix product: truncated field at %d", c.off)
		return make([]byte, max(n, 0))
	}
	out := c.b[c.off : c.off+n]
	c.off += n
	return out
}
func (c *pdReader) u16() uint16 { return binary.BigEndian.Uint16(c.take(2)) }
func (c *pdReader) u32() uint32 { return binary.BigEndian.Uint32(c.take(4)) }
func (c *pdReader) str() string {
	n := int(c.u16())
	s := string(c.take(n))
	if strings.ContainsRune(s, 0) && c.err == nil {
		c.err = fmt.Errorf("irix product: embedded NUL in string at %d", c.off-n)
	}
	return s
}
func (c *pdReader) count() int {
	n := int(c.u16())
	if n > c.remaining && c.err == nil {
		c.err = fmt.Errorf("irix product: record limit exceeded at %d", c.off)
	}
	c.remaining -= n
	if c.err != nil {
		return 0
	}
	return n
}
func (c *pdReader) mark() Mark {
	m := Mark{Product: c.str(), Image: c.str(), Subsystem: c.str(), Low: int64(int32(c.u32())), High: int64(int32(c.u32()))}
	if m.High < m.Low && c.err == nil {
		c.err = fmt.Errorf("irix product: invalid version range at %d", c.off)
	}
	return m
}
func (c *pdReader) marks() []Mark {
	n := c.count()
	out := make([]Mark, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, c.mark())
	}
	return out
}
func (c *pdReader) strings() []string {
	n := c.count()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, c.str())
	}
	return out
}

// ReadProducts reads the pd001 wrapper, product records and checked tape fill.
// Attribute strings and selection expressions are preserved, not executed.
func ReadProducts(file starfile.File, maximum int) ([]Product, error) {
	if maximum < 1 || file.Size() < 0 || file.Size() > 64<<20 {
		return nil, fmt.Errorf("irix product: invalid limit or oversized input")
	}
	b, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	c := pdReader{b: b, remaining: maximum}
	if len(b) >= 13 && string(b[:5]) == "pd001" {
		if b[5] != 'V' || b[9] != 'P' || b[12] != 0 {
			return nil, fmt.Errorf("irix product: invalid version wrapper")
		}
		for _, i := range []int{6, 7, 8, 10, 11} {
			if b[i] < '0' || b[i] > '9' {
				return nil, fmt.Errorf("irix product: invalid wrapper digits")
			}
		}
		c.off = 13
	}
	count := 1
	if c.u16() == 1988 {
		count = c.count()
	} else {
		c.off = 0
		if len(b) >= 13 && string(b[:5]) == "pd001" {
			c.off = 13
		}
	}
	products := make([]Product, 0, count)
	for i := 0; i < count; i++ {
		if c.u16() != 1987 {
			return nil, fmt.Errorf("irix product: invalid product magic at %d", c.off-2)
		}
		p := Product{Format: c.u16()}
		if p.Format < 1 || p.Format > 9 || p.Format == 7 {
			return nil, fmt.Errorf("irix product: unsupported structure version %d", p.Format)
		}
		p.Name, p.Description, p.Flags = c.str(), c.str(), c.u16()
		if p.Format >= 4 {
			p.Date = c.u32()
			p.Alternate = c.str()
		}
		if p.Format >= 8 {
			p.Extensions = c.marks()
			p.Attributes = c.strings()
		}
		for n, j := c.count(), 0; j < n; j++ {
			im := ProductImage{Flags: c.u16(), Name: c.str(), Description: c.str(), Format: c.u16()}
			if p.Format >= 3 {
				im.Order = c.u16()
			} else if im.Flags&1 != 0 {
				im.Order = 1
			}
			im.Version = c.u32()
			if p.Format < 6 {
				im.Length, im.Padding = c.u32(), c.u32()
			}
			if p.Format >= 4 {
				im.Alternate = c.str()
			}
			if p.Format >= 8 {
				im.Extensions = c.marks()
				im.Attributes = c.strings()
			}
			for n, k := c.count(), 0; k < n; k++ {
				ss := Subsystem{Flags: c.u16(), Name: c.str(), Description: c.str(), Expression: c.str()}
				if p.Format >= 2 {
					ss.Installed = c.u32()
					ss.Replacements = c.marks()
					for n, l := c.count(), 0; l < n; l++ {
						ss.Prerequisites = append(ss.Prerequisites, c.marks())
					}
				} else {
					ss.Installed = im.Length
					group := []Mark{}
					for n, l := c.count(), 0; l < n; l++ {
						group = append(group, Mark{Product: c.str(), Image: c.str(), Subsystem: c.str(), Low: int64(int32(c.u32())), High: 0x7fffffff})
					}
					if len(group) > 0 {
						ss.Prerequisites = append(ss.Prerequisites, group)
					}
					if im.Version > 0 {
						ss.Replacements = []Mark{{p.Name, im.Name, ss.Name, 0, int64(im.Version) - 1}}
					}
				}
				if p.Format >= 4 {
					ss.Alternate = c.str()
				}
				if p.Format >= 6 {
					ss.Extensions = c.marks()
				}
				if p.Format >= 8 {
					ss.Additional = c.marks()
					ss.Attributes = c.strings()
				}
				if p.Format >= 9 {
					ss.Final = c.marks()
				}
				im.Subsystems = append(im.Subsystems, ss)
			}
			p.Images = append(p.Images, im)
		}
		products = append(products, p)
	}
	if c.err != nil {
		return nil, c.err
	}
	if c.off != len(b) {
		if len(b)%512 != 0 {
			return nil, fmt.Errorf("irix product: unaligned trailer at %d", c.off)
		}
		for _, v := range b[c.off:] {
			if v != 0 {
				return nil, fmt.Errorf("irix product: nonzero trailer at %d", c.off)
			}
		}
	}
	return products, nil
}
