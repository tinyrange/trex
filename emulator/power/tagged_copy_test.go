package power

import (
	"bytes"
	"slices"
	"testing"
)

func TestTaggedRealCopyPartialEdgesAndStoreEffects(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, CPUs: 2, Extensions: []string{"as"}})
	c := m.CPUs[0]
	for i := 0; i < 128; i++ {
		m.Mem[0x1000+i] = byte(i*7 + 1)
	}
	m.tags[4] = 15
	m.tags[8] = 15
	m.CPUs[1].reserve(0x2000, 8)
	m.Watch(0x2010, 0x2011)
	if err := c.CopyRealTagged(0x2003, 0x1003, 46); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Mem[0x2003:0x2031], m.Mem[0x1003:0x1031]) {
		t.Fatal("copy bytes")
	}
	if m.Tag(0x2000) || !m.Tag(0x2010) || !m.Tag(0x2020) || m.Tag(0x2030) || !m.Tag(0x1000) {
		t.Fatal("partial stores must clear only their overlapping tags; full quads preserve tags")
	}
	if m.CPUs[1].resValid || c.stop == nil || c.stop.Kind != "watch" {
		t.Fatal("store effects")
	}
	before, tags := slices.Clone(m.Mem), slices.Clone(m.tags)
	for _, r := range [][3]uint64{{0x2001, 0x1000, 16}, {1 << 20, 0, 1}, {0, 1 << 20, 1}, {^uint64(0), 0, 1}} {
		if err := c.CopyRealTagged(r[0], r[1], r[2]); err == nil {
			t.Fatal("invalid copy accepted", r)
		}
		if !bytes.Equal(before, m.Mem) || !slices.Equal(tags, m.tags) {
			t.Fatal("invalid copy mutated memory")
		}
	}
}

func TestTaggedRealCopyForwardOverlapAndSelf(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	c := m.CPUs[0]
	for i := 0; i < 48; i++ {
		m.Mem[0x1000+i] = byte(i)
	}
	m.tags[4] = 1
	if err := c.CopyRealTagged(0x1010, 0x1000, 32); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Mem[0x1000:0x1010], m.Mem[0x1020:0x1030]) || !m.Tag(0x1020) {
		t.Fatal("forward quadword overlap must observe the preceding store")
	}
	if err := c.CopyRealTagged(0x1000, 0x1000, 48); err != nil || m.tags[4]&7 != 7 {
		t.Fatal("aligned self-copy lost tags", err)
	}
}
