package amd64

import "testing"

func TestMOVLHPS(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		dst, src   int
		want       [16]byte
	}{
		{"distinct", "0f 16 c1", 0, 1, [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36, 37, 38, 39}},
		{"self-memset", "0f 16 c0", 0, 0, [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}},
		{"extended", "45 0f 16 f7", 14, 15, [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 32, 33, 34, 35, 36, 37, 38, 39}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			c.xmm[tc.src] = [16]byte{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}
			c.xmm[tc.dst] = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			c.flags = flagCarry | flagZero | flagDirection
			before := *c
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.xmm[tc.dst] != tc.want {
				t.Fatalf("got %x, want %x", c.xmm[tc.dst], tc.want)
			}
			if c.flags != before.flags {
				t.Fatal("changed flags")
			}
			for i := range c.xmm {
				if i != tc.dst && c.xmm[i] != before.xmm[i] {
					t.Fatalf("changed X%d", i)
				}
			}
		})
	}
}
