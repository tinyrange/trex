package s390

// ssCharacter handles SS-format character instructions with a single length.
func (c *CPU) ssCharacter() {
	op := c.op[:]
	l := uint32(op[1]) + 1
	a1 := c.eaBD(op[2], op[3])
	a2 := c.eaBD(op[4], op[5])
	b1, b2 := int(op[2]>>4), int(op[4]>>4)
	switch op[0] {
	case 0xd2: // MVC
		c.checkFetch(a2, l, b2)
		c.checkStore(a1, l, b1)
		if d := c.span(a1, l, accStore, b1); d != nil {
			if s := c.span(a2, l, accFetch, b2); s != nil {
				if !overlapsForward(a1, a2, l) {
					copy(d, s)
					return
				}
				for i := range d {
					d[i] = s[i]
				}
				return
			}
		}
		for i := uint32(0); i < l; i++ {
			c.storeByte(a1+i, b1, c.fetchByte(a2+i, b2))
		}
	case 0xd1, 0xd3: // MVN, MVZ
		mask := byte(0x0f)
		if op[0] == 0xd3 {
			mask = 0xf0
		}
		c.checkFetch(a2, l, b2)
		c.checkStore(a1, l, b1)
		for i := uint32(0); i < l; i++ {
			x := c.fetchByte(a2+i, b2)
			y := c.fetchByte(a1+i, b1)
			c.storeByte(a1+i, b1, y&^mask|x&mask)
		}
	case 0xd4, 0xd6, 0xd7: // NC, OC, XC
		c.checkFetch(a2, l, b2)
		c.checkStore(a1, l, b1)
		var nz byte
		if op[0] == 0xd7 && a1 == a2 && b1 == b2 {
			if d := c.span(a1, l, accStore, b1); d != nil {
				for i := range d {
					d[i] = 0
				}
				c.PSW.CC = 0
				return
			}
		}
		for i := uint32(0); i < l; i++ {
			x := c.fetchByte(a2+i, b2)
			y := c.fetchByte(a1+i, b1)
			switch op[0] {
			case 0xd4:
				y &= x
			case 0xd6:
				y |= x
			case 0xd7:
				y ^= x
			}
			nz |= y
			c.storeByte(a1+i, b1, y)
		}
		c.PSW.CC = 0
		if nz != 0 {
			c.PSW.CC = 1
		}
	case 0xd5: // CLC
		if p := c.span(a1, l, accFetch, b1); p != nil {
			if q := c.span(a2, l, accFetch, b2); q != nil {
				for i := range p {
					if p[i] != q[i] {
						if p[i] < q[i] {
							c.PSW.CC = 1
						} else {
							c.PSW.CC = 2
						}
						return
					}
				}
				c.PSW.CC = 0
				return
			}
		}
		for i := uint32(0); i < l; i++ {
			x := c.fetchByte(a1+i, b1)
			y := c.fetchByte(a2+i, b2)
			if x != y {
				if x < y {
					c.PSW.CC = 1
				} else {
					c.PSW.CC = 2
				}
				return
			}
		}
		c.PSW.CC = 0
	case 0xdc: // TR
		c.checkStore(a1, l, b1)
		for i := uint32(0); i < l; i++ {
			x := c.fetchByte(a1+i, b1)
			c.storeByte(a1+i, b1, c.fetchByte(a2+uint32(x), b2))
		}
	case 0xdd: // TRT
		for i := uint32(0); i < l; i++ {
			x := c.fetchByte(a1+i, b1)
			f := c.fetchByte(a2+uint32(x), b2)
			if f != 0 {
				if c.PSW.Amode31 {
					c.GR[1] = (a1 + i) & c.amask
				} else {
					c.GR[1] = c.GR[1]&0xff000000 | (a1+i)&0xffffff
				}
				c.GR[2] = c.GR[2]&^0xff | uint32(f)
				if i == l-1 {
					c.PSW.CC = 2
				} else {
					c.PSW.CC = 1
				}
				return
			}
		}
		c.PSW.CC = 0
	case 0xde, 0xdf:
		c.edit(l, a1, b1, a2, b2, op[0] == 0xdf)
	case 0xe8: // MVCIN
		c.checkStore(a1, l, b1)
		src := (a2 - (l - 1)) & c.amask
		c.checkFetch(src, l, b2)
		for i := uint32(0); i < l; i++ {
			c.storeByte(a1+i, b1, c.fetchByte(a2-i, b2))
		}
	}
}

// overlapsForward reports whether a forward byte copy would observe its own
// stores (destination starts inside the source, after it).
func overlapsForward(dst, src, n uint32) bool {
	return dst > src && dst < src+n
}

// edit implements ED and EDMK.
func (c *CPU) edit(l uint32, a1 uint32, b1 int, a2 uint32, b2 int, mark bool) {
	c.checkStore(a1, l, b1)
	fill := c.fetchByte(a1, b1)
	sig, nonzero := false, false
	src := a2
	var cur byte
	right := false // the right digit of cur is the next digit
	for i := uint32(0); i < l; i++ {
		pat := c.fetchByte(a1+i, b1)
		res := pat
		switch pat {
		case 0x20, 0x21:
			var digit byte
			if right {
				digit = cur & 0xf
				right = false
			} else {
				cur = c.fetchByte(src, b2)
				src = (src + 1) & c.amask
				digit = cur >> 4
				if digit > 9 {
					c.program(pgmData)
				}
				right = cur&0xf <= 9
			}
			if digit > 9 {
				c.program(pgmData)
			}
			if digit != 0 {
				nonzero = true
			}
			if sig || digit != 0 {
				res = 0xf0 | digit
				if !sig && mark {
					c.setMark(a1 + i)
				}
				sig = true
			} else {
				res = fill
				if pat == 0x21 {
					sig = true
				}
			}
			// A plus sign in the right half of a byte whose left digit was
			// just used turns significance off.
			if !right && cur&0xf >= 0xa {
				if low := cur & 0xf; low != 0xb && low != 0xd {
					sig = false
				}
			}
		case 0x22:
			res = fill
			sig = false
			nonzero = false
		default:
			if !sig {
				res = fill
			}
		}
		c.storeByte(a1+i, b1, res)
	}
	switch {
	case !nonzero:
		c.PSW.CC = 0
	case sig:
		c.PSW.CC = 1
	default:
		c.PSW.CC = 2
	}
}

func (c *CPU) setMark(a uint32) {
	if c.PSW.Amode31 {
		c.GR[1] = a & c.amask
	} else {
		c.GR[1] = c.GR[1]&0xff000000 | a&0xffffff
	}
}

// mvcl implements MOVE LONG.
func (c *CPU) mvcl(r1, r2 int) {
	c.even(r1)
	c.even(r2)
	d := c.GR[r1] & c.amask
	dl := c.GR[r1+1] & 0xffffff
	s := c.GR[r2] & c.amask
	sl := c.GR[r2+1] & 0xffffff
	pad := byte(c.GR[r2+1] >> 24)
	c.PSW.CC = ccCompareU(uint64(dl), uint64(sl))
	if dl == 0 {
		return
	}
	// Destructive overlap check.
	if sl > 0 && d > s && d < s+min(sl, dl) && !(d == s) {
		c.PSW.CC = 3
		return
	}
	cc := c.PSW.CC
	update := func() {
		c.GR[r1] = d
		c.GR[r1+1] = c.GR[r1+1]&0xff000000 | dl
		c.GR[r2] = s
		c.GR[r2+1] = c.GR[r2+1]&0xff000000 | sl
		if !c.PSW.Amode31 {
			c.GR[r1] = c.GR[r1] & 0xffffff
			c.GR[r2] = c.GR[r2] & 0xffffff
		}
	}
	defer func() {
		if r := recover(); r != nil {
			update()
			panic(r)
		}
	}()
	for dl > 0 {
		n := c.pgMask + 1 - d&c.pgMask
		if n > dl {
			n = dl
		}
		dst := c.span(d, n, accStore, r1)
		if sl > 0 {
			m := n
			if m > sl {
				m = sl
			}
			if left := c.pgMask + 1 - s&c.pgMask; m > left {
				m = left
			}
			src := c.span(s, m, accFetch, r2)
			copy(dst[:m], src)
			d = (d + m) & c.amask
			s = (s + m) & c.amask
			dl -= m
			sl -= m
		} else {
			for i := range dst {
				dst[i] = pad
			}
			d = (d + n) & c.amask
			dl -= n
		}
	}
	update()
	c.PSW.CC = cc
}

// clcl implements COMPARE LOGICAL LONG.
func (c *CPU) clcl(r1, r2 int) {
	c.even(r1)
	c.even(r2)
	a := c.GR[r1] & c.amask
	al := c.GR[r1+1] & 0xffffff
	b := c.GR[r2] & c.amask
	bl := c.GR[r2+1] & 0xffffff
	pad := byte(c.GR[r2+1] >> 24)
	cc := byte(0)
	for al > 0 || bl > 0 {
		x, y := pad, pad
		if al > 0 {
			x = c.fetchByte(a, r1)
		}
		if bl > 0 {
			y = c.fetchByte(b, r2)
		}
		if x != y {
			if x < y {
				cc = 1
			} else {
				cc = 2
			}
			break
		}
		if al > 0 {
			a = (a + 1) & c.amask
			al--
		}
		if bl > 0 {
			b = (b + 1) & c.amask
			bl--
		}
	}
	c.GR[r1] = a
	c.GR[r1+1] = c.GR[r1+1]&0xff000000 | al
	c.GR[r2] = b
	c.GR[r2+1] = c.GR[r2+1]&0xff000000 | bl
	c.PSW.CC = cc
}

// mvcle implements MOVE LONG EXTENDED (in units of at most 4K per execution).
func (c *CPU) mvcle(r1, r3 int, a2 uint32) {
	c.even(r1)
	c.even(r3)
	pad := byte(a2)
	d := c.GR[r1] & c.amask
	dl := c.GR[r1+1]
	s := c.GR[r3] & c.amask
	sl := c.GR[r3+1]
	if dl == 0 {
		c.PSW.CC = ccCompareU(uint64(dl), uint64(sl))
		return
	}
	n := c.pgMask + 1 - d&c.pgMask
	if n > dl {
		n = dl
	}
	for i := uint32(0); i < n; i++ {
		x := pad
		if sl > 0 {
			x = c.fetchByte(s, r3)
			s = (s + 1) & c.amask
			sl--
		}
		c.storeByte(d, r1, x)
		d = (d + 1) & c.amask
		dl--
	}
	c.GR[r1], c.GR[r1+1], c.GR[r3], c.GR[r3+1] = d, dl, s, sl
	if dl != 0 {
		c.PSW.CC = 3
		return
	}
	c.PSW.CC = ccCompareU(uint64(n+dl), uint64(n+sl))
	if sl == 0 {
		c.PSW.CC = 0
	} else {
		c.PSW.CC = 1
	}
}

// clcle implements COMPARE LOGICAL LONG EXTENDED.
func (c *CPU) clcle(r1, r3 int, a2 uint32) {
	c.even(r1)
	c.even(r3)
	pad := byte(a2)
	a := c.GR[r1] & c.amask
	al := c.GR[r1+1]
	b := c.GR[r3] & c.amask
	bl := c.GR[r3+1]
	for i := 0; i < 4096 && (al > 0 || bl > 0); i++ {
		x, y := pad, pad
		if al > 0 {
			x = c.fetchByte(a, r1)
		}
		if bl > 0 {
			y = c.fetchByte(b, r3)
		}
		if x != y {
			c.GR[r1], c.GR[r1+1], c.GR[r3], c.GR[r3+1] = a, al, b, bl
			if x < y {
				c.PSW.CC = 1
			} else {
				c.PSW.CC = 2
			}
			return
		}
		if al > 0 {
			a, al = (a+1)&c.amask, al-1
		}
		if bl > 0 {
			b, bl = (b+1)&c.amask, bl-1
		}
	}
	c.GR[r1], c.GR[r1+1], c.GR[r3], c.GR[r3+1] = a, al, b, bl
	if al > 0 || bl > 0 {
		c.PSW.CC = 3
		return
	}
	c.PSW.CC = 0
}
