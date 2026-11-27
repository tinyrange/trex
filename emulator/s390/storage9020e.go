package s390

// liveDisplayLogout9020E packs the two banks and common registers as
// A27-9020-01 figure 12-6 specifies. A CE cycle leaves the DG address
// register all ones and the DG data register empty (§12.12.1).
func (m *Machine) liveDisplayLogout9020E(id int) [seLogoutSize9020]byte {
	var data [seLogoutSize9020]byte
	var response byte
	cycles := &m.storageLatches9020[id-1]
	for bank, cycle := range cycles {
		words := data[bank*16:]
		if cycle.Operation == 0 {
			continue
		}
		be.PutUint64(words, cycle.Data)
		var parity byte
		for i := range 8 {
			parity = parity<<1 | byte(oddParity9020(byte(cycle.Data>>(56-8*i))))
		}
		address := cycle.Address >> 4
		hi, lo := byte(address>>7), byte(address&0x7f)
		words[8], words[9] = cycle.Marks, parity^cycle.BadDataParity
		words[10] = hi | byte(oddParity9020(hi))<<7
		words[11] = lo | byte(oddParity9020(lo))<<7
		operation := byte(oddParity9020(cycle.Marks)) << 7
		if cycle.Operation == seStore9020 {
			operation |= 0x20
		} else {
			operation |= 0x10
		}
		if cycle.BadDataParity != 0 {
			operation |= 0x08
			response |= cycle.Response
		}
		if cycle.BadAddressParity != 0 {
			words[10] ^= byte(cycle.BadAddressParity&badAddressPA9020) << 6
			words[11] ^= byte(cycle.BadAddressParity&badAddressPB9020) << 7
			operation |= 0x04
			response |= cycle.Response
		}
		if cycle.BadMarkParity {
			operation ^= 0x80
			operation |= 0x02
			response |= cycle.Response
		}
		words[12] = operation
		if cycle.BadInputKeyParity || cycle.BadStoredKeyParity {
			response |= cycle.Response
		}
	}
	protect := cycles[0]
	if cycles[1].BadInputKeyParity || cycles[1].BadStoredKeyParity {
		protect = cycles[1]
	}
	if protect.Operation != 0 {
		inputParity, storedParity := byte(oddParity9020(protect.InputKey)), byte(oddParity9020(protect.StoredKey))
		if protect.BadInputKeyParity {
			inputParity ^= 1
		}
		if protect.BadStoredKeyParity {
			storedParity ^= 1
		}
		data[13] = protect.InputKey | inputParity<<5
		data[14] = protect.StoredKey<<2 | storedParity<<7 | byte(protect.Operation>>14)
		if protect.BadInputKeyParity || protect.BadStoredKeyParity {
			data[15] |= 0x40
		}
	}
	ccr := m.ccr9020(7 + uint32(id))
	d := &m.displayRefresh9020E[id-max9020EStorageElements-1]
	hi, lo := byte(d.DGMask>>8), byte(d.DGMask)
	deCCR := oddParity9020(hi)<<31 | uint32(hi)<<23 | oddParity9020(lo)<<22 | uint32(lo)<<14 |
		(ccr&0xf8000000)>>19 | (ccr&0x01000000)>>18 | (ccr&0x00000e00)>>7
	if d.Invalid {
		deCCR |= 1
	}
	be.PutUint32(data[32:], deCCR)
	data[36] = response
	be.PutUint32(data[40:], 0xffff)
	module := uint32(id)
	be.PutUint32(data[44:], oddParity9020(byte(id))<<31|module<<27|
		oddParity9020(byte(id))<<26|module<<22)
	return data
}
