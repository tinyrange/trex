package cc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// appleAES implements the S8000 v3 software-key FIFO operations observed in
// the original PCC 26.6 driver (key/IV, physical DMA, IV readback and barrier).
// Hardware-bound keys and wrapped-key operations are deliberately unavailable.
type appleAES struct {
	address uint64

	control, mask, threshold, status, flag uint32
	command                                uint32
	words                                  []uint32
	need                                   int
	keys                                   [2]aesKey
	iv                                     [4][16]byte
	memory                                 func(uint64, uint64, bool) ([]byte, error)
	irq                                    func(bool) error
}
type aesKey struct {
	block   cipher.Block
	encrypt bool
	mode    uint32
}

func (d *appleAES) Contains(a uint64, n int) bool {
	return a >= d.address && a-d.address < 0x4000 && n == 4 && a&3 == 0
}
func (d *appleAES) interrupt() error {
	if d.irq != nil {
		return d.irq(d.status&d.mask != 0)
	}
	return nil
}
func (d *appleAES) Read(a uint64, n int) (uint64, error) {
	switch a - d.address {
	case 8:
		return uint64(d.control), nil
	case 12:
		return 0x3f80, nil // All six pipelines idle; commands execute synchronously.
	case 24:
		return uint64(d.status), nil
	case 28:
		return uint64(d.mask), nil
	case 32:
		return uint64(d.threshold), nil
	case 36:
		return 2, nil // Empty hardware FIFO; partial command held by decoder.
	case 48:
		return uint64(d.flag), nil
	}
	return 0, fmt.Errorf("Apple AES: unsupported read at %#x", a)
}
func (d *appleAES) Write(a uint64, n int, v uint64) error {
	switch a - d.address {
	case 8:
		if v > 3 {
			return fmt.Errorf("Apple AES: unknown control %#x", v)
		}
		d.control = uint32(v)
	case 24:
		d.status &^= uint32(v)
	case 28:
		d.mask = uint32(v)
	case 32:
		d.threshold = uint32(v)
	case 0x200:
		return d.fifo(uint32(v))
	default:
		return fmt.Errorf("Apple AES: unsupported write at %#x value %#x", a, v)
	}
	return d.interrupt()
}
func (d *appleAES) fifo(v uint32) error {
	if d.need != 0 {
		d.words = append(d.words, v)
		if len(d.words) < d.need {
			return nil
		}
		d.need = 0
		return d.execute()
	}
	d.command = v
	d.words = nil
	switch v >> 28 {
	case 1:
		// Driver emits 4/6/8 words for software 128/192/256-bit keys.
		if v&0x07000000 != 0 || v&0x002cffff != 0 || v>>16&3 > 2 || v>>22&3 == 3 {
			return fmt.Errorf("Apple AES: unsupported key command %#x", v)
		}
		d.need = 4 + 2*int(v>>22&3)
	case 2:
		if v&0x03ffffff != 0 {
			return fmt.Errorf("Apple AES: unsupported IV command %#x", v)
		}
		d.need = 4
	case 5:
		if v&0x01000000 != 0 || v&0xffffff == 0 || v&15 != 0 {
			return fmt.Errorf("Apple AES: invalid crypt command %#x", v)
		}
		d.need = 3
	case 6:
		if v&0x0fffff00 != 0 {
			return fmt.Errorf("Apple AES: unsupported IV readback %#x", v)
		}
		d.need = 1
	case 8:
		if v&0x07ff0000 != 0 {
			return fmt.Errorf("Apple AES: unsupported barrier %#x", v)
		}
		d.flag = v & 0xff
		if v&0x08000000 != 0 {
			d.status |= 1 << 5
		}
		return d.interrupt()
	default:
		return fmt.Errorf("Apple AES: unsupported FIFO command %#x", v)
	}
	return nil
}
func (d *appleAES) dma(a, n uint64, write bool) ([]byte, error) {
	if d.memory == nil {
		return nil, fmt.Errorf("Apple AES: DMA memory unavailable")
	}
	return d.memory(a, n, write)
}
func (d *appleAES) execute() error {
	c := d.command
	raw := make([]byte, len(d.words)*4)
	for i, w := range d.words {
		binary.LittleEndian.PutUint32(raw[i*4:], w)
	}
	switch c >> 28 {
	case 1:
		block, err := aes.NewCipher(raw)
		if err != nil {
			return err
		}
		d.keys[c>>27&1] = aesKey{block: block, encrypt: c&(1<<20) != 0, mode: c >> 16 & 3}
	case 2:
		copy(d.iv[c>>26&3][:], raw)
	case 5:
		key := d.keys[c>>27&1]
		if key.block == nil {
			return fmt.Errorf("Apple AES: crypt with empty software key")
		}
		high := uint64(d.words[0])
		if high&^uint64(0x00ff00ff) != 0 {
			return fmt.Errorf("Apple AES: unsupported DMA address bits")
		}
		n := uint64(c & 0xffffff)
		src := uint64(d.words[1]) | (high>>16&0xff)<<32
		dst := uint64(d.words[2]) | (high&0xff)<<32
		input, err := d.dma(src, n, false)
		if err != nil {
			return err
		}
		output, err := d.dma(dst, n, true)
		if err != nil {
			return err
		}
		// Read before writing, including overlapping source/destination mappings.
		input = append([]byte(nil), input...)
		iv := &d.iv[c>>25&3]
		switch key.mode {
		case 0:
			for i := 0; i < len(input); i += 16 {
				if key.encrypt {
					key.block.Encrypt(output[i:i+16], input[i:i+16])
				} else {
					key.block.Decrypt(output[i:i+16], input[i:i+16])
				}
			}
		case 1:
			if key.encrypt {
				cipher.NewCBCEncrypter(key.block, iv[:]).CryptBlocks(output, input)
				copy(iv[:], output[len(output)-16:])
			} else {
				cipher.NewCBCDecrypter(key.block, iv[:]).CryptBlocks(output, input)
				copy(iv[:], input[len(input)-16:])
			}
		case 2:
			cipher.NewCTR(key.block, iv[:]).XORKeyStream(output, input)
			for blocks := len(input) / 16; blocks > 0; blocks-- {
				for i := 15; i >= 0; i-- {
					iv[i]++
					if iv[i] != 0 {
						break
					}
				}
			}
		default:
			return fmt.Errorf("Apple AES: unsupported block mode")
		}
	case 6:
		a := uint64(d.words[0]) | uint64(c&0xff)<<32
		output, err := d.dma(a, 16, true)
		if err != nil {
			return err
		}
		copy(output, d.iv[0][:])
	}
	return nil
}
