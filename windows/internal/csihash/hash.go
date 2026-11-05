// Package csihash implements the shared native CSI name-hash arithmetic.
package csihash

import "fmt"

// Text hashes the ASCII subset using four interleaved uint32 X65599 lanes,
// combined modulo 2^64 in radix 2^33-9. Unicode folding is not approximated.
// This is a name discriminator, not a cryptographic trust digest.
func Text(text string) (uint64, error) {
	return foldedText(text, false)
}

// UpperText uses the native FileMap filename hash's ASCII uppercase folding.
// It must not be used for FileMap entry-table or assembly-identity hashing.
func UpperText(text string) (uint64, error) {
	return foldedText(text, true)
}

func foldedText(text string, upper bool) (uint64, error) {
	var lanes [4]uint32
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < 32 || c > 127 {
			return 0, fmt.Errorf("unsupported CSI text byte %#x", c)
		}
		if upper {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
		} else if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lanes[i%4] = lanes[i%4]*65599 + uint32(c)
	}
	var hash uint64
	for _, lane := range lanes {
		hash = hash*((1<<33)-9) + uint64(lane)
	}
	return hash, nil
}
