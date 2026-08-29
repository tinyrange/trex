package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"math/big"
	"math/bits"
	"slices"
	"strings"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultBinaryBuilderLimit = 512 << 20

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"aes":                 starlark.NewBuiltin("aes", cryptoAESBuiltin),
		"checksum":            starlark.NewBuiltin("checksum", cryptoChecksumBuiltin),
		"constant_time_equal": starlark.NewBuiltin("constant_time_equal", cryptoConstantTimeEqualBuiltin),
		"des":                 starlark.NewBuiltin("des", cryptoDESBuiltin),
		"deterministic":       starlark.NewBuiltin("deterministic", cryptoDeterministicBuiltin),
		"hash":                starlark.NewBuiltin("hash", cryptoHashBuiltin),
		"hash_blocks":         starlark.NewBuiltin("hash_blocks", cryptoHashBlocksBuiltin),
		"hasher":              starlark.NewBuiltin("hasher", cryptoHasherBuiltin),
		"hmac":                starlark.NewBuiltin("hmac", cryptoHMACBuiltin),
		"mod_exp":             starlark.NewBuiltin("mod_exp", cryptoModExpBuiltin),
		"mod_inverse":         starlark.NewBuiltin("mod_inverse", cryptoModInverseBuiltin),
		"mod_mul":             starlark.NewBuiltin("mod_mul", cryptoModMulBuiltin),
		"random":              starlark.NewBuiltin("random", cryptoRandomBuiltin),
		"rc4":                 starlark.NewBuiltin("rc4", cryptoRC4Builtin),
		"xtea":                starlark.NewBuiltin("xtea", cryptoXTEABuiltin),
	}
}

func bytesForBinaryValue(value starlark.Value) ([]byte, error) {
	return starfile.BytesForValue(value, defaultBinaryBuilderLimit)
}

func cryptoModExpBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var baseValue, exponentValue, modulusValue starlark.Value
	byteOrder := "big"
	if err := starlark.UnpackArgs("mod_exp", args, kwargs,
		"base", &baseValue,
		"exponent", &exponentValue,
		"modulus", &modulusValue,
		"byte_order?", &byteOrder,
	); err != nil {
		return nil, err
	}
	base, err := bytesForBinaryValue(baseValue)
	if err != nil {
		return nil, fmt.Errorf("mod_exp: base: %w", err)
	}
	exponent, err := bytesForBinaryValue(exponentValue)
	if err != nil {
		return nil, fmt.Errorf("mod_exp: exponent: %w", err)
	}
	modulus, err := bytesForBinaryValue(modulusValue)
	if err != nil {
		return nil, fmt.Errorf("mod_exp: modulus: %w", err)
	}
	const maximumBits = 16 << 10
	if len(base) > maximumBits/8 || len(exponent) > maximumBits/8 || len(modulus) == 0 || len(modulus) > maximumBits/8 {
		return nil, fmt.Errorf("mod_exp: operands must be between 1 and %d bits", maximumBits)
	}
	littleEndian := false
	switch strings.ToLower(byteOrder) {
	case "big", "be", "big-endian":
	case "little", "le", "little-endian":
		littleEndian = true
	default:
		return nil, fmt.Errorf("mod_exp: byte_order must be big or little")
	}
	toInteger := func(value []byte) *big.Int {
		if littleEndian {
			value = append([]byte(nil), value...)
			slices.Reverse(value)
		}
		return new(big.Int).SetBytes(value)
	}
	modulusInteger := toInteger(modulus)
	if modulusInteger.Sign() == 0 {
		return nil, fmt.Errorf("mod_exp: modulus must be non-zero")
	}
	result := new(big.Int).Exp(toInteger(base), toInteger(exponent), modulusInteger).Bytes()
	if len(result) > len(modulus) {
		return nil, fmt.Errorf("mod_exp: result exceeds modulus width")
	}
	output := make([]byte, len(modulus))
	copy(output[len(output)-len(result):], result)
	if littleEndian {
		slices.Reverse(output)
	}
	return starlark.Bytes(output), nil
}

func cryptoModMulBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var leftValue, rightValue, modulusValue starlark.Value
	byteOrder := "big"
	if err := starlark.UnpackArgs("mod_mul", args, kwargs,
		"left", &leftValue,
		"right", &rightValue,
		"modulus", &modulusValue,
		"byte_order?", &byteOrder,
	); err != nil {
		return nil, err
	}
	left, err := bytesForBinaryValue(leftValue)
	if err != nil {
		return nil, fmt.Errorf("mod_mul: left: %w", err)
	}
	right, err := bytesForBinaryValue(rightValue)
	if err != nil {
		return nil, fmt.Errorf("mod_mul: right: %w", err)
	}
	modulus, err := bytesForBinaryValue(modulusValue)
	if err != nil {
		return nil, fmt.Errorf("mod_mul: modulus: %w", err)
	}
	const maximumBits = 16 << 10
	if len(left) > maximumBits/8 || len(right) > maximumBits/8 || len(modulus) == 0 || len(modulus) > maximumBits/8 {
		return nil, fmt.Errorf("mod_mul: operands must be between 1 and %d bits", maximumBits)
	}
	littleEndian := false
	switch strings.ToLower(byteOrder) {
	case "big", "be", "big-endian":
	case "little", "le", "little-endian":
		littleEndian = true
	default:
		return nil, fmt.Errorf("mod_mul: byte_order must be big or little")
	}
	toInteger := func(value []byte) *big.Int {
		if littleEndian {
			value = append([]byte(nil), value...)
			slices.Reverse(value)
		}
		return new(big.Int).SetBytes(value)
	}
	modulusInteger := toInteger(modulus)
	if modulusInteger.Sign() == 0 {
		return nil, fmt.Errorf("mod_mul: modulus must be non-zero")
	}
	result := new(big.Int).Mul(toInteger(left), toInteger(right))
	result.Mod(result, modulusInteger)
	encoded := result.Bytes()
	if len(encoded) > len(modulus) {
		return nil, fmt.Errorf("mod_mul: result exceeds modulus width")
	}
	output := make([]byte, len(modulus))
	copy(output[len(output)-len(encoded):], encoded)
	if littleEndian {
		slices.Reverse(output)
	}
	return starlark.Bytes(output), nil
}

var sha256RoundConstants = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func sha256Compress(state *[8]uint32, blocks []byte) {
	var schedule [64]uint32
	for len(blocks) != 0 {
		for index := range 16 {
			schedule[index] = binary.BigEndian.Uint32(blocks[index*4:])
		}
		for index := 16; index < len(schedule); index++ {
			left := schedule[index-15]
			right := schedule[index-2]
			sigma0 := bits.RotateLeft32(left, -7) ^ bits.RotateLeft32(left, -18) ^ left>>3
			sigma1 := bits.RotateLeft32(right, -17) ^ bits.RotateLeft32(right, -19) ^ right>>10
			schedule[index] = schedule[index-16] + sigma0 + schedule[index-7] + sigma1
		}

		a, b, c, d := state[0], state[1], state[2], state[3]
		e, f, g, h := state[4], state[5], state[6], state[7]
		for index := range len(schedule) {
			sigma1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
			choice := e&f ^ (^e)&g
			temporary1 := h + sigma1 + choice + sha256RoundConstants[index] + schedule[index]
			sigma0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
			majority := a&b ^ a&c ^ b&c
			temporary2 := sigma0 + majority
			h, g, f, e = g, f, e, d+temporary1
			d, c, b, a = c, b, a, temporary1+temporary2
		}
		state[0] += a
		state[1] += b
		state[2] += c
		state[3] += d
		state[4] += e
		state[5] += f
		state[6] += g
		state[7] += h
		blocks = blocks[64:]
	}
}

// cryptoHashBlocksBuiltin applies complete compression blocks to an explicit
// hash chaining state. It intentionally performs no padding or length framing.
func cryptoHashBlocksBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var algorithm string
	var stateValue, blocksValue starlark.Value
	if err := starlark.UnpackArgs("hash_blocks", args, kwargs, "algorithm", &algorithm, "state", &stateValue, "blocks", &blocksValue); err != nil {
		return nil, err
	}
	if strings.ToLower(strings.ReplaceAll(algorithm, "-", "")) != "sha256" {
		return nil, fmt.Errorf("hash_blocks: unsupported algorithm %q", algorithm)
	}
	stateBytes, err := bytesForBinaryValue(stateValue)
	if err != nil {
		return nil, fmt.Errorf("hash_blocks: state: %w", err)
	}
	if len(stateBytes) != sha256.Size {
		return nil, fmt.Errorf("hash_blocks: SHA-256 state must contain exactly %d bytes", sha256.Size)
	}
	blocks, err := bytesForBinaryValue(blocksValue)
	if err != nil {
		return nil, fmt.Errorf("hash_blocks: blocks: %w", err)
	}
	if len(blocks)%64 != 0 {
		return nil, fmt.Errorf("hash_blocks: SHA-256 input size must be a multiple of 64")
	}
	if len(blocks) > defaultBinaryBuilderLimit {
		return nil, fmt.Errorf("hash_blocks: input exceeds the %d-byte limit", defaultBinaryBuilderLimit)
	}
	var state [8]uint32
	for index := range state {
		state[index] = binary.BigEndian.Uint32(stateBytes[index*4:])
	}
	sha256Compress(&state, blocks)
	output := make([]byte, sha256.Size)
	for index, word := range state {
		binary.BigEndian.PutUint32(output[index*4:], word)
	}
	return starlark.Bytes(output), nil
}

// cryptoAESBuiltin applies AES without padding. Framing and padding belong to
// format modules because many binary formats use non-standard constructions.
func cryptoAESBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var keyValue, value, ivValue starlark.Value
	decrypt := false
	mode := "cbc"
	ivValue = starlark.None
	if err := starlark.UnpackArgs("aes", args, kwargs,
		"key", &keyValue,
		"value", &value,
		"decrypt?", &decrypt,
		"mode?", &mode,
		"iv?", &ivValue,
	); err != nil {
		return nil, err
	}
	key, err := bytesForBinaryValue(keyValue)
	if err != nil {
		return nil, fmt.Errorf("aes: key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("aes: value: %w", err)
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("aes: input size must be a multiple of %d", aes.BlockSize)
	}
	out := make([]byte, len(data))
	switch strings.ToLower(mode) {
	case "ecb":
		for offset := 0; offset < len(data); offset += aes.BlockSize {
			if decrypt {
				block.Decrypt(out[offset:offset+aes.BlockSize], data[offset:offset+aes.BlockSize])
			} else {
				block.Encrypt(out[offset:offset+aes.BlockSize], data[offset:offset+aes.BlockSize])
			}
		}
	case "cbc":
		iv := make([]byte, aes.BlockSize)
		if ivValue != starlark.None {
			iv, err = bytesForBinaryValue(ivValue)
			if err != nil {
				return nil, fmt.Errorf("aes: iv: %w", err)
			}
			if len(iv) != aes.BlockSize {
				return nil, fmt.Errorf("aes: CBC IV must contain exactly %d bytes", aes.BlockSize)
			}
		}
		if decrypt {
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
		} else {
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
		}
	default:
		return nil, fmt.Errorf("aes: mode must be cbc or ecb")
	}
	return starlark.Bytes(out), nil
}

func cryptoModInverseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value, modulus starlark.Int
	if err := starlark.UnpackArgs("mod_inverse", args, kwargs, "value", &value, "modulus", &modulus); err != nil {
		return nil, err
	}
	m := modulus.BigInt()
	if m.Sign() <= 0 {
		return nil, fmt.Errorf("mod_inverse: modulus must be positive")
	}
	const maximumBits = 16 << 10
	if value.BigInt().BitLen() > maximumBits || m.BitLen() > maximumBits {
		return nil, fmt.Errorf("mod_inverse: operands must be at most %d bits", maximumBits)
	}
	inverse := new(big.Int).ModInverse(value.BigInt(), m)
	if inverse == nil {
		return starlark.None, nil
	}
	return starlark.MakeBigInt(inverse), nil
}

func newHash(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(strings.ReplaceAll(algorithm, "-", "")) {
	case "md4":
		return newMD4(), nil
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha224":
		return sha256.New224(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", algorithm)
	}
}

func hashValue(h hash.Hash, value starlark.Value) error {
	if file, ok := value.(storage.Reader); ok {
		_, err := io.Copy(h, io.NewSectionReader(file, 0, file.Size()))
		return err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return err
	}
	_, err = h.Write(data)
	return err
}

func cryptoHashBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var algorithm string
	var value starlark.Value
	if err := starlark.UnpackArgs("hash", args, kwargs, "algorithm", &algorithm, "value", &value); err != nil {
		return nil, err
	}
	h, err := newHash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	if err := hashValue(h, value); err != nil {
		return nil, fmt.Errorf("hash: %w", err)
	}
	return starlark.Bytes(h.Sum(nil)), nil
}

func cryptoHMACBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var algorithm string
	var keyValue, value starlark.Value
	if err := starlark.UnpackArgs("hmac", args, kwargs, "algorithm", &algorithm, "key", &keyValue, "value", &value); err != nil {
		return nil, err
	}
	key, err := bytesForBinaryValue(keyValue)
	if err != nil {
		return nil, fmt.Errorf("hmac: key: %w", err)
	}
	factory := func() hash.Hash {
		h, factoryErr := newHash(algorithm)
		if factoryErr != nil {
			panic(factoryErr)
		}
		return h
	}
	if _, err := newHash(algorithm); err != nil {
		return nil, fmt.Errorf("hmac: %w", err)
	}
	h := hmac.New(factory, key)
	if err := hashValue(h, value); err != nil {
		return nil, fmt.Errorf("hmac: %w", err)
	}
	return starlark.Bytes(h.Sum(nil)), nil
}

func cryptoRC4Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var keyValue, value starlark.Value
	if err := starlark.UnpackArgs("rc4", args, kwargs, "key", &keyValue, "value", &value); err != nil {
		return nil, err
	}
	key, err := bytesForBinaryValue(keyValue)
	if err != nil {
		return nil, fmt.Errorf("rc4: key: %w", err)
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("rc4: value: %w", err)
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("rc4: %w", err)
	}
	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return starlark.Bytes(out), nil
}

// cryptoXTEABuiltin applies the standard 32-round XTEA block cipher.  Modes
// and framing deliberately remain with callers so format modules can express
// unusual constructions without adding format policy to this package.
func cryptoXTEABuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var keyValue, value starlark.Value
	decrypt := false
	byteOrder := "big"
	if err := starlark.UnpackArgs("xtea", args, kwargs, "key", &keyValue, "value", &value, "decrypt?", &decrypt, "byte_order?", &byteOrder); err != nil {
		return nil, err
	}
	key, err := bytesForBinaryValue(keyValue)
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("xtea: key must contain exactly 16 bytes")
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("xtea: value: %w", err)
	}
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("xtea: input size must be a multiple of 8")
	}
	var order binary.ByteOrder
	switch strings.ToLower(byteOrder) {
	case "big", "be", "big-endian":
		order = binary.BigEndian
	case "little", "le", "little-endian":
		order = binary.LittleEndian
	default:
		return nil, fmt.Errorf("xtea: byte_order must be big or little")
	}
	words := [4]uint32{
		order.Uint32(key[0:4]), order.Uint32(key[4:8]),
		order.Uint32(key[8:12]), order.Uint32(key[12:16]),
	}
	out := make([]byte, len(data))
	for offset := 0; offset < len(data); offset += 8 {
		left, right := order.Uint32(data[offset:offset+4]), order.Uint32(data[offset+4:offset+8])
		if decrypt {
			sum := uint32(0xc6ef3720)
			for range 32 {
				right -= (((left << 4) ^ (left >> 5)) + left) ^ (sum + words[(sum>>11)&3])
				sum -= uint32(0x9e3779b9)
				left -= (((right << 4) ^ (right >> 5)) + right) ^ (sum + words[sum&3])
			}
		} else {
			var sum uint32
			for range 32 {
				left += (((right << 4) ^ (right >> 5)) + right) ^ (sum + words[sum&3])
				sum += uint32(0x9e3779b9)
				right += (((left << 4) ^ (left >> 5)) + left) ^ (sum + words[(sum>>11)&3])
			}
		}
		order.PutUint32(out[offset:offset+4], left)
		order.PutUint32(out[offset+4:offset+8], right)
	}
	return starlark.Bytes(out), nil
}

func cryptoDESBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var keyValue, value, ivValue starlark.Value
	ivValue = starlark.None
	decrypt := false
	if err := starlark.UnpackArgs("des", args, kwargs, "key", &keyValue, "value", &value, "decrypt?", &decrypt, "iv?", &ivValue); err != nil {
		return nil, err
	}
	key, err := bytesForBinaryValue(keyValue)
	if err != nil {
		return nil, fmt.Errorf("des: key: %w", err)
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("des: value: %w", err)
	}
	if len(data)%des.BlockSize != 0 {
		return nil, fmt.Errorf("des: input size must be a multiple of %d", des.BlockSize)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("des: %w", err)
	}
	var iv []byte
	if ivValue != starlark.None {
		iv, err = bytesForBinaryValue(ivValue)
		if err != nil || len(iv) != des.BlockSize {
			return nil, fmt.Errorf("des: iv must contain exactly %d bytes", des.BlockSize)
		}
	}
	out := make([]byte, len(data))
	previous := append([]byte(nil), iv...)
	for offset := 0; offset < len(data); offset += des.BlockSize {
		input := data[offset : offset+des.BlockSize]
		output := out[offset : offset+des.BlockSize]
		if decrypt {
			block.Decrypt(output, input)
			if iv != nil {
				for i := range output {
					output[i] ^= previous[i]
				}
				copy(previous, input)
			}
		} else {
			copy(output, input)
			if iv != nil {
				for i := range output {
					output[i] ^= previous[i]
				}
			}
			block.Encrypt(output, output)
			if iv != nil {
				copy(previous, output)
			}
		}
	}
	return starlark.Bytes(out), nil
}

func cryptoChecksumBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var algorithm string
	var value starlark.Value
	if err := starlark.UnpackArgs("checksum", args, kwargs, "algorithm", &algorithm, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	var result uint32
	switch strings.ToLower(strings.ReplaceAll(algorithm, "-", "")) {
	case "adler32":
		result = adler32.Checksum(data)
	case "crc32", "crc32ieee":
		result = crc32.ChecksumIEEE(data)
	case "crc32c", "castagnoli":
		result = crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli))
	case "crc32bzip2", "bzip2":
		result = crc32Bzip2(data)
	default:
		return nil, fmt.Errorf("checksum: unsupported algorithm %q", algorithm)
	}
	return starlark.MakeUint(uint(result)), nil
}

// crc32Bzip2 implements the non-reflected CRC-32/BZIP2 parameters. Go's
// hash/crc32 package exposes reflected CRCs, so the table is kept separate.
var crc32Bzip2Table = func() [256]uint32 {
	var table [256]uint32
	for index := range table {
		value := uint32(index) << 24
		for bit := 0; bit < 8; bit++ {
			if value&0x80000000 != 0 {
				value = value<<1 ^ 0x04c11db7
			} else {
				value <<= 1
			}
		}
		table[index] = value
	}
	return table
}()

func crc32Bzip2(data []byte) uint32 {
	value := uint32(0xffffffff)
	for _, current := range data {
		value = value<<8 ^ crc32Bzip2Table[byte(value>>24)^current]
	}
	return ^value
}

func cryptoConstantTimeEqualBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var leftValue, rightValue starlark.Value
	if err := starlark.UnpackArgs("constant_time_equal", args, kwargs, "left", &leftValue, "right", &rightValue); err != nil {
		return nil, err
	}
	left, err := bytesForBinaryValue(leftValue)
	if err != nil {
		return nil, fmt.Errorf("constant_time_equal: left: %w", err)
	}
	right, err := bytesForBinaryValue(rightValue)
	if err != nil {
		return nil, fmt.Errorf("constant_time_equal: right: %w", err)
	}
	return starlark.Bool(subtle.ConstantTimeCompare(left, right) == 1), nil
}

func cryptoRandomBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var size int
	if err := starlark.UnpackArgs("random", args, kwargs, "size", &size); err != nil {
		return nil, err
	}
	if size < 0 || size > defaultBinaryBuilderLimit {
		return nil, fmt.Errorf("random: size must be between 0 and %d", defaultBinaryBuilderLimit)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return starlark.Bytes(data), nil
}

func cryptoDeterministicBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var seedValue starlark.Value
	var size int
	algorithm := "sha256"
	if err := starlark.UnpackArgs("deterministic", args, kwargs, "seed", &seedValue, "size", &size, "algorithm?", &algorithm); err != nil {
		return nil, err
	}
	if size < 0 || size > defaultBinaryBuilderLimit {
		return nil, fmt.Errorf("deterministic: size must be between 0 and %d", defaultBinaryBuilderLimit)
	}
	seed, err := bytesForBinaryValue(seedValue)
	if err != nil {
		return nil, fmt.Errorf("deterministic: seed: %w", err)
	}
	out := make([]byte, 0, size)
	var counter uint64
	for len(out) < size {
		h, err := newHash(algorithm)
		if err != nil {
			return nil, fmt.Errorf("deterministic: %w", err)
		}
		_, _ = h.Write([]byte("trex/crypto/deterministic\x00"))
		_, _ = h.Write(seed)
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], counter)
		_, _ = h.Write(encoded[:])
		out = append(out, h.Sum(nil)...)
		counter++
	}
	return starlark.Bytes(out[:size]), nil
}

type cryptoHasher struct {
	algorithm string
	hash      hash.Hash
	frozen    bool
}

func cryptoHasherBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var algorithm string
	if err := starlark.UnpackArgs("hasher", args, kwargs, "algorithm", &algorithm); err != nil {
		return nil, err
	}
	h, err := newHash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("hasher: %w", err)
	}
	return &cryptoHasher{algorithm: algorithm, hash: h}, nil
}
func (h *cryptoHasher) String() string {
	return fmt.Sprintf("<crypto.hasher algorithm=%q>", h.algorithm)
}
func (h *cryptoHasher) Type() string          { return "crypto.hasher" }
func (h *cryptoHasher) Freeze()               { h.frozen = true }
func (h *cryptoHasher) Truth() starlark.Bool  { return starlark.True }
func (h *cryptoHasher) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", h.Type()) }
func (h *cryptoHasher) AttrNames() []string   { return []string{"reset", "sum", "update"} }
func (h *cryptoHasher) Attr(name string) (starlark.Value, error) {
	if name == "update" {
		return starlark.NewBuiltin("update", h.updateBuiltin), nil
	}
	if name == "sum" {
		return starlark.NewBuiltin("sum", h.sumBuiltin), nil
	}
	if name == "reset" {
		return starlark.NewBuiltin("reset", h.resetBuiltin), nil
	}
	return nil, nil
}
func (h *cryptoHasher) updateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("update", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	if h.frozen {
		return nil, fmt.Errorf("update: hasher is frozen")
	}
	if err := hashValue(h.hash, value); err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}
	return h, nil
}
func (h *cryptoHasher) sumBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("sum", args, kwargs); err != nil {
		return nil, err
	}
	return starlark.Bytes(h.hash.Sum(nil)), nil
}
func (h *cryptoHasher) resetBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("reset", args, kwargs); err != nil {
		return nil, err
	}
	if h.frozen {
		return nil, fmt.Errorf("reset: hasher is frozen")
	}
	h.hash.Reset()
	return h, nil
}

// md4Digest implements RFC 1320 as a generic legacy hash primitive required by
// old Windows formats. It contains no Windows-specific key or record behavior.
type md4Digest struct {
	state [4]uint32
	count uint64
	block [64]byte
	used  int
}

func newMD4() hash.Hash {
	d := &md4Digest{}
	d.Reset()
	return d
}
func (d *md4Digest) Reset() {
	d.state = [4]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}
	d.count, d.used = 0, 0
}
func (d *md4Digest) Size() int      { return 16 }
func (d *md4Digest) BlockSize() int { return 64 }
func (d *md4Digest) Write(data []byte) (int, error) {
	written := len(data)
	d.count += uint64(written)
	if d.used != 0 {
		n := copy(d.block[d.used:], data)
		d.used += n
		data = data[n:]
		if d.used == len(d.block) {
			d.compress(d.block[:])
			d.used = 0
		} else {
			return written, nil
		}
	}
	for len(data) >= len(d.block) {
		d.compress(data[:64])
		data = data[64:]
	}
	d.used = copy(d.block[:], data)
	return written, nil
}
func (d *md4Digest) Sum(prefix []byte) []byte {
	copyDigest := *d
	var padding [72]byte
	padding[0] = 0x80
	paddingSize := 56 - copyDigest.used
	if paddingSize <= 0 {
		paddingSize += 64
	}
	bitCount := copyDigest.count * 8
	_, _ = copyDigest.Write(padding[:paddingSize])
	binary.LittleEndian.PutUint64(padding[:8], bitCount)
	_, _ = copyDigest.Write(padding[:8])
	var digest [16]byte
	for i, value := range copyDigest.state {
		binary.LittleEndian.PutUint32(digest[i*4:], value)
	}
	return append(prefix, digest[:]...)
}
func (d *md4Digest) compress(block []byte) {
	var x [16]uint32
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(block[i*4:])
	}
	state := d.state
	f := func(x, y, z uint32) uint32 { return x&y | ^x&z }
	g := func(x, y, z uint32) uint32 { return x&y | x&z | y&z }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	register := [...]int{0, 3, 2, 1}
	for step := 0; step < 16; step++ {
		current := register[step%4]
		state[current] = rotateLeft(
			state[current]+f(state[(current+1)%4], state[(current+2)%4], state[(current+3)%4])+x[step],
			[...]int{3, 7, 11, 19}[step%4],
		)
	}
	roundTwoIndex := [...]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	for step, index := range roundTwoIndex {
		current := register[step%4]
		state[current] = rotateLeft(
			state[current]+g(state[(current+1)%4], state[(current+2)%4], state[(current+3)%4])+x[index]+0x5a827999,
			[...]int{3, 5, 9, 13}[step%4],
		)
	}
	roundThreeIndex := [...]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
	for step, index := range roundThreeIndex {
		current := register[step%4]
		state[current] = rotateLeft(
			state[current]+h(state[(current+1)%4], state[(current+2)%4], state[(current+3)%4])+x[index]+0x6ed9eba1,
			[...]int{3, 9, 11, 15}[step%4],
		)
	}
	for i := range d.state {
		d.state[i] += state[i]
	}
}
func rotateLeft(value uint32, shift int) uint32 { return value<<shift | value>>(32-shift) }
