package apfs

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Seal describes a volume's integrity metadata and filesystem root. Hashes
// here describe the image; authenticating them requires a trusted external seal.
type Seal struct {
	Version, Flags, HashType      uint32
	BrokenTransaction             uint64
	RootAddress, IntegrityAddress uint64
	RootHash, RootNode            []byte
}

func sealHasher(kind uint32) (hash.Hash, error) {
	switch kind {
	case 1:
		return sha256.New(), nil
	case 2:
		return sha512.New512_256(), nil
	case 3:
		return sha512.New384(), nil
	case 4:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("apfs: unsupported seal hash type %d", kind)
	}
}

// SealInformation reads the versioned integrity object without assuming that
// the advertised root hash is authentic or that descendants are intact.
func (v *Volume) SealInformation() (*Seal, error) {
	if v.Integrity == 0 || v.Incompatible&0x20 == 0 {
		return nil, fmt.Errorf("apfs: volume is not sealed")
	}
	address, err := resolve(v.omap, v.Integrity)
	if err != nil {
		return nil, err
	}
	b, err := v.container.object(address, 30)
	if err != nil {
		return nil, err
	}
	s := &Seal{Version: le.Uint32(b[32:]), Flags: le.Uint32(b[36:]), HashType: le.Uint32(b[40:]), BrokenTransaction: le.Uint64(b[48:]), IntegrityAddress: address}
	if s.Version != 1 && s.Version != 2 {
		return nil, fmt.Errorf("apfs: unsupported integrity version %d", s.Version)
	}
	if s.Flags & ^uint32(1) != 0 || (s.Flags&1 == 0) != (s.BrokenTransaction == 0) {
		return nil, fmt.Errorf("apfs: inconsistent seal flags/transaction")
	}
	h, err := sealHasher(s.HashType)
	if err != nil {
		return nil, err
	}
	off := uint64(le.Uint32(b[44:]))
	minimum := uint64(56)
	if s.Version == 2 {
		minimum = 128
	}
	if off < minimum || off > uint64(len(b))-uint64(h.Size()) {
		return nil, fmt.Errorf("apfs: invalid root hash extent")
	}
	s.RootHash = append([]byte(nil), b[off:off+uint64(h.Size())]...)
	s.RootAddress, err = v.rootAddress(v.RootTree, v.RootTreeType)
	if err != nil {
		return nil, err
	}
	s.RootNode, err = v.container.raw(s.RootAddress)
	return s, err
}

// VerifySeal verifies the filesystem metadata tree against its advertised seal.
// A nonnil expected hash also binds it to the caller's trusted external value.
// File data is covered by the verified file-info records but is not read here.
func (v *Volume) VerifySeal(expected []byte) (records, dataHashes uint64, err error) {
	s, err := v.SealInformation()
	if err != nil {
		return 0, 0, err
	}
	if s.Flags != 0 {
		return 0, 0, fmt.Errorf("apfs: volume seal is broken")
	}
	if expected != nil && !bytes.Equal(expected, s.RootHash) {
		return 0, 0, fmt.Errorf("apfs: external root seal mismatch")
	}
	err = v.container.walkTreeHash(s.RootAddress, v.sealedResolver(s), s.HashType, s.RootHash, func(k, b []byte) error {
		if len(k) < 8 {
			return fmt.Errorf("apfs: truncated sealed filesystem key")
		}
		records++
		if le.Uint64(k)>>60 == 13 {
			if len(k) != 16 || le.Uint64(k[8:])>>56 != 1 || len(b) < 3+len(s.RootHash) || len(b) > 10+len(s.RootHash) || le.Uint16(b) == 0 || int(b[2]) != len(s.RootHash) {
				return fmt.Errorf("apfs: invalid sealed file-info record")
			}
			dataHashes++
		}
		return nil
	})
	return records, dataHashes, err
}

func (v *Volume) sealedResolver(s *Seal) func(uint64) (uint64, error) {
	return func(id uint64) (uint64, error) {
		if le.Uint16(s.RootNode[32:])&16 != 0 {
			if id > ^uint64(0)-v.RootTree {
				return 0, fmt.Errorf("apfs: wrapping relative child identifier")
			}
			id += v.RootTree
		}
		return v.rootAddress(id, v.RootTreeType)
	}
}

func verifySealBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.verify_seal", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var expected starlark.Value = starlark.None
		if err := starlark.UnpackArgs("verify_seal", args, kwargs, "expected?", &expected); err != nil {
			return nil, err
		}
		var root []byte
		if expected != starlark.None {
			b, ok := expected.(starlark.Bytes)
			if !ok {
				return nil, fmt.Errorf("apfs: expected root hash bytes")
			}
			root = []byte(b)
		}
		r, d, err := v.VerifySeal(root)
		if err != nil {
			return nil, err
		}
		return starfile.NewRecord(starlark.StringDict{"records": starlark.MakeUint64(r), "data_hashes": starlark.MakeUint64(d)}), nil
	})
}

func sealInfoBuiltin(v *Volume) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.seal_info", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("seal_info", args, kwargs); err != nil {
			return nil, err
		}
		s, err := v.SealInformation()
		if err != nil {
			return nil, err
		}
		return starfile.NewRecord(starlark.StringDict{
			"version": starlark.MakeUint64(uint64(s.Version)), "flags": starlark.MakeUint64(uint64(s.Flags)), "hash_type": starlark.MakeUint64(uint64(s.HashType)), "broken_transaction": starlark.MakeUint64(s.BrokenTransaction),
			"root_address": starlark.MakeUint64(s.RootAddress), "integrity_address": starlark.MakeUint64(s.IntegrityAddress), "root_hash": starlark.Bytes(s.RootHash), "root_node": starfile.NewReader("APFS sealed root", bytes.NewReader(s.RootNode)),
		}), nil
	})
}
