package memory

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// AMD64Translation describes a four-level paging resolution. Execute reflects
// NX bits in the page tables, assuming EFER.NXE. Writable is the combined R/W
// bit and does not include privilege-specific overrides such as CR0.WP.
type AMD64Translation struct {
	Physical, PageSize      uint64
	User, Writable, Execute bool
}

// WalkAMD64 resolves a canonical address with four-level x86-64 page tables
// without modifying accessed/dirty bits. readEntry reads physical words.
func WalkAMD64(cr3, address uint64, readEntry func(uint64) (uint64, error)) (AMD64Translation, error) {
	if uint64(int64(address<<16)>>16) != address {
		return AMD64Translation{}, &Fault{Kind: "invalid-address", Address: address, Level: "virtual"}
	}
	const physMask = 0x000ffffffffff000
	table := cr3 & physMask
	result := AMD64Translation{User: true, Writable: true, Execute: true}
	for _, level := range []struct {
		name  string
		shift uint
	}{{"pml4e", 39}, {"pdpte", 30}, {"pde", 21}, {"pte", 12}} {
		entryAddress := table + (address>>level.shift&511)*8
		entry, err := readEntry(entryAddress)
		if err != nil {
			return AMD64Translation{}, contextualFault(err, address, entryAddress, level.name)
		}
		if entry&1 == 0 {
			return AMD64Translation{}, &Fault{Kind: "not-present", Address: address, Physical: entryAddress, Level: level.name}
		}
		table = entry & physMask
		result.User = result.User && entry&4 != 0
		result.Writable = result.Writable && entry&2 != 0
		result.Execute = result.Execute && entry>>63 == 0
		large := entry&128 != 0 && (level.shift == 30 || level.shift == 21)
		if level.shift == 12 || large {
			result.PageSize = uint64(1) << level.shift
			mask := result.PageSize - 1
			result.Physical = table&^mask | address&mask
			return result, nil
		}
	}
	return AMD64Translation{}, fmt.Errorf("AMD64 page table walk did not reach a leaf")
}

// TranslateAMD64 walks page tables in a contiguous physical file starting at
// address zero. A sparse file can supply zero-filled holes.
func TranslateAMD64(source storage.Reader, cr3, address uint64) (AMD64Translation, error) {
	if source == nil {
		return AMD64Translation{}, fmt.Errorf("AMD64 translation requires a physical memory file")
	}
	return WalkAMD64(cr3, address, func(physical uint64) (uint64, error) {
		var raw [8]byte
		n, err := source.ReadAt(raw[:], int64(physical))
		if n == len(raw) && err == io.EOF {
			err = nil
		}
		if n != len(raw) && err == nil {
			err = io.ErrUnexpectedEOF
		}
		return binary.LittleEndian.Uint64(raw[:]), err
	})
}
