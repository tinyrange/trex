package linux

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/storage"
)

func readFull(source storage.Reader, offset uint64, data []byte) error {
	if offset > uint64(source.Size()) || uint64(len(data)) > uint64(source.Size())-offset {
		return fmt.Errorf("linux: ELF read outside input")
	}
	n, err := source.ReadAt(data, int64(offset))
	if n != len(data) {
		return io.ErrUnexpectedEOF
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
func (p *process) load(image storage.Reader) error {
	if image == nil || image.Size() < 64 {
		return fmt.Errorf("linux: truncated ELF")
	}
	var header [64]byte
	if err := readFull(image, 0, header[:]); err != nil {
		return err
	}
	u16 := binary.LittleEndian.Uint16
	u32 := binary.LittleEndian.Uint32
	u64 := binary.LittleEndian.Uint64
	if string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 || u16(header[18:]) != 62 || u32(header[20:]) != 1 || u16(header[52:]) != 64 {
		return fmt.Errorf("linux: expected ELF64 little-endian AMD64")
	}
	kind := u16(header[16:])
	if kind != 2 && kind != 3 {
		return fmt.Errorf("linux: ELF is not executable or static PIE")
	}
	base := uint64(0)
	if kind == 3 {
		base = 0x40000000
	}
	entry := u64(header[24:])
	phoff := u64(header[32:])
	phsize := u16(header[54:])
	phnum := u16(header[56:])
	if phsize != 56 || phnum == 0 || phnum > 1024 {
		return fmt.Errorf("linux: invalid program header table")
	}
	if phoff > uint64(image.Size()) || uint64(phsize)*uint64(phnum) > uint64(image.Size())-phoff {
		return fmt.Errorf("linux: truncated program header table")
	}
	if entry >= userLimit-base {
		return fmt.Errorf("linux: invalid ELF entry")
	}
	phdr := uint64(0)
	loads := 0
	highest := uint64(0)
	for index := uint16(0); index < phnum; index++ {
		var h [56]byte
		if err := readFull(image, phoff+uint64(index)*56, h[:]); err != nil {
			return err
		}
		typ, flags := u32(h[:]), u32(h[4:])
		offset, address, filesz, memsz, alignment := u64(h[8:]), u64(h[16:]), u64(h[32:]), u64(h[40:]), u64(h[48:])
		if typ == 3 {
			return fmt.Errorf("linux: PT_INTERP requires an unsupported dynamic linker")
		}
		if typ != 1 {
			continue
		}
		loads++
		if filesz > memsz || filesz > 0 && (offset > uint64(image.Size()) || filesz > uint64(image.Size())-offset) || address >= userLimit-base || memsz > userLimit-base-address {
			return fmt.Errorf("linux: invalid ELF load segment offset=%#x address=%#x filesz=%#x memsz=%#x input=%#x", offset, address, filesz, memsz, image.Size())
		}
		if alignment > 1 && (alignment&(alignment-1) != 0 || address%alignment != offset%alignment) {
			return fmt.Errorf("linux: invalid ELF segment alignment")
		}
		if memsz == 0 {
			continue
		}
		address += base
		start := address &^ (pageSize - 1)
		size := align(address+memsz) - start
		if size > p.cfg.MaxMemory-p.used {
			return fmt.Errorf("linux: ELF exceeds memory budget")
		}
		data := make([]byte, int(size))
		if filesz > 0 {
			if err := readFull(image, offset, data[address-start:address-start+filesz]); err != nil {
				return err
			}
		}
		access := cpu.Access(0)
		if flags&4 != 0 {
			access |= cpu.Read
		}
		if flags&2 != 0 {
			access |= cpu.Write
		}
		if flags&1 != 0 {
			access |= cpu.Execute
		}
		if err := p.mapMemory(start, size, data, access); err != nil {
			return err
		}
		highest = max(highest, start+size)
		if phoff >= offset && phoff-offset <= filesz && uint64(phsize)*uint64(phnum) <= filesz-(phoff-offset) {
			phdr = address + (phoff - offset)
		}
	}
	if loads == 0 {
		return fmt.Errorf("linux: ELF has no load segments")
	}
	entry += base
	if err := p.memory.CheckMemory(entry, 1, cpu.Execute); err != nil {
		return fmt.Errorf("linux: entry is not executable: %w", err)
	}
	p.brk, p.initialBrk = highest, highest
	if err := p.stack(entry, phdr, uint64(phnum)); err != nil {
		return err
	}
	p.cpu.SetPC(entry)
	return nil
}
func (p *process) stack(entry, phdr, phnum uint64) error {
	const top = uint64(0x7ffffff00000)
	const size = uint64(2 << 20)
	if err := p.mapMemory(top-size, size, nil, cpu.Read|cpu.Write); err != nil {
		return err
	}
	cursor := top
	push := func(data []byte) (uint64, error) {
		if uint64(len(data)) > cursor-(top-size) {
			return 0, fmt.Errorf("linux: argument stack exceeds budget")
		}
		cursor -= uint64(len(data))
		return cursor, p.memory.WriteMemory(cursor, data)
	}
	stringsToPointers := func(values []string) ([]uint64, error) {
		if len(values) > 16384 {
			return nil, fmt.Errorf("linux: argument count budget exceeded")
		}
		pointers := make([]uint64, len(values))
		for i, value := range values {
			if strings.ContainsRune(value, 0) {
				return nil, fmt.Errorf("linux: NUL in process argument")
			}
			address, err := push(append([]byte(value), 0))
			if err != nil {
				return nil, err
			}
			pointers[i] = address
		}
		return pointers, nil
	}
	argv, err := stringsToPointers(p.cfg.Args)
	if err != nil {
		return err
	}
	env, err := stringsToPointers(p.cfg.Env)
	if err != nil {
		return err
	}
	random, err := push(p.cfg.Random[:])
	if err != nil {
		return err
	}
	words := []uint64{uint64(len(argv))}
	words = append(words, argv...)
	words = append(words, 0)
	words = append(words, env...)
	words = append(words, 0)
	// Linux/System V auxiliary vector; no host addresses or host credentials.
	words = append(words, 3, phdr, 4, 56, 5, phnum, 6, pageSize, 7, 0, 9, entry, 11, 1000, 12, 1000, 13, 1000, 14, 1000, 23, 0, 25, random, 0, 0)
	bytes := uint64(len(words)) * 8
	if bytes > cursor-(top-size) {
		return fmt.Errorf("linux: argument stack exceeds budget")
	}
	cursor = (cursor - bytes) &^ uint64(15)
	data := make([]byte, len(words)*8)
	for i, value := range words {
		binary.LittleEndian.PutUint64(data[i*8:], value)
	}
	if err := p.memory.WriteMemory(cursor, data); err != nil {
		return err
	}
	return p.cpu.SetRegister("rsp", cursor)
}
