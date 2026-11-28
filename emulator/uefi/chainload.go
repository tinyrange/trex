package uefi

import (
	"debug/pe"
	"encoding/binary"

	"github.com/tinyrange/trex/emulator/peimage"
)

const (
	loadError       = efiError | 1
	imageReturnGate = "Image.Return"
	maxImageBytes   = 256 << 20
	maxDevicePath   = 4096
)

type loadedApplication struct {
	base, pages, entry, handlePages uint64
	running                         bool
}

// ImageStart describes the control transfer after StartImage. The caller
// enters PC using the firmware ABI, with ReturnAddress as the return target.
type ImageStart struct {
	PC, ImageHandle, SystemTable, ReturnAddress uint64
}

// StartImage enters a buffer-loaded application. The CPU owner calls
// FinishImage when the application returns via ReturnAddress.
func (f *Firmware) StartImage(handle uint64) (ImageStart, uint64) {
	m := f.machine
	image, ok := f.applications[handle]
	if m.exited || !ok || image.running {
		return ImageStart{}, invalidParameter
	}
	image.running = true
	f.applications[handle] = image
	m.activeImage = handle
	return ImageStart{image.entry, handle, m.systemTable, f.applicationReturn}, 0
}

// FinishImage restores the parent as the active EFI image.
func (f *Firmware) FinishImage(handle, parent uint64) {
	image := f.applications[handle]
	image.running = false
	f.applications[handle] = image
	f.machine.activeImage = parent
}

func (f *Firmware) loadApplication(a [10]uint64) uint64 {
	m := f.machine
	if m.exited || m.protocols[a[1]][loadedImageGUID] == 0 || a[5] == 0 {
		return invalidParameter
	}
	// A source-buffer load needs no firmware filesystem lookup.
	if a[3] == 0 {
		return unsupported
	}
	if a[4] == 0 || a[4] > min(m.opts.Memory, maxImageBytes) {
		return loadError
	}
	path, valid := m.copyDevicePath(a[2])
	if !valid {
		return invalidParameter
	}
	image, err := peimage.Parse(m.get(a[3], a[4]), min(m.opts.Memory, maxImageBytes))
	if err != nil || image.Architecture.Name != f.architecture {
		return loadError
	}
	pages := (uint64(len(image.Data)) + page - 1) / page
	allocationKind := uint64(0)
	if image.Characteristics&pe.IMAGE_FILE_RELOCS_STRIPPED != 0 {
		allocationKind = 2
	}
	base := m.allocate(allocationKind, 1, pages, image.PreferredBase)
	if base == 0 {
		return outOfResources
	}
	// Position-independent EFI images can omit the relocation directory.
	// A COFF image with relocations explicitly stripped needs its fixed base.
	relocation := image.Directories[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if relocation.VirtualAddress != 0 || relocation.Size != 0 {
		if err := image.Rebase(base); err != nil {
			m.free(base, pages)
			return loadError
		}
	}
	// Store the interface and its private, caller-independent copy of FilePath
	// in the same allocation as the handle.
	handlePages := (uint64(len(path)) + 128 + page - 1) / page
	handle := m.allocate(0, 2, handlePages, 0)
	if handle == 0 {
		m.free(base, pages)
		return outOfResources
	}
	loaded := make([]byte, 128)
	binary.LittleEndian.PutUint32(loaded, 0x1000)
	binary.LittleEndian.PutUint64(loaded[8:], a[1])
	binary.LittleEndian.PutUint64(loaded[16:], m.systemTable)
	if len(path) != 0 {
		binary.LittleEndian.PutUint64(loaded[32:], handle+128)
		m.put(handle+128, path)
	}
	binary.LittleEndian.PutUint64(loaded[64:], base)
	binary.LittleEndian.PutUint64(loaded[72:], uint64(len(image.Data)))
	binary.LittleEndian.PutUint32(loaded[80:], 1)
	binary.LittleEndian.PutUint32(loaded[84:], 2)
	m.put(base, image.Data)
	m.put(handle, loaded)
	m.protocols[handle] = map[string]uint64{loadedImageGUID: handle}
	f.applications[handle] = loadedApplication{base: base, pages: pages, entry: base + uint64(image.EntryRVA), handlePages: handlePages}
	m.u64(a[5], handle)
	return 0
}

func (f *Firmware) unloadApplication(handle uint64) uint64 {
	image, ok := f.applications[handle]
	if f.machine.exited || !ok || image.running {
		return invalidParameter
	}
	f.machine.free(image.base, image.pages)
	f.machine.free(handle, image.handlePages)
	delete(f.applications, handle)
	delete(f.machine.protocols, handle)
	return 0
}

func (m *Machine) copyDevicePath(address uint64) ([]byte, bool) {
	var result []byte
	if address == 0 {
		return result, true
	}
	for len(result)+4 <= maxDevicePath {
		header := m.get(address+uint64(len(result)), 4)
		if m.err != nil {
			return nil, false
		}
		size := int(binary.LittleEndian.Uint16(header[2:]))
		if size < 4 || len(result)+size > maxDevicePath {
			return nil, false
		}
		result = append(result, m.get(address+uint64(len(result)), uint64(size))...)
		if header[0] == 0x7f && header[1] == 0xff {
			return result, size == 4 && m.err == nil
		}
	}
	return nil, false
}
