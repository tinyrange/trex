package native

import (
	"golang.org/x/sys/windows"
	"io/fs"
	"unsafe"
)

var queryVolumeInformation = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")

// Space queries the opened root's volume, including after the directory has
// been renamed. It never resolves the original host path a second time.
func (r *Root) Space() (uint64, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, 0, fs.ErrClosed
	}
	f, err := r.root.Open(".")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var status struct{ Status, Information uintptr }
	var info struct {
		Total, Available, ActualAvailable int64
		SectorsPerUnit, BytesPerSector    uint32
	}
	code, _, _ := queryVolumeInformation.Call(f.Fd(), uintptr(unsafe.Pointer(&status)), uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 7)
	if int32(code) < 0 {
		return 0, 0, windows.NTStatus(code)
	}
	unit := uint64(info.SectorsPerUnit) * uint64(info.BytesPerSector)
	return uint64(info.Total) * unit, uint64(info.Available) * unit, nil
}
