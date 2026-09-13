package archivegui

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

// ShellExecute uses the registered Windows file association. It is invoked
// only by an explicit desktop action, never to implement archive processing.
func shellOpen(name string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err != nil && err != syscall.Errno(1) { // S_FALSE also owns a COM reference.
		return err
	}
	defer windows.CoUninitialize()
	file, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}
