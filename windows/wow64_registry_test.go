package windows

import "testing"

func TestWOW64RegistryPhysicalKeys(t *testing.T) {
	for _, tc := range [][2]string{
		{`HKEY_CLASSES_ROOT\CLSID\{id}\InprocServer32`, `HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{id}\InprocServer32`},
		{`HKEY_CLASSES_ROOT\TypeLib\{id}`, `HKEY_CLASSES_ROOT\TypeLib\{id}`},
		{`HKEY_CLASSES_ROOT\AppID\{id}`, `HKEY_CLASSES_ROOT\AppID\{id}`},
		{`HKEY_CLASSES_ROOT\Interface\{id}`, `HKEY_CLASSES_ROOT\WOW6432Node\Interface\{id}`},
		{`HKEY_LOCAL_MACHINE\Software\Vendor\Product`, `HKEY_LOCAL_MACHINE\Software\WOW6432Node\Vendor\Product`},
		{`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\app.exe`, `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\app.exe`},
		{`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App PathsSuffix`, `HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App PathsSuffix`},
		{`HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{id}`, `HKEY_LOCAL_MACHINE\Software\Classes\WOW6432Node\CLSID\{id}`},
		{`HKEY_CURRENT_USER\Software\Vendor`, `HKEY_CURRENT_USER\Software\Vendor`},
		{`HKEY_CURRENT_USER\Software\Classes\CLSID\{id}`, `HKEY_CURRENT_USER\Software\Classes\WOW6432Node\CLSID\{id}`},
		{`HKEY_USERS\.DEFAULT\Software\Classes\CLSID\{id}`, `HKEY_USERS\.DEFAULT\Software\Classes\WOW6432Node\CLSID\{id}`},
		{`HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001`, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001`},
	} {
		if got := wow64RegistryKey(tc[0]); got != tc[1] {
			t.Errorf("%s: got %s, want %s", tc[0], got, tc[1])
		}
		if got := wow64RegistryKey(tc[1]); got != tc[1] {
			t.Errorf("double redirected %s to %s", tc[1], got)
		}
	}
}
