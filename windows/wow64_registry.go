package windows

import (
	"strings"

	"go.starlark.net/starlark"
)

// wow64RegistryKeyBuiltin resolves a 32-bit logical registry path to its
// physical location on AMD64 Windows 7 and later (no legacy reflection).
// Rules: https://learn.microsoft.com/windows/win32/winprog64/shared-registry-keys
func wow64RegistryKeyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs("wow64_registry_key", args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	return starlark.String(wow64RegistryKey(key)), nil
}

func wow64RegistryKey(key string) string {
	key = strings.ReplaceAll(key, "/", `\`)
	parts := strings.Split(key, `\`)
	if len(parts) == 0 {
		return key
	}
	classes := -1
	switch strings.ToUpper(parts[0]) {
	case "HKEY_CLASSES_ROOT":
		classes = 1
	case "HKEY_CURRENT_USER":
		if len(parts) > 2 && strings.EqualFold(parts[1], "Software") && strings.EqualFold(parts[2], "Classes") {
			classes = 3
		}
	case "HKEY_USERS":
		if len(parts) > 3 && strings.EqualFold(parts[2], "Software") && strings.EqualFold(parts[3], "Classes") {
			classes = 4
		}
	case "HKEY_LOCAL_MACHINE":
		if len(parts) <= 1 || !strings.EqualFold(parts[1], "Software") {
			return key
		}
		if len(parts) > 2 && strings.EqualFold(parts[2], "Classes") {
			classes = 3
		} else {
			suffix := strings.ToLower(strings.Join(parts[2:], `\`))
			if registryKeyWithin(suffix, "wow6432node") {
				return key
			}
			for _, shared := range wow64SharedSoftware {
				if registryKeyWithin(suffix, shared) {
					return key
				}
			}
			return strings.Join(append(append([]string{}, parts[:2]...), append([]string{"WOW6432Node"}, parts[2:]...)...), `\`)
		}
	}
	if classes >= 0 && len(parts) > classes {
		for _, redirected := range []string{"CLSID", "DirectShow", "Interface", "Media Type", "MediaFoundation"} {
			if strings.EqualFold(parts[classes], redirected) {
				return strings.Join(append(append([]string{}, parts[:classes]...), append([]string{"WOW6432Node"}, parts[classes:]...)...), `\`)
			}
		}
	}
	return key
}

func registryKeyWithin(key, root string) bool { return key == root || strings.HasPrefix(key, root+`\`) }

var wow64SharedSoftware = []string{
	`clients`, `policies`, `registeredapplications`,
	`microsoft\com3`, `microsoft\cryptography\calais\current`, `microsoft\cryptography\calais\readers`,
	`microsoft\cryptography\services`, `microsoft\ctf\systemshared`, `microsoft\ctf\tip`,
	`microsoft\dfs`, `microsoft\driver signing`, `microsoft\enterprisecertificates`,
	`microsoft\eventsystem`, `microsoft\msmq`, `microsoft\non-driver signing`, `microsoft\notepad\defaultfonts`,
	`microsoft\ole`, `microsoft\ras`, `microsoft\rpc`, `microsoft\shared tools\msinfo`,
	`microsoft\systemcertificates`, `microsoft\termservlicensing`, `microsoft\transactionserver`,
	`microsoft\windows\currentversion\app paths`, `microsoft\windows\currentversion\control panel\cursors\schemes`,
	`microsoft\windows\currentversion\explorer\autoplayhandlers`, `microsoft\windows\currentversion\explorer\driveicons`,
	`microsoft\windows\currentversion\explorer\kindmap`, `microsoft\windows\currentversion\group policy`,
	`microsoft\windows\currentversion\policies`, `microsoft\windows\currentversion\previewhandlers`,
	`microsoft\windows\currentversion\setup`, `microsoft\windows\currentversion\telephony\locations`,
	`microsoft\windows nt\currentversion\console`, `microsoft\windows nt\currentversion\fontdpi`,
	`microsoft\windows nt\currentversion\fontlink`, `microsoft\windows nt\currentversion\fontmapper`,
	`microsoft\windows nt\currentversion\fonts`, `microsoft\windows nt\currentversion\fontsubstitutes`,
	`microsoft\windows nt\currentversion\gre_initialize`, `microsoft\windows nt\currentversion\image file execution options`,
	`microsoft\windows nt\currentversion\language pack`, `microsoft\windows nt\currentversion\networkcards`,
	`microsoft\windows nt\currentversion\perflib`, `microsoft\windows nt\currentversion\ports`,
	`microsoft\windows nt\currentversion\print`, `microsoft\windows nt\currentversion\profilelist`,
	`microsoft\windows nt\currentversion\time zones`,
}
