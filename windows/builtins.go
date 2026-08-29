package windows

import "go.starlark.net/starlark"

// Builtins returns the Windows format and construction functions exposed by
// the optional Starlark frontend.
func Builtins() starlark.StringDict {
	functions := map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){
		"ne_fastboot": windowsNEFastBootBuiltin, "setver": windowsSetverBuiltin,
		"win9x_vxd_unpack": win9xVXDUnpackBuiltin, "win9x_vxd_library": win9xVXDLibraryBuiltin, "win9x_vxd_library_members": win9xVXDLibraryMembersBuiltin,
		"pdb": windowsPDBBuiltin, "symbol_server": windowsSymbolServerBuiltin, "hive": hiveBuiltin,
		"assembly_manifest": assemblyManifestBuiltin, "certificate": certificateBuiltin, "csp_registrations": cspRegistrationsBuiltin,
		"font_names": fontNamesBuiltin, "icon": windowsIconBuiltin, "pe": peObjectBuiltin, "pe32_executable": pe32ExecutableBuiltin,
		"hive_from_patches": hiveFromPatchesBuiltin, "creg_from_patches": cregFromPatchesBuiltin, "creg_compare": cregCompareBuiltin,
		"creg_keys": cregKeysBuiltin, "creg_patches": cregPatchesBuiltin, "hive_keys": hiveKeysBuiltin, "hive_patches": hivePatchesBuiltin,
		"hives_from_inf": hivesFromINFBuiltin, "inf_patches": infPatchesBuiltin, "inf": infBuiltin, "msc_snapins": mscSnapinsBuiltin,
		"minidump": minidumpBuiltin, "mof": mofBuiltin, "wmi_repository": wmiRepositoryBuiltin,
		"pkcs7_certificates": pkcs7CertificatesBuiltin, "catalog_members": catalogMembersBuiltin, "catalog_hash": catalogHashBuiltin,
		"patch_hive": patchHiveBuiltin, "hive_log": hiveLogBuiltin, "empty_event_log": emptyEventLogBuiltin, "event_log": eventLogBuiltin,
		"selfreg_patches": selfregPatchesBuiltin, "shortcut": shortcutBuiltin, "internet_shortcut": internetShortcutBuiltin,
		"utf16_strings": utf16StringsBuiltin,
	}
	result := make(starlark.StringDict, len(functions))
	for name, function := range functions {
		result[name] = starlark.NewBuiltin(name, function)
	}
	return result
}
