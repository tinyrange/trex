package uup

import (
	"bytes"
	"testing"
)

func TestNativeCSIDeploymentRecords(t *testing.T) {
	const identity = "0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=amd64, versionScope=NonSxS"
	id, err := parseCSIIdentity([]byte(identity))
	if err != nil {
		t.Fatal(err)
	}
	key, err := csiDeploymentKey(id)
	if err != nil || key != "0074283ce7e..0edcf95464e_b77a5c561934e089_4.0.15920.100_3fb84cbf20555c08" {
		t.Fatalf("%q %v", key, err)
	}
	encoded, err := marshalCSIIdentity(id)
	if err != nil || string(encoded) != identity {
		t.Fatalf("%q %v", encoded, err)
	}
	primary := "Package_11_for_KB5126052~31bf3856ad364e35~amd64~~10.0.9347.1.5126052-721_neutral"
	key, err = cbsSourceKey(primary)
	if err != nil || key != "CBS_package_11_for_kb5126052~31bf3856ad364e35~amd64~~10.0.9347.1_c1f9778e70bce084" {
		t.Fatalf("%q %v", key, err)
	}
	native := append([]byte{80, 0, 0, 0, 1, 0, 0, 0}, []byte(primary+"8")...)
	source, err := parseCBSDeploymentSource(native)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = marshalCBSDeploymentSource(source, []byte("8"))
	if err != nil || !bytes.Equal(encoded, native) {
		t.Fatalf("%q %v", encoded, err)
	}
	source.Update = ""
	if _, err := marshalCBSDeploymentSource(source, nil); err == nil {
		t.Fatal("accepted empty update")
	}
	id.Name = "invalid/name"
	if _, err := csiDeploymentKey(id); err == nil {
		t.Fatal("accepted path separator")
	}
}

func TestNativeCSIFileKeys(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"wpcip.inf", "f!wpcip.inf"},
		{"1394.inf_loc", "f!1394.inf_loc_c820a7a9f3fa126b"},
		{"Windows.Internal.AdaptiveCards.XamlCardRenderer.dll", "f!windows.internal.adaptive_dae76fb214900fb4"},
		{`WidevineCdm\_platform_specific\win_x64\widevinecdm.dll`, "f!widevinecdm_platform_spec_28259d2da2c0d73a"},
		{"ODBC Data Sources (64-bit).lnk", "f!odbc_data_sources_64-bit__dacabb533b2082f6"},
		{"{60FD87F8-4593-44A0-91B0-2E0DA022F248}.cip", "f!_60fd87f8-4593-44a0-91b0-_228a32d74da9caef"},
	} {
		got, err := csiFileKey(tc.name)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %s %v", tc.name, got, err)
		}
	}
}
