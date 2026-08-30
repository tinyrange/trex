package installshield

import (
	"testing"

	cabarchive "github.com/tinyrange/trex/archive/cab"
	starfile "github.com/tinyrange/trex/storage/star"

	"go.starlark.net/starlark"
)

func TestInstallerPlanResolvesExplicitComponentLocations(t *testing.T) {
	payload := &Archive{files: []fileRecord{{
		name: "app.exe", directory: `Bin`, group: "Application",
		components: []string{"<Data>/Program Files"}, path: "/Application/Bin/app.exe", expandedSize: 123,
	}}}
	installer := &Installer{format: "installshield6", payload: payload, container: &cabarchive.Archive{}}
	locations := starlark.NewDict(1)
	if err := locations.SetKey(starlark.String("<Data>/Program Files"), starlark.String(`C:\Program Files\Example`)); err != nil {
		t.Fatal(err)
	}
	value, err := installer.planBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("locations"), locations}})
	if err != nil {
		t.Fatal(err)
	}
	plan := value.(*starlark.Dict)
	filesValue, found, err := plan.Get(starlark.String("files"))
	if err != nil || !found {
		t.Fatalf("files: found=%v err=%v", found, err)
	}
	files := filesValue.(*starlark.List)
	if files.Len() != 1 {
		t.Fatalf("files = %d, want 1", files.Len())
	}
	entry := files.Index(0).(*starlark.Dict)
	destination, found, err := entry.Get(starlark.String("destination"))
	if err != nil || !found || string(destination.(starlark.String)) != `C:\Program Files\Example\Bin\app.exe` {
		t.Fatalf("destination = %v, found=%v err=%v", destination, found, err)
	}
}

func TestInstallerPlanIncludesEveryNestedPackage(t *testing.T) {
	primary := &Archive{files: []fileRecord{{name: "main.exe", path: "/Main/main.exe", expandedSize: 1}}}
	nested := &Archive{files: []fileRecord{{name: "helper.exe", path: "/Helper/helper.exe", expandedSize: 2}}}
	installer := &Installer{
		format: "installshield5", payload: primary, container: &cabarchive.Archive{},
		packages: []installerPackage{{root: "/", payload: primary}, {root: "/sendfax", payload: nested}},
	}
	value, err := installer.planBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	filesValue, _, _ := value.(*starlark.Dict).Get(starlark.String("files"))
	files := filesValue.(*starlark.List)
	if files.Len() != 2 {
		t.Fatalf("files = %d, want 2", files.Len())
	}
	root, _, _ := files.Index(1).(*starlark.Dict).Get(starlark.String("package_root"))
	if got, want := string(root.(starlark.String)), "/sendfax"; got != want {
		t.Fatalf("nested package root = %q, want %q", got, want)
	}
}

func TestInstallerPlanSelectsExactComponents(t *testing.T) {
	payload := &Archive{files: []fileRecord{
		{name: "app.exe", group: "Application", components: []string{"<Data>/Program Files"}, path: "/Application/app.exe", expandedSize: 1},
		{name: "setup.vxd", group: "Setup Engine", components: []string{"<Engine>/Setup"}, path: "/Setup/setup.vxd"},
	}}
	installer := &Installer{format: "installshield6", payload: payload, container: &cabarchive.Archive{}}
	locations := starlark.NewDict(1)
	_ = locations.SetKey(starlark.String("<TARGETDIR>"), starlark.String(`C:\Program Files\Example`))
	components := starlark.NewList([]starlark.Value{starlark.String("<data>/program files")})
	value, err := installer.planBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("locations"), locations},
		{starlark.String("components"), components},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := value.(*starlark.Dict)
	filesValue, _, _ := plan.Get(starlark.String("files"))
	if got, want := filesValue.(*starlark.List).Len(), 1; got != want {
		t.Fatalf("files = %d, want %d", got, want)
	}
	artifactsValue, _, _ := plan.Get(starlark.String("artifacts"))
	if got := artifactsValue.(*starlark.List).Len(); got != 0 {
		t.Fatalf("artifacts = %d, want 0", got)
	}
}

func TestInstallerPlanRejectsStringComponents(t *testing.T) {
	installer := &Installer{format: "installshield6", payload: &Archive{}, container: &cabarchive.Archive{}}
	_, err := installer.planBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("components"), starlark.String("Application")}})
	if err == nil {
		t.Fatal("string components were accepted")
	}
}

func TestInstallerPlanSkipsInvalidDatabasePlaceholderName(t *testing.T) {
	payload := &Archive{files: []fileRecord{
		{name: "valid.ini", components: []string{"Application"}},
		{name: "\x19\x17", components: []string{"Application"}},
	}}
	installer := &Installer{format: "installshield6", payload: payload, container: &cabarchive.Archive{}}
	value, err := installer.planBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("components"), starlark.NewList([]starlark.Value{starlark.String("Application")})}})
	if err != nil {
		t.Fatal(err)
	}
	filesValue, _, _ := value.(*starlark.Dict).Get(starlark.String("files"))
	if got, want := filesValue.(*starlark.List).Len(), 1; got != want {
		t.Fatalf("files = %d, want %d", got, want)
	}
}

func TestInstallerPlanInspectsActiveXControlsForRegistration(t *testing.T) {
	for _, name := range []string{"control.ocx", "CONTROL.OCX", "helper.dll", "setup.exe"} {
		if !installPlanExecutableArtifact(name, "") {
			t.Fatalf("%q was not treated as an executable installer artifact", name)
		}
	}
	if installPlanExecutableArtifact("readme.txt", "") {
		t.Fatal("plain data was treated as an executable installer artifact")
	}
}

func TestInstallPlanCustomActionsRejectsUnprovedLegacyCalls(t *testing.T) {
	unsafe := starlark.NewDict(2)
	_ = unsafe.SetKey(starlark.String("dll"), starlark.String("example.dll"))
	_ = unsafe.SetKey(starlark.String("construction_safe"), starlark.False)
	safe := starlark.NewDict(1)
	_ = safe.SetKey(starlark.String("dll"), starlark.String("example.dll"))
	actions := installPlanCustomActions(starlark.NewList([]starlark.Value{unsafe, safe}))
	if got, want := actions.Len(), 1; got != want || actions.Index(0) != safe {
		t.Fatalf("custom actions = %v, want only proved call", actions)
	}
}

func TestJoinInstallWindowsPathPreservesUNC(t *testing.T) {
	if got, want := joinInstallWindowsPath(`\\server\share`, "bin", "app.exe"), `\\server\share\bin\app.exe`; got != want {
		t.Fatalf("join = %q, want %q", got, want)
	}
}

func TestExpandInstallPlanValueResolvesEmbeddedTokens(t *testing.T) {
	locations := map[string]string{"<uninstpath>": `C:\Program Files\Example`}
	got, resolved := expandInstallPlanValue(`-f"<UninstPath>\Uninst.isu" -c"<UNINSTPATH>\Uninst.dll"`, locations, nil)
	want := `-f"C:\Program Files\Example\Uninst.isu" -c"C:\Program Files\Example\Uninst.dll"`
	if !resolved || got != want {
		t.Fatalf("expanded value = %q, resolved=%v, want %q, true", got, resolved, want)
	}

	got, resolved = expandInstallPlanValue(`-f"<Missing>\Uninst.isu"`, locations, nil)
	if resolved || got != `-f"<Missing>\Uninst.isu"` {
		t.Fatalf("unresolved value = %q, resolved=%v", got, resolved)
	}
}

func TestParseInstallPlanINI(t *testing.T) {
	profiles := parseInstallPlanINI([]byte("; comment\r\n[Setup]\r\n AppType = 100 \r\nPath=C:\\Program Files\r\n"))
	if got, want := profiles["Setup"]["AppType"], "100"; got != want {
		t.Fatalf("AppType = %q, want %q", got, want)
	}
	if got, want := profiles["Setup"]["Path"], `C:\Program Files`; got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
}

func TestInstallerPlanExposesEmbeddedProfiles(t *testing.T) {
	contents := []byte("[Startup]\r\nAppName=Example Player\r\n")
	container, err := cabarchive.Open(&starfile.Bytes{
		Name: "container.cab",
		Data: uncompressedTestCabinet("Setup.ini", contents),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	installer := &Installer{format: "installshield6", payload: &Archive{}, container: container}
	value, err := installer.planBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	profilesValue, found, err := value.(*starlark.Dict).Get(starlark.String("profiles"))
	if err != nil || !found {
		t.Fatalf("profiles: found=%v err=%v", found, err)
	}
	setupValue, found, err := profilesValue.(*starlark.Dict).Get(starlark.String("Setup.ini"))
	if err != nil || !found {
		t.Fatalf("Setup.ini: found=%v err=%v", found, err)
	}
	startupValue, found, err := setupValue.(*starlark.Dict).Get(starlark.String("Startup"))
	if err != nil || !found {
		t.Fatalf("Startup: found=%v err=%v", found, err)
	}
	appName, found, err := startupValue.(*starlark.Dict).Get(starlark.String("AppName"))
	if err != nil || !found || string(appName.(starlark.String)) != "Example Player" {
		t.Fatalf("AppName = %v, found=%v err=%v", appName, found, err)
	}
}
