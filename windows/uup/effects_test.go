package uup

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/tinyrange/trex/archive/cab"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestStageEffectsRetainCBSRegistryKeysWithoutInventingValues(t *testing.T) {
	const updated = `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\UpdatedApplications\Microsoft.UI.Xaml.CBS_8wekyb3d8bbwe`
	for _, arch := range []string{"amd64", "wow64"} {
		data := []byte(`<assembly><assemblyIdentity name="Microsoft-UI-Xaml-CBS" version="10.0.26100.8328" processorArchitecture="` + arch + `"/>
<registryKeys><registryKey keyName="` + updated + `"/>
<registryKey keyName="HKEY_CURRENT_USER\Software\Example"><registryValue name="Present" valueType="REG_DWORD" value="1"/></registryKey></registryKeys></assembly>`)
		name := arch + "_microsoft-ui-xaml-cbs.manifest"
		descriptor := ContentDescriptor{Name: name, Length: int64(len(data)), SHA256: sha256.Sum256(data)}
		payload := DeltaPayload{Target: descriptor, Record: descriptor, RecordType: "RAW", Literal: true}
		stage := &CumulativeStage{
			metadataCAB: &cab.Archive{}, Graph: &CumulativeGraph{Payloads: []DeltaPayload{payload}},
			PSF: &starfile.Bytes{Data: data}, expressByTarget: map[string]DeltaPayload{normalizeCIXName(name): payload},
		}
		plan, err := PlanStageEffects(stage, StageAssemblyPlan{Components: []PlannedComponent{{
			Path: name, Identity: AssemblyIdentity{Name: "Microsoft-UI-Xaml-CBS", Version: "10.0.26100.8328", ProcessorArchitecture: arch},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.RegistryKeys) != 2 || plan.Summary.RegistryKeys != 2 || plan.Summary.RegistryValues != 1 {
			t.Fatalf("lost registry declarations: %#v", plan)
		}
		if plan.RegistryKeys[0] != (StageRegistryKeyEffect{Architecture: arch, KeyName: updated}) || plan.RegistryKeys[1].Architecture != arch {
			t.Fatalf("key identity lost: %#v", plan.RegistryKeys)
		}
		if len(plan.RegistryValues) != 1 || plan.RegistryValues[0].Value.Name != "Present" {
			t.Fatalf("invented placeholder value: %#v", plan.RegistryValues)
		}
	}
}

func TestPackageCatalogHasNativeCatRootDestination(t *testing.T) {
	// Catalog-signed serviced drivers need the selected package catalog in
	// CatRoot as well as the CBS store. FileCrypt26100.1150 otherwise fails
	// with STATUS_INVALID_IMAGE_HASH even when its target bytes verify.
	for _, arch := range []string{"amd64", "wow64"} {
		name := "Package~31bf3856ad364e35~" + arch + "~~10.0.26100.1742"
		stage := &CumulativeStage{metadataCAB: &cab.Archive{}, Graph: &CumulativeGraph{
			Payloads: []DeltaPayload{
				{Target: ContentDescriptor{Name: name + ".mum"}},
				{Target: ContentDescriptor{Name: name + ".cat"}},
			},
		}}
		plan, err := PlanStageEffects(stage, StageAssemblyPlan{Packages: []NamedAssemblyManifest{{Path: name + ".mum"}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Files) != 2 {
			t.Fatalf("files: %#v", plan.Files)
		}
		for _, file := range plan.Files {
			if file.Kind != "package-catalog" {
				if len(file.Destinations) != 0 {
					t.Fatal("manifest installed as catalog")
				}
				continue
			}
			want := `$(runtime.windows)\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\` + name + ".cat"
			if file.StorePath != "/Windows/servicing/Packages/"+name+".cat" || len(file.Destinations) != 1 || file.Destinations[0] != want || file.SourceMode != "payload" {
				t.Fatalf("catalog placement %s: %#v", arch, file)
			}
		}
	}
}

func TestComponentSourcePathIgnoresBuildProvenance(t *testing.T) {
	got, err := componentSourcePath(AssemblyFile{
		Name: "CLR-ETW.man", SourceName: "CLR-ETW.man.txt",
		SourcePath: `Win\Microsoft.NET\Framework\v4`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "CLR-ETW.man" {
		t.Fatalf("source path = %q", got)
	}
}

func TestComponentSourcePathKeepsFileNameSubdirectory(t *testing.T) {
	got, err := componentSourcePath(AssemblyFile{Name: `f\a.dll`, SourceName: "a.dll"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "f/a.dll" {
		t.Fatalf("source path = %q", got)
	}
}

func TestComponentDestinationDoesNotRepeatStoreRelativeDirectory(t *testing.T) {
	for _, tc := range []struct{ name, destination, want string }{
		{`61869720.Voiess\appxmanifest.xml`, `$(runtime.windows)\SystemApps\SxS\MicrosoftWindows.61869720.Voiess_cw5n1h2txyewy\`, `$(runtime.windows)\SystemApps\SxS\MicrosoftWindows.61869720.Voiess_cw5n1h2txyewy\appxmanifest.xml`},
		{`61869720.Voiess\VoiceAccess\VoiceAccess.exe`, `$(runtime.windows)\SystemApps\SxS\MicrosoftWindows.61869720.Voiess_cw5n1h2txyewy\VoiceAccess\`, `$(runtime.windows)\SystemApps\SxS\MicrosoftWindows.61869720.Voiess_cw5n1h2txyewy\VoiceAccess\VoiceAccess.exe`},
		{`normal.dll`, `$(runtime.system32)`, `$(runtime.system32)\normal.dll`},
	} {
		relative, err := componentSourcePath(AssemblyFile{Name: tc.name})
		if err != nil {
			t.Fatal(err)
		}
		got := componentDestinationPath(tc.destination, relative)
		if got != tc.want {
			t.Fatalf("destination for %q = %q, want %q", tc.name, got, tc.want)
		}
		if relative != strings.ReplaceAll(tc.name, `\`, "/") {
			t.Fatal("destination mapping changed the component-store source path")
		}
	}
}

func TestComponentPayloadSourceNamesRetainInstalledAndBuildIdentities(t *testing.T) {
	got, err := componentPayloadSourceNames("amd64_component_hash", AssemblyFile{
		Name: "installed.dll.mun", SourceName: "source.dll", SourcePath: `f`,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`amd64_component_hash\installed.dll.mun`,
		`amd64_component_hash\source.dll`,
		`amd64_component_hash\f\source.dll`,
	}
	if len(got) != len(want) {
		t.Fatalf("source candidates = %#v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("source candidate %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestComponentPayloadSourceNamesTreatsCurrentSourcePathAsNoDirectory(t *testing.T) {
	got, err := componentPayloadSourceNames("component", AssemblyFile{
		Name: "installed.dll", SourceName: "source.dll", SourcePath: `.\`,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`component\installed.dll`, `component\source.dll`}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("source candidates = %#v, want %#v", got, want)
	}
}

func TestResolveStageEffectSourceUsesImageAliasAndPrefersLogicalPayload(t *testing.T) {
	payload := DeltaPayload{Target: ContentDescriptor{Name: `component\source.dll`}}
	payloads := map[string]DeltaPayload{}
	for _, key := range stageEffectLookupKeys(payload.Target.Name) {
		payloads[key] = payload
	}
	metadata := map[string]string{normalizeCIXName(`/image1/component/source.dll`): `/image1/component/source.dll`}
	got, err := resolveStageEffectSource("component-file", []string{`/image1/component/source.dll`}, nil, payloads, nil, nil, nil, metadata, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "payload" || got.Name != payload.Target.Name {
		t.Fatalf("source = %#v", got)
	}
}

func TestResolveStageEffectSourcePrefersInstalledName(t *testing.T) {
	left := DeltaPayload{Target: ContentDescriptor{Name: `component\installed.dll`}}
	right := DeltaPayload{Target: ContentDescriptor{Name: `component\source.dll`}}
	payloads := map[string]DeltaPayload{
		normalizeCIXName(left.Target.Name):  left,
		normalizeCIXName(right.Target.Name): right,
	}
	got, err := resolveStageEffectSource("component-file", []string{left.Target.Name, right.Target.Name}, nil, payloads, nil, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "payload" || got.Name != left.Target.Name {
		t.Fatalf("source = %#v", got)
	}
}

func TestResolveStageEffectSourceUsesManifestHashWithinComponent(t *testing.T) {
	digest := sha256.Sum256([]byte("payload"))
	payload := DeltaPayload{Target: ContentDescriptor{Name: `component\source.dll`, SHA256: digest}}
	got, err := resolveStageEffectSource(
		"component-file",
		[]string{`component\installed.dll.mun`},
		&digest,
		nil,
		map[[sha256.Size]byte][]DeltaPayload{digest: {payload}},
		nil,
		nil,
		nil,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "payload" || got.Name != payload.Target.Name {
		t.Fatalf("hash-resolved source = %#v", got)
	}
}

func TestResolveStageEffectSourceUsesInstalledFallbackLast(t *testing.T) {
	payload := DeltaPayload{Target: ContentDescriptor{Name: `component\updated.dll`}}
	got, err := resolveStageEffectSource(
		"component-file", []string{payload.Target.Name}, nil,
		map[string]DeltaPayload{normalizeCIXName(payload.Target.Name): payload}, nil, nil, nil, nil,
		`component-old\updated.dll`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "payload" || got.Name != payload.Target.Name {
		t.Fatalf("explicit payload did not precede installed fallback: %#v", got)
	}
	got, err = resolveStageEffectSource("component-file", []string{`component\unchanged.dll`}, nil, nil, nil, nil, nil, nil, `component-old\unchanged.dll`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "installed" || got.Name != `component-old\unchanged.dll` {
		t.Fatalf("installed fallback = %#v", got)
	}
}

func TestResolveStageEffectSourceUsesExactPredecessorDescriptor(t *testing.T) {
	digest := sha256.Sum256([]byte("unchanged"))
	descriptor := ContentDescriptor{Name: `component\unchanged.dll`, Length: 9, SHA256: digest}
	got, err := resolveStageEffectSource(
		"component-file",
		[]string{descriptor.Name},
		nil,
		nil,
		nil,
		map[string]ContentDescriptor{normalizeCIXName(descriptor.Name): descriptor},
		nil,
		nil,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != "predecessor" || got.Descriptor == nil || *got.Descriptor != descriptor {
		t.Fatalf("predecessor source = %#v", got)
	}
}
