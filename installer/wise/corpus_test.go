package wise

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/filesystem/iso9660"
	"github.com/tinyrange/trex/storage/native"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func corpusFile(t *testing.T, name string) starfile.File {
	t.Helper()
	image := os.Getenv("TREX_PCWORLD_ISO")
	if image == "" {
		t.Skip("set TREX_PCWORLD_ISO to the August 2000 PCWorld ISO")
	}
	thread := &starlark.Thread{Name: "wise corpus"}
	f, err := starlark.Call(thread, native.Builtins()["open"], starlark.Tuple{starlark.String(image)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	disc, err := iso9660.ISO9660Builtin(thread, nil, starlark.Tuple{f}, nil)
	if err != nil {
		t.Fatal(err)
	}
	find, err := disc.(starlark.HasAttrs).Attr("find")
	if err != nil {
		t.Fatal(err)
	}
	value, err := starlark.Call(thread, find, starlark.Tuple{starlark.String(name)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return value.(starfile.File)
}

func TestPCWorldWiseOverlays(t *testing.T) {
	for _, sample := range []struct {
		name, hash string
		payloads   int
	}{
		{"/essent/getrt420.exe", "6eab854d9eb4f98d9fab578aa62c303b7073efab18c21c7991b39bc3a4755781", 85},
		{"/essent/cute4032.exe", "2bac44f20c9e66da98d8c12970a91ea44847f79c9af2c6b4ee04542b2199c591", 4},
	} {
		t.Run(sample.name, func(t *testing.T) {
			file := corpusFile(t, sample.name)
			hash := sha256.New()
			if _, err := io.Copy(hash, io.NewSectionReader(file, 0, file.Size())); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(hash.Sum(nil)) != sample.hash {
				t.Fatal("unexpected source SHA-256")
			}
			archive, err := Open(file, 256<<20)
			if err != nil {
				t.Fatal(err)
			}
			if len(archive.script.files) != sample.payloads {
				t.Fatalf("payloads=%d want %d", len(archive.script.files), sample.payloads)
			}
			for _, member := range archive.members {
				if _, err := io.Copy(io.Discard, io.NewSectionReader(member.file, 0, member.file.Size())); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := archive.Plan(map[string]string{"<TARGETDIR>": `C:\Program Files\Example`, "<PROGRAMFILES>": `C:\Program Files`, "<WINSYSDIR>": `C:\WINDOWS\SYSTEM`, "<SHELL_OBJECT_FOLDER>": `C:\WINDOWS\Start Menu\Programs`}, nil)
			if err != nil {
				t.Fatal(err)
			}
			unresolved := planValue(t, plan, "unresolved").(*starlark.List)
			if sample.payloads == 4 && unresolved.Len() == 0 {
				t.Fatal("nested temporary-file copies were silently omitted")
			}
			if sample.payloads == 85 && unresolved.Len() != 0 {
				t.Fatalf("fresh GetRight plan has gaps: %s", unresolved)
			}

		})
	}
}

func TestPCWorldCuteFTPNestedCopyPlan(t *testing.T) {
	archive, err := Open(corpusFile(t, "/essent/cute4032.exe"), 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := archive.Lookup("/payload/0003/ftp400c.exe")
	if err != nil {
		t.Fatal(err)
	}
	// Independently established CAB boundary in this exact corpus fixture.
	nested, err := cab.Open(&starfile.Slice{Base: launcher, Offset: 101376, Length: 1206048}, true)
	if err != nil {
		t.Fatal(err)
	}
	local := make(map[string]starfile.File)
	for _, info := range nested.Files() {
		file, err := nested.Lookup(info.Name)
		if err != nil {
			t.Fatal(err)
		}
		local[`C:\WINDOWS\TEMP\`+strings.TrimLeft(info.Name, "/")] = file
	}
	plan, err := archive.PlanWithLocalFiles(nil, nil, local)
	if err != nil {
		t.Fatal(err)
	}
	if gaps := planValue(t, plan, "unresolved").(*starlark.List); gaps.Len() != 0 {
		t.Fatal(gaps)
	}
	files := planValue(t, plan, "files").(*starlark.List)
	if files.Len() != 25 {
		t.Fatalf("installed files=%d want 25", files.Len())
	}
	found := map[string]bool{}
	for index := 0; index < files.Len(); index++ {
		found[strings.ToLower(dictString(t, files.Index(index).(*starlark.Dict), "destination"))] = true
	}
	for _, name := range []string{`c:\globalscape\cuteftp\cutftp32.exe`, `c:\globalscape\cutehtml\cutehtml.exe`, `c:\globalscape\cuteftp\license.rtf`} {
		if !found[name] {
			t.Fatalf("missing %s", name)
		}
	}

	writes := planValue(t, plan, "definitive_registry_writes").(*starlark.List)
	registry := map[string]string{}
	for index := 0; index < writes.Len(); index++ {
		entry := writes.Index(index).(*starlark.Dict)
		if dictString(t, entry, "operation") == "set_value" {
			registry[dictString(t, entry, "name")] = dictString(t, entry, "data")
		}
	}
	for name, want := range map[string]string{"CmdLine": `C:\GlobalSCAPE\CuteFTP\Cutftp32.exe`, "HTMLEditor": `C:\GlobalSCAPE\CuteHTML\CuteHTML.exe`} {
		if registry[name] != want {
			t.Fatalf("%s=%q want %q", name, registry[name], want)
		}
	}
	shortcuts := planValue(t, plan, "shortcuts").(*starlark.List)
	if shortcuts.Len() != 10 {
		t.Fatal(shortcuts)
	}
	for index := 0; index < shortcuts.Len(); index++ {
		entry := shortcuts.Index(index).(*starlark.Dict)
		if strings.Count(strings.ToLower(dictString(t, entry, "destination_folder")), "globalscape") > 1 {
			t.Fatal("later group assignment contaminated an earlier shortcut")
		}
	}
}
