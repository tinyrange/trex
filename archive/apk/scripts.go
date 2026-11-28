package apk

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const scriptDatabaseLimit = 32 << 20

var installedScriptPhases = map[string]bool{
	".pre-install": true, ".post-install": true,
	".pre-upgrade": true, ".post-upgrade": true,
	".pre-deinstall": true, ".post-deinstall": true,
	".trigger": true,
}

type scriptRegistration struct {
	name, version, checksum string
	scripts                 map[string]storage.Reader
	triggers                []string
}

func buildScriptDatabase(base storage.Reader, baseTriggers string, additions []scriptRegistration) ([]byte, string, error) {
	if base == nil || base.Size() > scriptDatabaseLimit || len(baseTriggers) > scriptDatabaseLimit {
		return nil, "", fmt.Errorf("apk: invalid base script database size")
	}
	var scripts bytes.Buffer
	var triggers strings.Builder
	triggers.WriteString(baseTriggers)
	if baseTriggers != "" && !strings.HasSuffix(baseTriggers, "\n") {
		triggers.WriteByte('\n')
	}
	seen := make(map[string]bool)
	writer := tar.NewWriter(&scripts)
	reader := tar.NewReader(io.NewSectionReader(base, 0, base.Size()))
	putScript := func(header *tar.Header, source io.Reader) error {
		if seen[header.Name] || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > int64(scriptDatabaseLimit-scripts.Len()) {
			return fmt.Errorf("apk: invalid installed script %q", header.Name)
		}
		seen[header.Name] = true
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		_, err := io.CopyN(writer, source, header.Size)
		return err
	}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if err := putScript(header, reader); err != nil {
			return nil, "", err
		}
	}
	for _, pkg := range additions {
		check, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pkg.checksum, "Q1"))
		if !ValidIdentity(pkg.name) || !ValidIdentity(pkg.version) || !strings.HasPrefix(pkg.checksum, "Q1") || err != nil || len(check) != 20 {
			return nil, "", fmt.Errorf("apk: invalid script package identity %q", pkg.name)
		}
		names := make([]string, 0, len(pkg.scripts))
		for name := range pkg.scripts {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, phase := range names {
			source := pkg.scripts[phase]
			if !installedScriptPhases[phase] || source == nil {
				return nil, "", fmt.Errorf("apk: invalid script phase %q", phase)
			}
			archiveName := pkg.name + "-" + pkg.version + "." + pkg.checksum + phase
			header := &tar.Header{Name: archiveName, Mode: 0755, Typeflag: tar.TypeReg, Size: source.Size()}
			if err := putScript(header, io.NewSectionReader(source, 0, source.Size())); err != nil {
				return nil, "", err
			}
		}
		if len(pkg.triggers) > 0 {
			if pkg.scripts[".trigger"] == nil {
				return nil, "", fmt.Errorf("apk: trigger paths without script for %s", pkg.name)
			}
			for _, trigger := range pkg.triggers {
				if !strings.HasPrefix(trigger, "/") || strings.ContainsAny(trigger, "\x00 \t\r\n") {
					return nil, "", fmt.Errorf("apk: invalid trigger pattern %q", trigger)
				}
			}
			fmt.Fprintln(&triggers, pkg.checksum, strings.Join(pkg.triggers, " "))
			if triggers.Len() > scriptDatabaseLimit {
				return nil, "", fmt.Errorf("apk: trigger database exceeds limit")
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return scripts.Bytes(), triggers.String(), nil
}

func ScriptDatabaseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var base starlark.Value
	var baseTriggers string
	var packages *starlark.List
	if err := starlark.UnpackArgs("apk_script_database", args, kwargs, "scripts", &base, "triggers", &baseTriggers, "packages", &packages); err != nil {
		return nil, err
	}
	archive, ok := base.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("apk: scripts must be a file")
	}
	additions := make([]scriptRegistration, 0, packages.Len())
	for value := range starlark.Elements(packages) {
		row, ok := value.(starlark.Tuple)
		if !ok || len(row) != 5 {
			return nil, fmt.Errorf("apk: expected (name, version, checksum, effects, triggers)")
		}
		name, nameOK := starlark.AsString(row[0])
		version, versionOK := starlark.AsString(row[1])
		checksum, checksumOK := starlark.AsString(row[2])
		effects, effectsOK := row[3].(*starlark.Dict)
		triggerList, triggersOK := row[4].(*starlark.List)
		if !nameOK || !versionOK || !checksumOK || !effectsOK || !triggersOK {
			return nil, fmt.Errorf("apk: invalid script registration")
		}
		entry := scriptRegistration{name: name, version: version, checksum: checksum, scripts: make(map[string]storage.Reader)}
		for _, effect := range effects.Items() {
			phase, phaseOK := starlark.AsString(effect[0])
			source, sourceOK := effect[1].(storage.Reader)
			if !phaseOK || !sourceOK {
				return nil, fmt.Errorf("apk: expected a phase and script file")
			}
			entry.scripts[phase] = source
		}
		for trigger := range starlark.Elements(triggerList) {
			name, ok := starlark.AsString(trigger)
			if !ok {
				return nil, fmt.Errorf("apk: expected a trigger pattern")
			}
			entry.triggers = append(entry.triggers, name)
		}
		additions = append(additions, entry)
	}
	scripts, triggers, err := buildScriptDatabase(archive, baseTriggers, additions)
	if err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{
		"scripts":  &starfile.Bytes{Name: "scripts.tar", Data: scripts},
		"triggers": starlark.String(triggers),
	}), nil
}
