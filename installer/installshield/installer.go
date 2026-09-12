package installshield

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	cabarchive "github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/installer/installshield/installscript"
	wiseinstaller "github.com/tinyrange/trex/installer/wise"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	installerDefaultMaximumScan = int64(256 << 20)
	installerScanWindow         = int64(64 << 10)
	cabinetHeaderSize           = int64(36)
)

// Installer is a parsed self-extracting installer payload. The first
// supported format is a PE launcher containing an embedded Microsoft Cabinet.
// starfile.File access stays within trex: the cabinet is a byte slice of the input
// and is never extracted or materialized on the host.
type Installer struct {
	format    string
	offset    int64
	size      int64
	container starlark.Value
	payload   installerPayload
	packages  []installerPackage
}

type installerPackage struct {
	root       string
	headerPath string
	payload    *Archive
	scriptPath string
	script     starfile.File
}

type installerPayload interface {
	starlark.Value
	starlark.HasAttrs
	Get(starlark.Value) (starlark.Value, bool, error)
}

func (i *Installer) installShieldPackages() []installerPackage {
	if len(i.packages) != 0 {
		return i.packages
	}
	if payload, ok := i.payload.(*Archive); ok {
		return []installerPackage{{root: "/", payload: payload}}
	}
	return nil
}

func InstallerBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumScan := installerDefaultMaximumScan
	cache := true
	if err := starlark.UnpackArgs("installer", args, kwargs,
		"file", &value,
		"maximum_scan?", &maximumScan,
		"cache?", &cache,
	); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("installer: got %s, want file", value.Type())
	}
	if maximumScan < cabinetHeaderSize {
		return nil, fmt.Errorf("installer: maximum_scan must be at least %d", cabinetHeaderSize)
	}
	return OpenInstaller(file, maximumScan, cache, bytecache.New(bytecache.DefaultBytes), 1)
}

// MediaBuiltin plans ordinary disc/diskette InstallShield layouts using the
// same package discovery as self-extracting cabinets. Files stay on the caller's
// portable backend; the mapping is an explicit media namespace, not host paths.
func MediaBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var files *starlark.Dict
	if err := starlark.UnpackArgs("installer_media", args, kwargs, "files", &files); err != nil {
		return nil, err
	}
	copy := starlark.NewDict(files.Len())
	for _, pair := range files.Items() {
		name, ok := starlark.AsString(pair[0])
		file, valid := pair[1].(starfile.File)
		if !ok || !valid {
			return nil, fmt.Errorf("installer_media: files must map relative names to files")
		}
		name = path.Clean("/" + strings.ReplaceAll(name, `\`, "/"))
		if _, found, _ := copy.Get(starlark.String(name)); found {
			return nil, fmt.Errorf("installer_media: duplicate path %s", name)
		}
		_ = copy.SetKey(starlark.String(name), file)
	}
	payload, packages, format, err := installerNestedPayload(copy)
	if err != nil {
		return nil, err
	}
	return &Installer{format: format, container: copy, payload: payload, packages: packages}, nil
}

// ProbeBuiltin applies the same bounded parser as archive.installer,
// but reports unrecognized or malformed inputs as data. This is useful when
// inventorying mixed-media collections: one unknown installer must not abort
// the rest of the scan, and callers can retain the parser error as research
// metadata. Argument and runtime-initialization failures still raise errors;
// format and source-reading failures are part of the probe result.
func ProbeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximumScan := installerDefaultMaximumScan
	cache := true
	if err := starlark.UnpackArgs("installer_probe", args, kwargs,
		"file", &value,
		"maximum_scan?", &maximumScan,
		"cache?", &cache,
	); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("installer_probe: got %s, want file", value.Type())
	}
	if maximumScan < cabinetHeaderSize {
		return nil, fmt.Errorf("installer_probe: maximum_scan must be at least %d", cabinetHeaderSize)
	}
	installer, probeErr := OpenInstaller(file, maximumScan, cache, bytecache.New(bytecache.DefaultBytes), 1)

	result := starlark.NewDict(7)
	fields := starlark.StringDict{
		"supported":       starlark.Bool(probeErr == nil),
		"recognized":      starlark.Bool(probeErr == nil),
		"format":          starlark.String(""),
		"offset":          starlark.MakeInt64(0),
		"size":            starlark.MakeInt64(0),
		"container_files": starlark.MakeInt(0),
		"payload_files":   starlark.MakeInt(0),
		"error":           starlark.String(""),
	}
	if probeErr != nil {
		fields["error"] = starlark.String(probeErr.Error())
		var versionErr *UnsupportedVersionError
		if errors.As(probeErr, &versionErr) {
			fields["recognized"] = starlark.True
			fields["format"] = starlark.String(fmt.Sprintf("installshield%d", versionErr.version))
		}
	} else {
		fields["format"] = starlark.String(installer.format)
		fields["offset"] = starlark.MakeInt64(installer.offset)
		fields["size"] = starlark.MakeInt64(installer.size)
		files, _ := installerContainerFiles(installer.container)
		fields["container_files"] = starlark.MakeInt(len(files))
		if files, attrErr := installer.payload.Attr("files"); attrErr == nil {
			if list, ok := files.(*starlark.List); ok {
				fields["payload_files"] = starlark.MakeInt(list.Len())
			}
		}
	}
	for name, field := range fields {
		if err := result.SetKey(starlark.String(name), field); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func OpenInstaller(file starfile.File, maximumScan int64, cache bool, store *bytecache.Cache, source uint64) (*Installer, error) {
	if file.Size() < cabinetHeaderSize+2 {
		return nil, fmt.Errorf("installer: file is too short")
	}
	magic := make([]byte, 2)
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, 2), magic); err != nil {
		return nil, fmt.Errorf("installer: read executable signature: %w", err)
	}
	if !bytes.Equal(magic, []byte("MZ")) {
		return nil, fmt.Errorf("installer: input is not a DOS or PE executable")
	}
	if offset, ok := peOverlayOffset(file); ok {
		outer, recognized, err := openSFX(file, offset)
		if err != nil {
			return nil, err
		}
		if recognized {
			return &Installer{format: "installshield_sfx", offset: offset, size: outer.size, container: outer, payload: outer}, nil
		}
	}

	scanSize := file.Size()
	if scanSize > maximumScan {
		scanSize = maximumScan
	}
	lastCandidate := int64(-1)
	for windowOffset := int64(0); windowOffset < scanSize; windowOffset += installerScanWindow - 3 {
		windowSize := installerScanWindow
		if remaining := scanSize - windowOffset; windowSize > remaining {
			windowSize = remaining
		}
		window := make([]byte, int(windowSize))
		n, err := file.ReadAt(window, windowOffset)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("installer: scan at offset %d: %w", windowOffset, err)
		}
		window = window[:n]
		for searchOffset := 0; searchOffset < len(window); {
			index := bytes.Index(window[searchOffset:], []byte("MSCF"))
			if index < 0 {
				break
			}
			candidate := windowOffset + int64(searchOffset+index)
			searchOffset += index + 1
			if candidate == lastCandidate {
				continue
			}
			lastCandidate = candidate
			archive, size, err := embeddedCabinetAt(file, candidate, cache, store, source)
			if err != nil {
				continue
			}
			payload, packages, format, err := installerNestedPayload(archive)
			if err != nil {
				return nil, err
			}
			return &Installer{
				format: format, offset: candidate, size: size, container: archive, payload: payload, packages: packages,
			}, nil
		}
		if n == 0 {
			break
		}
	}
	if scanSize < file.Size() {
		if wise, err := wiseinstaller.Open(file, maximumScan); err == nil {
			return &Installer{format: "wise", offset: 0, size: file.Size(), container: wise, payload: wise}, nil
		} else {
			return nil, fmt.Errorf("installer: no supported payload found in the first %d bytes; %v", scanSize, err)
		}
	}
	if wise, err := wiseinstaller.Open(file, maximumScan); err == nil {
		return &Installer{format: "wise", offset: 0, size: file.Size(), container: wise, payload: wise}, nil
	} else {
		return nil, fmt.Errorf("installer: no supported payload found; %v", err)
	}
}

type installerContainerFile struct {
	Name string
	Size int64
}

func installerContainerFiles(container starlark.Value) ([]installerContainerFile, error) {
	switch value := container.(type) {
	case *sfxArchive:
		output := []installerContainerFile{}
		for _, name := range value.names {
			file := value.files[strings.ToLower(name)]
			output = append(output, installerContainerFile{Name: name, Size: file.Size()})
		}
		return output, nil
	case *starlark.Dict:
		output := []installerContainerFile{}
		for _, pair := range value.Items() {
			name, _ := starlark.AsString(pair[0])
			file := pair[1].(starfile.File)
			output = append(output, installerContainerFile{Name: name, Size: file.Size()})
		}
		sort.Slice(output, func(i, j int) bool { return output[i].Name < output[j].Name })
		return output, nil
	case *cabarchive.Archive:
		files := value.Files()
		output := make([]installerContainerFile, len(files))
		for index, file := range files {
			output[index] = installerContainerFile{Name: file.Name, Size: file.Size}
		}
		return output, nil
	case *wiseinstaller.Archive:
		files := value.Files()
		output := make([]installerContainerFile, len(files))
		for index, file := range files {
			output[index] = installerContainerFile{Name: file.Name, Size: file.Size}
		}
		return output, nil
	default:
		return nil, fmt.Errorf("installer: unsupported container %s", container.Type())
	}
}

func installerContainerLookup(container starlark.Value, name string) (starfile.File, error) {
	switch value := container.(type) {
	case *sfxArchive:
		file, found, err := value.Get(starlark.String(name))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("installer: missing SFX file %s", name)
		}
		return file.(starfile.File), nil
	case *starlark.Dict:
		file, found, err := value.Get(starlark.String(name))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("installer: missing media file %s", name)
		}
		return file.(starfile.File), nil
	case *cabarchive.Archive:
		return value.Lookup(name)
	case *wiseinstaller.Archive:
		return value.Lookup(name)
	default:
		return nil, fmt.Errorf("installer: unsupported container %s", container.Type())
	}
}

func installerNestedPayload(container starlark.Value) (installerPayload, []installerPackage, string, error) {
	type memberFile struct {
		name  string
		lower string
		file  starfile.File
	}
	type headerFile struct {
		memberFile
		directory string
		root      string
		inline    bool
		primary   bool
	}
	containerFiles, err := installerContainerFiles(container)
	if err != nil {
		return nil, nil, "", err
	}
	members := make([]memberFile, 0, len(containerFiles))
	headers := make([]headerFile, 0)
	for _, member := range containerFiles {
		value, err := installerContainerLookup(container, member.Name)
		if err != nil {
			return nil, nil, "", err
		}
		name := path.Clean("/" + strings.TrimPrefix(member.Name, "/"))
		entry := memberFile{name: name, lower: strings.ToLower(name), file: value}
		members = append(members, entry)
		base := strings.ToLower(path.Base(name))
		if base == "data1.hdr" {
			directory := strings.ToLower(path.Dir(name))
			root := directory
			if strings.EqualFold(path.Base(directory), "disk1") {
				root = strings.ToLower(path.Dir(directory))
			}
			headers = append(headers, headerFile{memberFile: entry, directory: directory, root: root, primary: true})
		} else if strings.HasSuffix(base, "1.cab") && value.Size() >= 8 {
			common := make([]byte, 8)
			if _, err := io.ReadFull(io.NewSectionReader(value, 0, 8), common); err != nil {
				return nil, nil, "", fmt.Errorf("installer: read nested cabinet header %q: %w", name, err)
			}
			rawVersion := binary.LittleEndian.Uint32(common[4:])
			inlineV5 := base == "data1.cab" && rawVersion>>24 == 1 && (rawVersion>>12)&15 == 5
			if binary.LittleEndian.Uint32(common[:4]) == installShieldSignature && (rawVersion == 0x01000004 || inlineV5) {
				directory := strings.ToLower(path.Dir(name))
				headers = append(headers, headerFile{memberFile: entry, directory: directory, root: directory, inline: true, primary: base == "data1.cab"})
			}
		}
	}
	if len(headers) == 0 {
		if payload, ok := container.(*cabarchive.Archive); ok {
			return payload, nil, "embedded_cab", nil
		}
		return nil, nil, "", fmt.Errorf("installer_media: no supported InstallShield package found")
	}
	sort.Slice(headers, func(i, j int) bool {
		if headers[i].primary != headers[j].primary {
			return headers[i].primary
		}
		if len(headers[i].root) != len(headers[j].root) {
			return len(headers[i].root) < len(headers[j].root)
		}
		return headers[i].lower < headers[j].lower
	})
	owner := func(name string) int {
		best := -1
		for index, header := range headers {
			if name != header.root && !strings.HasPrefix(name, strings.TrimSuffix(header.root, "/")+"/") {
				continue
			}
			if best < 0 || len(header.root) > len(headers[best].root) {
				best = index
			}
		}
		return best
	}
	packages := make([]installerPackage, 0, len(headers))
	for headerIndex, header := range headers {
		magic := make([]byte, 4)
		if _, err := io.ReadFull(io.NewSectionReader(header.file, 0, 4), magic); err != nil {
			return nil, nil, "", fmt.Errorf("installer: read nested InstallShield header %q: %w", header.name, err)
		}
		if binary.LittleEndian.Uint32(magic) != installShieldSignature {
			continue
		}
		volumes := make(map[uint16]starfile.File)
		if header.inline {
			volumes[1] = header.file
		}
		external := make(map[string][]starfile.File)
		var script starfile.File
		scriptPath := ""
		for _, member := range members {
			belongs := owner(member.lower) == headerIndex
			if header.inline {
				belongs = member.lower == header.root || strings.HasPrefix(member.lower, strings.TrimSuffix(header.root, "/")+"/")
			}
			if !belongs {
				continue
			}
			addInstallShieldExternal(external, member.name, member.file)
			base := strings.ToLower(path.Base(member.name))
			if header.primary && (base == "setup.ins" || base == "setup.inx") {
				directory := strings.ToLower(path.Dir(member.name))
				if script == nil || directory == header.directory {
					script, scriptPath = member.file, member.name
				}
			}
			if header.inline {
				continue
			}
			var volume int
			if _, err := fmt.Sscanf(base, "data%d.cab", &volume); err != nil || volume <= 0 || volume > 0xffff {
				continue
			}
			directory := strings.ToLower(path.Dir(member.name))
			expectedDisk := strings.ToLower(path.Join(header.root, fmt.Sprintf("disk%d", volume)))
			if directory != header.directory && directory != header.root && directory != expectedDisk {
				continue
			}
			if previous, ok := volumes[uint16(volume)]; ok && previous.String() != member.file.String() {
				return nil, nil, "", fmt.Errorf("installer: package %q has ambiguous data%d.cab", header.root, volume)
			}
			volumes[uint16(volume)] = member.file
		}
		payload, err := Open(header.file, volumes, external)
		if err != nil {
			return nil, nil, "", fmt.Errorf("installer: nested payload %q: %w", header.name, err)
		}
		packages = append(packages, installerPackage{root: header.root, headerPath: header.name, payload: payload, scriptPath: scriptPath, script: script})
	}
	if len(packages) == 0 {
		if payload, ok := container.(*cabarchive.Archive); ok {
			return payload, nil, "embedded_cab", nil
		}
		return nil, nil, "", fmt.Errorf("installer_media: no supported InstallShield package found")
	}
	return packages[0].payload, packages, fmt.Sprintf("installshield%d", packages[0].payload.version), nil
}

func embeddedCabinetAt(file starfile.File, offset int64, cache bool, store *bytecache.Cache, source uint64) (*cabarchive.Archive, int64, error) {
	if offset < 0 || offset > file.Size() || cabinetHeaderSize > file.Size()-offset {
		return nil, 0, fmt.Errorf("cabinet header at offset %d is truncated", offset)
	}
	header := make([]byte, cabinetHeaderSize)
	if _, err := io.ReadFull(io.NewSectionReader(file, offset, cabinetHeaderSize), header); err != nil {
		return nil, 0, err
	}
	if string(header[:4]) != "MSCF" {
		return nil, 0, fmt.Errorf("invalid cabinet signature")
	}
	size := int64(binary.LittleEndian.Uint32(header[8:12]))
	fileTable := int64(binary.LittleEndian.Uint32(header[16:20]))
	folders := binary.LittleEndian.Uint16(header[26:28])
	files := binary.LittleEndian.Uint16(header[28:30])
	if size < cabinetHeaderSize || size > file.Size()-offset {
		return nil, 0, fmt.Errorf("invalid cabinet size %d", size)
	}
	if fileTable < cabinetHeaderSize || fileTable >= size || folders == 0 || files == 0 {
		return nil, 0, fmt.Errorf("invalid cabinet directory")
	}
	payload := &starfile.Slice{Name: fmt.Sprintf("%s[%d:%d]", file.String(), offset, offset+size), Base: file, Offset: offset, Length: size}
	archive, err := cabarchive.OpenWithCache(payload, cache, store, source)
	if err != nil {
		return nil, 0, err
	}
	return archive, size, nil
}

func (i *Installer) String() string {
	return fmt.Sprintf("<installer format=%s offset=%d size=%d>", i.format, i.offset, i.size)
}
func (i *Installer) Type() string         { return "installer" }
func (i *Installer) Freeze()              {}
func (i *Installer) Truth() starlark.Bool { return starlark.True }
func (i *Installer) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", i.Type())
}
func (i *Installer) Get(key starlark.Value) (starlark.Value, bool, error) {
	return i.payload.Get(key)
}
func (i *Installer) AttrNames() []string {
	return []string{"container", "files", "find", "format", "installscript", "offset", "packages", "payload", "plan", "size"}
}
func (i *Installer) Attr(name string) (starlark.Value, error) {
	switch name {
	case "format":
		return starlark.String(i.format), nil
	case "offset":
		return starlark.MakeInt64(i.offset), nil
	case "size":
		return starlark.MakeInt64(i.size), nil
	case "payload":
		return i.payload, nil
	case "container":
		return i.container, nil
	case "packages":
		values := make([]starlark.Value, len(i.packages))
		for index, pkg := range i.packages {
			script := starlark.Value(starlark.None)
			if pkg.script != nil {
				script = pkg.script
			}
			values[index] = starlarkStringDict(map[string]starlark.Value{
				"format":      starlark.String(fmt.Sprintf("installshield%d", pkg.payload.version)),
				"header_path": starlark.String(pkg.headerPath),
				"payload":     pkg.payload,
				"root":        starlark.String(pkg.root),
				"script":      script,
				"script_path": starlark.String(pkg.scriptPath),
			})
		}
		return starlark.NewList(values), nil
	case "installscript":
		script, err := i.installScript()
		if err != nil {
			return nil, err
		}
		if script == nil {
			return starlark.None, nil
		}
		return script, nil
	case "plan":
		return starlark.NewBuiltin("installer.plan", i.planBuiltin), nil
	case "files":
		return i.payload.Attr("files")
	case "find":
		return starlark.NewBuiltin("installer.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("installer.find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			value, found, err := i.payload.Get(starlark.String(path.Clean("/" + strings.TrimPrefix(name, "/"))))
			if err != nil || !found {
				return starlark.None, nil
			}
			return value, nil
		}), nil
	default:
		return nil, nil
	}
}

func (i *Installer) installScript() (*installscript.Script, error) {
	if len(i.packages) != 0 && i.packages[0].script != nil {
		extension := strings.ToLower(path.Ext(i.packages[0].scriptPath))
		if extension == ".inx" || extension == ".ins" {
			return installscript.Open(i.packages[0].script)
		}
		return nil, nil
	}
	members, err := installerContainerFiles(i.container)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		base := path.Base(member.Name)
		if !strings.EqualFold(base, "setup.inx") && !strings.EqualFold(base, "setup.ins") {
			continue
		}
		value, err := installerContainerLookup(i.container, member.Name)
		if err != nil {
			return nil, fmt.Errorf("installer: %s: %w", base, err)
		}
		return installscript.Open(value)
	}
	return nil, nil
}
