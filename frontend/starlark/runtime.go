package starlarkfrontend

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	hexenc "encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"

	ararchive "github.com/tinyrange/trex/archive/ar"
	cabarchive "github.com/tinyrange/trex/archive/cab"
	"github.com/tinyrange/trex/archive/kwaj"
	"github.com/tinyrange/trex/archive/sevenzip"
	"github.com/tinyrange/trex/archive/sfp"
	"github.com/tinyrange/trex/archive/szdd"
	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/archive/xz"
	ziparchive "github.com/tinyrange/trex/archive/zip"
	binaryapi "github.com/tinyrange/trex/binary"
	binarystar "github.com/tinyrange/trex/binary/star"
	debugapi "github.com/tinyrange/trex/debug"
	x86api "github.com/tinyrange/trex/emulator/x86"
	filesystemapi "github.com/tinyrange/trex/filesystem"
	filesystemfat "github.com/tinyrange/trex/filesystem/fat"
	filesystemgpt "github.com/tinyrange/trex/filesystem/gpt"
	filesystemiso9660 "github.com/tinyrange/trex/filesystem/iso9660"
	filesystemmbr "github.com/tinyrange/trex/filesystem/mbr"
	filesystemnative "github.com/tinyrange/trex/filesystem/native"
	filesystemntfs "github.com/tinyrange/trex/filesystem/ntfs"
	filesystemudf "github.com/tinyrange/trex/filesystem/udf"
	filesystemvhdx "github.com/tinyrange/trex/filesystem/vhdx"
	acpistar "github.com/tinyrange/trex/firmware/acpi/star"
	"github.com/tinyrange/trex/installer/installshield"
	"github.com/tinyrange/trex/installer/installshield/installscript"
	imagestar "github.com/tinyrange/trex/media/image/star"
	starcrypto "github.com/tinyrange/trex/script/crypto"
	starjson "github.com/tinyrange/trex/script/json"
	storagenative "github.com/tinyrange/trex/storage/native"
	qemuapi "github.com/tinyrange/trex/vmm/qemu"
	vmmstar "github.com/tinyrange/trex/vmm/star"
	webstar "github.com/tinyrange/trex/web/star"
	windowsapi "github.com/tinyrange/trex/windows"
	"github.com/tinyrange/trex/windows/kd"
	"go.starlark.net/starlark"
)

func predeclared() starlark.StringDict {
	nativeIO := storagenative.Builtins()
	if qemuapi.Available() {
		vmmstar.RegisterBackend("qemu.v1", qemuapi.Capabilities())
	}
	windowsBuiltins := windowsapi.Builtins()
	windowsBuiltins["kd"] = starlark.NewBuiltin("kd", kd.Builtin)
	archiveModule := namespace{
		name: "archive",
		attrs: starlark.StringDict{
			"ar":              starlark.NewBuiltin("ar", ararchive.Builtin),
			"cab":             starlark.NewBuiltin("cab", cabarchive.Builtin),
			"cab_set":         starlark.NewBuiltin("cab_set", cabarchive.SetBuiltin),
			"installer":       starlark.NewBuiltin("installer", installshield.InstallerBuiltin),
			"installer_probe": starlark.NewBuiltin("installer_probe", installshield.ProbeBuiltin),
			"installscript":   starlark.NewBuiltin("installscript", installscript.Builtin),
			"installshield":   starlark.NewBuiltin("installshield", installshield.Builtin),
			"kwaj":            starlark.NewBuiltin("kwaj", kwaj.Builtin),
			"kwaj_info":       starlark.NewBuiltin("kwaj_info", kwaj.InfoBuiltin),
			"sevenzip":        starlark.NewBuiltin("sevenzip", sevenzip.Builtin),
			"sfp":             starlark.NewBuiltin("sfp", sfp.Builtin),
			"szdd":            starlark.NewBuiltin("szdd", szdd.Builtin),
			"tar":             starlark.NewBuiltin("tar", filesystemapi.TarBuiltin),
			"wim":             starlark.NewBuiltin("wim", wim.Builtin),
			"xz":              starlark.NewBuiltin("xz", xz.Builtin),
			"zip":             starlark.NewBuiltin("zip", ziparchive.Builtin),
		},
	}
	filesystemModule := namespace{
		name: "filesystem",
		attrs: starlark.StringDict{
			"fat":     starlark.NewBuiltin("fat", filesystemfat.FATBuiltin),
			"fat12":   starlark.NewBuiltin("fat12", filesystemfat.FAT12Builtin),
			"fat16":   starlark.NewBuiltin("fat16", filesystemfat.FAT16Builtin),
			"fat32":   starlark.NewBuiltin("fat32", filesystemfat.FAT32Builtin),
			"gpt":     starlark.NewBuiltin("gpt", filesystemgpt.GPTBuiltin),
			"host":    starlark.NewBuiltin("host", filesystemnative.HostBuiltin),
			"iso9660": starlark.NewBuiltin("iso9660", filesystemiso9660.ISO9660Builtin),
			"mbr":     starlark.NewBuiltin("mbr", filesystemmbr.MBRBuiltin),
			"ntfs":    starlark.NewBuiltin("ntfs", filesystemntfs.NTFSBuiltin),
			"udf":     starlark.NewBuiltin("udf", filesystemudf.UDFBuiltin),
			"vhdx":    starlark.NewBuiltin("vhdx", filesystemvhdx.VHDXBuiltin),
		},
	}
	return starlark.StringDict{
		"archive": archiveModule,
		"binary":  namespace{name: "binary", attrs: binarystar.Builtins()},
		"block":   blockNamespace(),
		"clock": namespace{
			name: "clock",
			attrs: starlark.StringDict{
				"monotonic": starlark.NewBuiltin("monotonic", clockMonotonicBuiltin),
				"profiler":  starlark.NewBuiltin("profiler", clockProfilerBuiltin),
				"unix":      starlark.NewBuiltin("unix", clockUnixBuiltin),
				"utc":       starlark.NewBuiltin("utc", clockUTCBuiltin),
			},
		},
		"filesystem": filesystemModule,
		"firmware":   namespace{name: "firmware", attrs: acpistar.Builtins()},
		"image":      namespace{name: "image", attrs: imagestar.Builtins()},
		"qemu":       namespace{name: "qemu", attrs: qemuapi.Builtins()},
		"runtime":    runtimeNamespace(),
		"vmm":        namespace{name: "vmm", attrs: vmmstar.Builtins()},
		"crypto":     namespace{name: "crypto", attrs: starcrypto.Builtins()},
		"debug":      namespace{name: "debug", attrs: debugapi.Builtins()},
		"emulator":   namespace{name: "emulator", attrs: x86api.Builtins()},
		"json":       namespace{name: "json", attrs: starjson.Builtins()},
		"html": namespace{
			name: "html",
			attrs: starlark.StringDict{
				"escape":   starlark.NewBuiltin("escape", htmlEscapeBuiltin),
				"unescape": starlark.NewBuiltin("unescape", htmlUnescapeBuiltin),
			},
		},
		"regexp": namespace{
			name: "regexp",
			attrs: starlark.StringDict{
				"compile": starlark.NewBuiltin("compile", regexpCompileBuiltin),
			},
		},
		"url": namespace{
			name: "url",
			attrs: starlark.StringDict{
				"path_escape":   starlark.NewBuiltin("path_escape", urlPathEscapeBuiltin),
				"path_unescape": starlark.NewBuiltin("path_unescape", urlPathUnescapeBuiltin),
			},
		},
		"web": namespace{name: "web", attrs: webstar.Builtins()},
		"path": namespace{
			name: "path",
			attrs: starlark.StringDict{
				"base":         starlark.NewBuiltin("base", filesystemapi.PathBaseBuiltin),
				"clean":        starlark.NewBuiltin("clean", filesystemapi.PathCleanBuiltin),
				"dir":          starlark.NewBuiltin("dir", filesystemapi.PathDirBuiltin),
				"ext":          starlark.NewBuiltin("ext", filesystemapi.PathExtBuiltin),
				"from_windows": starlark.NewBuiltin("from_windows", filesystemapi.PathFromWindowsBuiltin),
				"join":         starlark.NewBuiltin("join", filesystemapi.PathJoinBuiltin),
			},
		},
		"testing": testingNamespace(),
		"windows": namespace{
			name:  "windows",
			attrs: windowsBuiltins,
		},
		"error":        starlark.NewBuiltin("error", errorBuiltin),
		"directory":    starlark.NewBuiltin("directory", filesystemapi.DirectoryBuiltin),
		"bytes_concat": starlark.NewBuiltin("bytes_concat", bytesConcatBuiltin),
		"digest":       starlark.NewBuiltin("digest", digestBuiltin),
		"hex":          starlark.NewBuiltin("hex", hexBuiltin),
		"help":         starlark.NewBuiltin("help", helpBuiltin),
		"open":         nativeIO["open"],
		"repl":         starlark.NewBuiltin("repl", replBuiltin),
		"stdout":       nativeIO["stdout"],
		"write":        nativeIO["write"],
	}
}

func digestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	algorithm := "sha256"
	if err := starlark.UnpackArgs("digest", args, kwargs, "value", &value, "algorithm?", &algorithm); err != nil {
		return nil, err
	}
	var h hash.Hash
	switch strings.ToLower(algorithm) {
	case "md5":
		h = md5.New()
	case "sha1", "sha-1":
		h = sha1.New()
	case "sha256", "sha-256":
		h = sha256.New()
	case "sha512", "sha-512":
		h = sha512.New()
	default:
		return nil, fmt.Errorf("digest: unsupported algorithm %q", algorithm)
	}
	if file, ok := value.(File); ok {
		if _, err := io.Copy(h, io.NewSectionReader(file, 0, file.Size())); err != nil {
			return nil, fmt.Errorf("digest: %w", err)
		}
	} else {
		data, err := binaryapi.BytesForValue(value)
		if err != nil {
			return nil, fmt.Errorf("digest: got %s, want file, string, or bytes", value.Type())
		}
		_, _ = h.Write(data)
	}
	return starlark.Bytes(h.Sum(nil)), nil
}

func clockUnixBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("unix", args, kwargs); err != nil {
		return nil, err
	}
	return starlark.MakeInt64(time.Now().Unix()), nil
}

// clockUTCBuiltin provides calendar facts without embedding a format-specific
// timestamp layout in Go.
func clockUTCBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var timestamp int64
	if err := starlark.UnpackArgs("utc", args, kwargs, "timestamp", &timestamp); err != nil {
		return nil, err
	}
	value := time.Unix(timestamp, 0).UTC()
	fields := []struct {
		name  string
		value int
	}{
		{"year", value.Year()}, {"month", int(value.Month())}, {"weekday", int(value.Weekday())},
		{"day", value.Day()}, {"hour", value.Hour()}, {"minute", value.Minute()},
		{"second", value.Second()}, {"millisecond", value.Nanosecond() / int(time.Millisecond)},
	}
	out := starlark.NewDict(len(fields))
	for _, field := range fields {
		if err := out.SetKey(starlark.String(field.name), starlark.MakeInt(field.value)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func bytesConcatBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var parts *starlark.List
	if err := starlark.UnpackArgs("bytes_concat", args, kwargs, "parts", &parts); err != nil {
		return nil, err
	}
	out := make([]byte, 0)
	for i := 0; i < parts.Len(); i++ {
		part, err := binaryapi.BytesForValue(parts.Index(i))
		if err != nil {
			return nil, fmt.Errorf("bytes_concat: parts[%d]: %w", i, err)
		}
		out = append(out, part...)
	}
	return starlark.Bytes(out), nil
}

func errorBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var msg string
	if err := starlark.UnpackArgs("error", args, kwargs, "message", &msg); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s", msg)
}

func hexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	width := 0
	if err := starlark.UnpackArgs("hex", args, kwargs, "value", &value, "width?", &width); err != nil {
		return nil, err
	}
	if width < 0 {
		return nil, fmt.Errorf("hex: width must be non-negative")
	}
	if i, ok := value.(starlark.Int); ok {
		n := i.BigInt()
		sign := ""
		if n.Sign() < 0 {
			sign = "-"
			n = new(big.Int).Abs(n)
		}
		digits := n.Text(16)
		if width > len(digits) {
			digits = strings.Repeat("0", width-len(digits)) + digits
		}
		return starlark.String(sign + "0x" + digits), nil
	}
	data, err := binaryapi.BytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("hex: got %s, want int, file, string, or bytes", value.Type())
	}
	return starlark.String(hexenc.EncodeToString(data)), nil
}

type namespace struct {
	name  string
	attrs starlark.StringDict
}

func (n namespace) String() string       { return fmt.Sprintf("<module %s>", n.name) }
func (n namespace) Type() string         { return "module" }
func (n namespace) Freeze()              {}
func (n namespace) Truth() starlark.Bool { return starlark.True }
func (n namespace) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", n.Type())
}
func (n namespace) Attr(name string) (starlark.Value, error) {
	return n.attrs[name], nil
}
func (n namespace) AttrNames() []string {
	names := make([]string, 0, len(n.attrs))
	for name := range n.attrs {
		names = append(names, name)
	}
	return names
}
