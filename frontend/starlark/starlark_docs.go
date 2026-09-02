package starlarkfrontend

import (
	"bytes"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// standardLibraryDocumentation validates and renders the embedded Starlark API
// reference without creating extracted source or intermediate files.
func standardLibraryDocumentation() ([]byte, error) {
	var modules []string
	err := fs.WalkDir(standardLibrary, "stdlib", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(name, ".star") {
			modules = append(modules, strings.TrimPrefix(name, "stdlib/"))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(modules)

	thread, _, err := newStarlarkRuntime("-")
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.WriteString("# trex Starlark Standard Library\n\n")
	for _, modulePath := range modules {
		sourcePath := "stdlib/" + modulePath
		source, err := fs.ReadFile(standardLibrary, sourcePath)
		if err != nil {
			return nil, err
		}
		file, err := syntax.Parse(sourcePath, source, 0)
		if err != nil {
			return nil, err
		}
		if len(file.Stmts) == 0 {
			return nil, fmt.Errorf("%s: missing module docstring", modulePath)
		}
		doc, ok := starlarkModuleDocstring(file.Stmts[0])
		if !ok {
			return nil, fmt.Errorf("%s: missing module docstring", modulePath)
		}
		globals, err := thread.Load(thread, stdlibLabelForPath(modulePath))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&output, "## `%s`\n\n%s\n\n", modulePath, strings.TrimSpace(doc))
		var names []string
		for name, value := range globals {
			if _, ok := value.(*starlark.Function); ok && !strings.HasPrefix(name, "_") && !strings.HasPrefix(name, "test_") && !strings.HasPrefix(name, "fixture_") {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			function := globals[name].(*starlark.Function)
			doc := strings.TrimSpace(function.Doc())
			if doc == "" {
				return nil, fmt.Errorf("%s: public function %s has no docstring", modulePath, name)
			}
			fmt.Fprintf(&output, "### `%s`\n\n%s\n\n", name, doc)
		}
	}
	writeNativeStarlarkDocumentation(&output)
	return append(bytes.TrimRight(output.Bytes(), "\n"), '\n'), nil
}

var nativeStarlarkTypes = map[string][]string{
	"ar":                    {"entries", "files", "find(name, occurrence=0)"},
	"ar_entry":              {"binary", "bytes", "gid", "hex", "mode", "mtime", "name", "read", "size", "slice", "uid"},
	"block_device":          {"capabilities", "commit()", "extents(offset, length)", "flush()", "geometry", "read(offset, size)", "size", "snapshot()", "stats", "trim(offset, length)", "write(offset, value)", "zero(offset, length)"},
	"binary.builder":        {"align(alignment, fill=0)", "append(value)", "bytes()", "file()", "patch(offset, value)", "reserve(size, fill=0)", "size"},
	"binary.cursor":         {"align(alignment)", "bytes(size)", "offset", "remaining", "seek(offset)", "skip(size)"},
	"binary.layout":         {"decode(source, offset=0)", "encode(values)", "size"},
	"binary.xml_document":   {"bytes(maximum=16MiB)", "root", "with_root(root)"},
	"binary.xml_node":       {"attribute(name, default=None, namespace='')", "attributes", "bytes(maximum=16MiB)", "child(name, namespace='')", "children", "children_named(name, namespace='')", "direct_text", "name", "namespace", "prefix", "qualified_name", "text", "with_children(children)", "with_text(text)"},
	"byte_view":             {"bytes(offset=0, size=remaining)", "compare(other, signed=False, exact=False)", "find(needle, start=0, end=size)", "find_all(needle, start=0, end=size, limit=1M)", "find_indices(needles, start=0, end=size)", "size", "slice(offset=0, size=remaining)"},
	"byte_channel":          {"close()", "name", "read(size, maximum=8MiB)", "read_some(maximum=64KiB, timeout=30)", "write(value)"},
	"clock.profiler":        {"counter(name, amount=1)", "measure(name, function, *args, **kwargs)", "report(minimum_coverage=0.95)", "snapshot()", "span(name)"},
	"clock.span":            {"end() -> elapsed seconds"},
	"directory":             {"fat_short_path(name)", "files", "find(path)", "mkdir(name)", "remove(name)", "set_attributes(name, readonly=False, hidden=False, system=False, archive=False)", "set_security(name, descriptor)", "write(name, value)"},
	"emulator.execution":    {"close()", "closed", "done", "run(instruction_limit=0)"},
	"emulator.x86":          {"accelerate_loop(address, pattern=None, size=0, digest=None, normalize_relative=False, maximum_instructions=1Mi)", "accelerate_region(entry, start, size, digest, reenter=False, maximum_instructions=1Mi)", "accelerate_runtime_region(anchor, size, digest, entry_offset=0, anchor_mask=None, name='runtime executable region', normalize_relative=True, reenter=False, maximum_instructions=1Mi)", "allocate(size=0, value=None, address=None, alignment=16, name='plugin', readable=True, writable=True, executable=False)", "call(address, args=[], registers={})", "call_export(name, args=[], registers={})", "call_trace(reset=False)", "checkpoint()", "code_trace(watch, reset=False)", "configure_call_trace(enabled=True, limit=unchanged, start=0, size=0, reset=True)", "configure_trace(enabled=True, limit=unchanged, reset=True)", "entry", "free(address)", "get_register(name)", "hook(...) and use(plugins)", "imports", "invoke(address, args=[], registers={})", "load_module(image, name)", "mappings", "memory_writes(watch, reset=False)", "modules", "profile(limit=256, reset=False)", "protect(address, size, readable=True, writable=False, executable=False)", "provide_export(callback=None, module, name|ordinal, argc=0, convention='stdcall', value=None, writable=True)", "read_cbytes(address, maximum=32KiB, require_terminator=True, unit_width=1)", "restore(checkpoint)", "rewrite(address, pattern=None, size=0, digest=None, callback, name='inline rewrite', normalize_relative=False)", "run()", "set_register(name, value)", "snapshot()", "spawn(address, args=[], registers={})", "stack", "stop(reason, detail='')", "transfer(address, esp=None, ebp=None, return_address=None)", "transform(anchor, size, digest, callback, anchor_mask=None, name='runtime transformation', normalize_relative=True)", "u32_multiply_accumulate(destination, source, count, scalar, carry=0, subtract=False)", "watch_code(address, size, limit=4096, stack_bytes=0, captures={})", "watch_memory(address, size, limit=4096)"},
	"gdb":                   {"address_space(page_table, kind='user')", "architecture", "breakpoint(address, kind='hardware', size=1, timeout=30)", "close()", "continue(timeout=30)", "current_thread(timeout=30)", "features", "generation", "interrupt(timeout=30)", "monitor(command, timeout=30)", "packet(payload, timeout=30)", "read_memory(address, size, timeout=30)", "read_register(name, timeout=30)", "registers(timeout=30)", "running", "search_memory(address, size, pattern, limit=256, timeout=30)", "select_thread(thread, general=True, execution=True, timeout=30)", "step(timeout=30)", "threads(timeout=30)", "wait(timeout=30)", "watchpoint(address, size, access='write', timeout=30)", "with_register(name, value, callback)", "with_state(registers, memory, callback, timeout=30)", "write_memory(address, data, timeout=30)", "write_register(name, value, timeout=30)"},
	"gdb_address_space":     {"generation", "kind", "page_table", "read_memory(address, size, timeout=30)"},
	"gdb_point":             {"address", "kind", "remove(timeout=30)", "removed", "size", "with_disabled(callback, timeout=30)"},
	"installer":             {"container", "files", "find(path)", "format", "installscript", "offset", "payload", "plan(locations={}, variables={}, components=None)", "size"},
	"installscript":         {"blocks", "callbacks", "calls", "effects", "evaluate(entry='application', strings={}, numbers={}, profiles={}, maximum_steps=200000, maximum_depth=64)", "find_function(name)", "functions", "strings"},
	"installshield":         {"components", "entries", "files", "find(path)", "groups", "shortcuts", "version"},
	"nbd_server":            {"close()", "export_name", "serve(channel)", "stats"},
	"qemu_acpi_table":       {"file", "name", "properties"},
	"qemu_chardev":          {"name", "properties"},
	"qemu_device":           {"name", "properties"},
	"qemu_netdev":           {"name", "properties"},
	"qemu_option":           {"name", "properties"},
	"qemu.v1":               {"block_stats()", "capabilities", "hmp(command, timeout=30)", "process", "qmp(command, arguments={}, timeout=30)", "qmp_schema(timeout=30)"},
	"sfp":                   {"archive_size", "data_offset", "entries", "files", "find(path)", "package_label", "version"},
	"sfp_entry":             {"binary", "bytes", "created_time", "entry_type", "file_length", "flags", "hex", "modified_time", "name", "parent", "path", "payload_offset", "read", "record_offset", "size", "slice", "stored_size"},
	"tar":                   {"entries", "files", "find(path, occurrence=0)"},
	"tar_entry":             {"binary", "bytes", "entry_type", "gid", "gname", "hex", "link", "mode", "mtime", "name", "path", "read", "size", "slice", "stored_size", "uid", "uname"},
	"vm":                    {"backend_id", "capabilities", "channel(name, timeout=30)", "chord(keys)", "debugger(protocol, create=False, paused=False, timeout=30)", "detach()", "extension(name)", "has_capability(name)", "key(key, down=True)", "next_event(timeout=-1)", "pause(timeout=30)", "pointer(x=0, y=0, absolute=False, buttons=[], wheel=0)", "powerdown(timeout=30)", "reset(timeout=30)", "result", "resume(timeout=30)", "running", "screenshot(format='png', timeout=30)", "send_keys(keys)", "send_text(text)", "shutdown(timeout=30, force=True, force_timeout=10)", "status", "stop(timeout=30)", "tap(key)", "type_and_enter(text, enter='enter')", "wait(timeout=-1)"},
	"vmm_backend":           {"accelerator", "block_transport", "capabilities", "id", "machine"},
	"vmm_channel":           {"kind", "name", "required"},
	"vmm_disk":              {"bus", "chs", "device", "media", "name", "read_only", "required", "snapshot", "unit"},
	"vmm_display":           {"mode", "required"},
	"vmm_machine":           {"architecture", "channels", "cpus", "disks", "display", "memory", "networks", "required_capabilities", "start_paused"},
	"vmm_network":           {"kind", "name", "required"},
	"windows.kd":            {"breakin()", "breakpoint(address, timeout=30)", "close()", "context(timeout=30)", "continue(status=0x10002, timeout=30)", "file_io(handler=None)", "next_event(timeout=-1)", "packet(kind, payload, packet_id=None, timeout=30)", "read_physical(address, size, timeout=30)", "read_virtual(address, size, timeout=30)", "request(api, processor=-1, arguments={}, data=b'', timeout=30)", "set_context(raw, edi=None, esi=None, ebx=None, edx=None, ecx=None, eax=None, ebp=None, eip=None, eflags=None, esp=None, timeout=30)", "write_physical(address, data, timeout=30)", "write_virtual(address, data, timeout=30)"},
	"windows.kd_breakpoint": {"address", "handle", "remove(timeout=30)", "removed"},
	"windows.pe":            {"codeview", "data", "disasm(rva, size=256)", "exports", "imports", "info", "messages", "patch(rva, data, update_checksum=True)", "pointer_string_tables(suffix='', minimum=2, maximum=260)", "read(rva, size)", "resources", "sections", "typelibs", "version"},
	"windows.pdb":           {"age", "guid", "nearest(rva)", "signature", "symbols"},
	"windows.pdb_symbol":    {"kind", "name", "rva"},
}

var nativeStarlarkSignatures = map[string]string{
	"bytes_concat":                      "bytes_concat(parts) -> bytes",
	"digest":                            "digest(value, algorithm='sha256') -> bytes",
	"directory":                         "directory() -> directory",
	"error":                             "error(message)",
	"help":                              "help(value=None) -> None",
	"json.decode":                       "json.decode(value, maximum=64MiB) -> value",
	"hex":                               "hex(value, width=0) -> string",
	"mirror_file":                       "mirror_file(urls, cache, key, sha256='', size=-1, maximum=64GiB, timeout=3600) -> file",
	"open":                              "open(name) -> file",
	"repl":                              "repl() -> None",
	"stdout":                            "stdout(value) -> None",
	"write":                             "write(name, value, max_bytes=64GiB) -> None",
	"archive.kwaj":                      "archive.kwaj(file, maximum=512MiB) -> file",
	"archive.kwaj_info":                 "archive.kwaj_info(file, maximum=512MiB) -> record(file, name, method, decoded_size, compressed_size)",
	"archive.cab_set":                   "archive.cab_set(files, cache=True) -> cab",
	"archive.installer":                 "archive.installer(file, maximum_scan=256MiB, cache=True) -> installer",
	"archive.installer_probe":           "archive.installer_probe(file, maximum_scan=256MiB, cache=True) -> dict",
	"archive.installscript":             "archive.installscript(file) -> installscript",
	"archive.installshield":             "archive.installshield(header, cabinets, external={}) -> installshield",
	"block.cache":                       "block.cache(base, max_bytes=32MiB, chunk_size=64KiB)",
	"block.device":                      "block.device(file, format='raw', logical_block_size=512, physical_block_size=logical, writable=False)",
	"block.nbd":                         "block.nbd(device, export_name='', max_request=8MiB, structured=True, handshake_timeout=10, request_timeout=30, workers=4)",
	"block.overlay":                     "block.overlay(base, max_dirty_bytes=128MiB, chunk_size=64KiB, trace_operations=0)",
	"block.view":                        "block.view(device) -> live read-only file view",
	"archive.ar":                        "archive.ar(file, maximum_entries=1M, maximum_metadata=64MiB) -> ar",
	"archive.sevenzip":                  "archive.sevenzip(file, maximum_entries=1M, maximum_metadata=64MiB, max_dictionary=256MiB) -> sevenzip",
	"archive.szdd":                      "archive.szdd(file, maximum=512MiB) -> file",
	"archive.sfp":                       "archive.sfp(file, maximum_entries=1M, maximum_metadata=64MiB) -> sfp",
	"archive.tar":                       "archive.tar(directory, compress='') -> bytes; archive.tar(file, maximum_entries=1M) -> tar",
	"archive.xz":                        "archive.xz(file, max_dictionary=64MiB) -> file",
	"clock.monotonic":                   "clock.monotonic() -> elapsed seconds",
	"clock.profiler":                    "clock.profiler() -> clock.profiler",
	"binary.base64":                     "binary.base64(value, url=False, padding=True, maximum=512MiB)",
	"binary.hex":                        "binary.hex(value, maximum=512MiB)",
	"binary.xml":                        "binary.xml(value, maximum=16MiB, max_depth=256, max_nodes=1M)",
	"database.ese":                      "database.ese(file) -> ESE database",
	"database.ese_build":                "database.ese_build(tables, database_pages=0, sort_data=None) -> file",
	"debug.disassemble":                 "debug.disassemble(data, address=0, architecture='i386', maximum=64MiB, count=-1); architectures: i8086/x86-16, i386/x86, amd64/x86_64",
	"debug.gdb":                         "debug.gdb(channel, memory_limit=64MiB, stop_queue=256, timeout=15)",
	"debug.select":                      "debug.select(values, timeout=-1)",
	"emulator.x86":                      "emulator.x86(image|code, base=0x1000, entry=None, instruction_limit=2M, memory_limit=32MiB, stack_size=1MiB, call_depth_limit=1024, trace=False, trace_limit=4096, profile=False, profile_interval=256, profile_limit=16384, image_name='main', fs_base=0, segment_size=4096)",
	"firmware.acpi_compatible_id":       "firmware.acpi_compatible_id(device, compatible_id)",
	"firmware.acpi_table":               "firmware.acpi_table(signature, body, revision=2, oem_id='TREXOS', oem_table_id='TREXACPI', oem_revision=1, creator_id='TREX', creator_revision=1)",
	"filesystem.mbr":                    "filesystem.mbr(file) -> parsed MBR; filesystem.mbr(size, boot_code=None, disk_signature=0, chs=None) -> builder",
	"filesystem.fat16":                  "filesystem.fat16(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', file_order=[], directory_label=True, extended_bpb=True, chs=None) -> file",
	"filesystem.fat12":                  "filesystem.fat12(directory, size, boot_code=None, hidden_sectors=0, label='NO NAME', file_order=[], directory_label=True, extended_bpb=False, chs=None) -> file",
	"filesystem.gpt":                    "filesystem.gpt(file) -> parsed GPT; filesystem.gpt(size, disk_guid=...) -> builder",
	"filesystem.ntfs":                   "filesystem.ntfs(source, size=None, boot_code=None, hidden_sectors=0, label='NO NAME', version='1.1', log_file=None, upcase=None, upcase_profile='default')",
	"image.compare":                     "image.compare(left, right, threshold=8, maximum=128MiB, max_pixels=16MiP) -> record",
	"image.info":                        "image.info(source, maximum=128MiB, max_pixels=16MiP) -> record",
	"image.pixel":                       "image.pixel(source, x, y, maximum=128MiB, max_pixels=16MiP) -> record",
	"path.base":                         "path.base(path) -> string",
	"path.clean":                        "path.clean(path) -> logical absolute path",
	"path.dir":                          "path.dir(path) -> logical directory path",
	"path.ext":                          "path.ext(path) -> extension",
	"runtime.stats":                     "runtime.stats() -> record",
	"windows.csp_registrations":         "windows.csp_registrations(file, strict=True)",
	"windows.creg_from_patches":         "windows.creg_from_patches(name, patches, keys=[], state=1, generation='windows95') -> file",
	"windows.creg_compare":              "windows.creg_compare(left, right) -> structural difference report",
	"windows.creg_keys":                 "windows.creg_keys(file) -> list[list[string]]",
	"windows.creg_patches":              "windows.creg_patches(file) -> list[dict]",
	"windows.icon":                      "windows.icon(file, index=0, width=32, height=32)",
	"windows.ne_fastboot":               "windows.ne_fastboot(modules, overlay_path='C:\\\\WINDOWS\\\\WIN100.OVL', maximum=64MiB) -> {bin, overlay}",
	"windows.setver":                    "windows.setver(source, name, major, minor, maximum=16MiB) -> file",
	"windows.win9x_vxd_unpack":          "windows.win9x_vxd_unpack(file) -> file",
	"windows.win9x_vxd_library":         "windows.win9x_vxd_library(base, members, exclude=[]) -> file",
	"windows.win9x_vxd_library_members": "windows.win9x_vxd_library_members(file) -> list[string]",
	"qemu.acpi_table":                   "qemu.acpi_table(file)",
	"qemu.backend":                      "qemu.backend(binary='', machine='pc', accelerator='auto', display_frontend='auto', block_transport='auto', overlay_limit=256MiB, stderr_limit=1MiB, devices=[], netdevs=[], chardevs=[], options=[], acpi_tables=[])",
	"qemu.chardev":                      "qemu.chardev(name, **properties)",
	"qemu.device":                       "qemu.device(name, **properties)",
	"qemu.extension":                    "qemu.extension(vm)",
	"qemu.netdev":                       "qemu.netdev(name, **properties)",
	"qemu.option":                       "qemu.option(name, value=None); -d accepts a list of debug event names",
	"vmm.backends":                      "vmm.backends()",
	"vmm.channel":                       "vmm.channel(kind, name, required=True)",
	"vmm.disk":                          "vmm.disk(source, name='disk0', bus='auto', media='disk', unit=-1, chs=None, read_only=None, snapshot=False, required=True)",
	"vmm.display":                       "vmm.display(mode, required=True)",
	"vmm.machine":                       "vmm.machine(architecture, memory, cpus=1, disks=[], networks=[], display=vmm.display('none'), channels=[], start_paused=False, required_capabilities=[])",
	"vmm.network":                       "vmm.network(kind, name='net0', required=True)",
	"vmm.start":                         "vmm.start(machine, backend)",
	"vmm.validate":                      "vmm.validate(machine, backend)",
	"windows.kd":                        "windows.kd(channel, architecture='i386', packet_limit=65535, memory_limit=64MiB, event_queue=512)",
	"windows.catalog_hash":              "windows.catalog_hash(file, algorithm='sha1')",
	"windows.catalog_members":           "windows.catalog_members(value)",
	"windows.pdb":                       "windows.pdb(file, stream_limit=256MiB)",
	"windows.symbol_server":             "windows.symbol_server(base_url, name, key, guid=None, age=None, maximum=256MiB, timeout=45)",
	"windows.wmi_repository":            "windows.wmi_repository(files=None, documents=None, default_namespace='root\\cimv2', server_name='')",
}

// writeNativeStarlarkDocumentation reflects native namespace builtins so new
// entry points cannot silently disappear from the generated API reference.
// Opaque value methods are listed explicitly because they are capability-
// dependent and cannot all be instantiated while generating documentation.
func writeNativeStarlarkDocumentation(output *bytes.Buffer) {
	output.WriteString("## Native namespaces and values\n\n")
	environment := predeclared()
	var topLevel []string
	for name, value := range environment {
		if _, ok := value.(*starlark.Builtin); ok {
			topLevel = append(topLevel, name)
		}
	}
	sort.Strings(topLevel)
	for _, name := range topLevel {
		fmt.Fprintf(output, "### `%s`\n\n`%s`\n\nNative top-level operation.\n\n", name, nativeStarlarkSignature(name))
	}
	var namespaces []string
	for name, value := range environment {
		if _, ok := value.(namespace); ok {
			namespaces = append(namespaces, name)
		}
	}
	sort.Strings(namespaces)
	for _, name := range namespaces {
		module := environment[name].(namespace)
		var builtins []string
		for attr, value := range module.attrs {
			if _, ok := value.(*starlark.Builtin); ok {
				builtins = append(builtins, attr)
			}
		}
		sort.Strings(builtins)
		for _, builtin := range builtins {
			qualified := name + "." + builtin
			signature := nativeStarlarkSignature(qualified)
			fmt.Fprintf(output, "### `%s`\n\n`%s`\n\nNative `%s` operation. Limits and timeout arguments are validated before work begins.\n\n", qualified, signature, name)
		}
	}
	var types []string
	for name := range nativeStarlarkTypes {
		types = append(types, name)
	}
	sort.Strings(types)
	for _, name := range types {
		methods := append([]string(nil), nativeStarlarkTypes[name]...)
		if name == "binary.cursor" {
			for _, codec := range binaryapi.ScalarCodecs {
				methods = append(methods, codec.Name+"()")
			}
		}
		if name == "binary.builder" {
			for _, codec := range binaryapi.ScalarCodecs {
				methods = append(methods, codec.Name+"(value)", "patch_"+codec.Name+"(offset, value)")
			}
		}
		if name == "emulator.x86" {
			for _, codec := range binaryapi.ScalarCodecs {
				methods = append(methods, "read_"+codec.Name+"(address)", "write_"+codec.Name+"(address, value)")
			}
		}
		sort.Strings(methods)
		fmt.Fprintf(output, "### `%s` value\n\nMethods and attributes: `%s`.\n\n", name, strings.Join(methods, "`, `"))
	}
}

func nativeStarlarkSignature(qualified string) string {
	if signature := nativeStarlarkSignatures[qualified]; signature != "" {
		return signature
	}
	if strings.HasPrefix(qualified, "binary.read_") {
		if codec, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "binary.read_")); ok {
			result := "int"
			if codec.Float {
				result = "float"
			}
			return qualified + "(source, offset=0) -> " + result
		}
	}
	if strings.HasPrefix(qualified, "binary.") {
		if _, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "binary.")); ok {
			return qualified + "(value) -> bytes"
		}
	}
	if strings.HasPrefix(qualified, "binary.builder.patch_") {
		if _, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "binary.builder.patch_")); ok {
			return qualified + "(offset, value) -> binary.builder"
		}
	}
	if strings.HasPrefix(qualified, "binary.builder.") {
		if _, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "binary.builder.")); ok {
			return qualified + "(value) -> binary.builder"
		}
	}
	if strings.HasPrefix(qualified, "binary.cursor.") {
		if codec, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "binary.cursor.")); ok {
			result := "int"
			if codec.Float {
				result = "float"
			}
			return qualified + "() -> " + result
		}
	}
	if strings.HasPrefix(qualified, "emulator.x86.read_") {
		if codec, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "emulator.x86.read_")); ok {
			result := "int"
			if codec.Float {
				result = "float"
			}
			return qualified + "(address) -> " + result
		}
	}
	if strings.HasPrefix(qualified, "emulator.x86.write_") {
		if _, ok := binaryapi.ScalarCodecNamed(strings.TrimPrefix(qualified, "emulator.x86.write_")); ok {
			return qualified + "(address, value) -> None"
		}
	}
	return qualified + "(...)"
}

func starlarkModuleDocstring(statement syntax.Stmt) (string, bool) {
	expression, ok := statement.(*syntax.ExprStmt)
	if !ok {
		return "", false
	}
	literal, ok := expression.X.(*syntax.Literal)
	if !ok || literal.Token != syntax.STRING {
		return "", false
	}
	value, ok := literal.Value.(string)
	return value, ok && strings.TrimSpace(value) != ""
}

func stdlibLabelForPath(modulePath string) string {
	directory, file := splitModulePath(modulePath)
	return fmt.Sprintf("@stdlib//%s:%s", directory, file)
}

func splitModulePath(modulePath string) (string, string) {
	index := strings.LastIndexByte(modulePath, '/')
	if index < 0 {
		return "", modulePath
	}
	return modulePath[:index], modulePath[index+1:]
}
