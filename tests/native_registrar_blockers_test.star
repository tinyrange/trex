"""Focused native registrar contracts for ME mapped files and NT5 SCM queries."""

load("//tests:testing.star", "case", "equal", "suite", "true")

def test_query_service_config():
    scm_module = testing.module("@stdlib//windows/selfreg:service.star")
    registry_module = testing.module("@stdlib//windows/selfreg:registry.star")
    kernel_module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        for wide in [False, True]:
            machine = emulator.machine(code = b"\xc3", architecture = architecture)
            registry = registry_module["registry_plugin"]()
            kernel = kernel_module["kernel32_plugin"]()
            scm = scm_module["service_manager_plugin"](registry, kernel = kernel)
            machine.use([kernel, scm])
            def call(name, args):
                result = machine.call(machine.resolve_export("advapi32.dll", name = name), args = args)
                equal(result.reason, "return", result.detail)
                return result.value
            encoding = "utf16le" if wide else "ascii"
            suffix = "W" if wide else "A"
            def text(value):
                return machine.allocate(value = binary.encode(value, encoding = encoding, nul = True))
            display = "Storage 🎵" if wide else "Storage"
            image = r"%SystemRoot%\system32\储存.exe" if wide else r"%SystemRoot%\system32\storage.exe"
            dependencies = ["依存🎵", "+组", "Last"] if wide else ["RpcSs", "+Group", "Last"]
            service_name = text("StorageSvc")
            manager = call("OpenSCManager" + suffix, [0, 0, 0])
            tag = machine.allocate(size = 4)
            handle = call("CreateService" + suffix, [manager, service_name, text(display), 1, 0x20, 2, 1, text(image), text("StorageGroup"), tag, text("\x00".join(dependencies) + "\x00"), 0, 0])
            true(handle != 0)
            key = "/ControlSet001/Services/StorageSvc"
            registry.set_value("SYSTEM", key, "Tag", "REG_DWORD", 73)
            query = "QueryServiceConfig" + suffix
            needed = machine.allocate(value = b"\xcc" * 4)
            equal(call(query, [0, 0, 0, needed]), 0)
            equal(kernel.state["last_error"], 6)
            equal(machine.read_u32le(needed), 0xcccccccc)
            denied = call("OpenService" + suffix, [manager, service_name, 4])
            equal(call(query, [denied, 0, 0, needed]), 0)
            equal(kernel.state["last_error"], 5)
            equal(call(query, [handle, 0, 0, 0]), 0)
            equal(kernel.state["last_error"], 87)
            equal(call(query, [handle, 0, 0, needed]), 0)
            equal(kernel.state["last_error"], 122)
            # SCM stores service and group dependencies separately; its wire
            # MULTI_SZ prefixes group names with '+' again.
            expected_dependencies = [dependencies[0], dependencies[2], dependencies[1]]
            strings = [image, "StorageGroup", "\x00".join(expected_dependencies) + "\x00", "LocalSystem", display]
            encoded = [binary.encode(value, encoding = encoding, nul = True) for value in strings]
            header = 64 if architecture == "amd64" else 36
            size = header
            for data in encoded:
                size += len(data)
            equal(machine.read_u32le(needed), size)
            output = machine.allocate(value = b"\xa5" * (size + 8), address = 0x100300000 if architecture == "amd64" else 0x300000)
            high = 0x100000000 if architecture == "amd64" else 0
            equal(call(query, [handle, output, high | (size - 1), needed]), 0)
            equal(kernel.state["last_error"], 122)
            equal(machine.read(output, size + 8), b"\xa5" * (size + 8))
            equal(call(query, [handle, 0, size, needed]), 0)
            equal(kernel.state["last_error"], 87)
            equal(call(query, [handle, output, high | size, needed]), 1)
            equal([machine.read_u32le(output + index * 4) for index in range(3)], [0x20, 2, 1])
            equal(machine.read_u32le(output + (32 if header == 64 else 20)), 73)
            offsets = [16, 24, 40, 48, 56] if header == 64 else [12, 16, 24, 28, 32]
            cursor = output + header
            for offset, data in zip(offsets, encoded):
                equal(machine.read_pointer(output + offset), cursor)
                equal(machine.read(cursor, len(data)), data)
                cursor += len(data)
            equal(machine.read(output + size, 8), b"\xa5" * 8)
            # Query existing registry services as well as services created in
            # this invocation; do not expand ImagePath environment strings.
            reopened = call("OpenService" + suffix, [manager, service_name, 0x80000000])
            equal(call(query, [reopened, output, size, needed]), 1)
            equal(call("CloseServiceHandle", [reopened]), 1)
            equal(call(query, [reopened, output, size, needed]), 0)
            equal(kernel.state["last_error"], 6)
            registry.set_value("SYSTEM", "/ControlSet001/Services/Minimal", "Type", "REG_DWORD", 1)
            minimal = call("OpenService" + suffix, [manager, text("Minimal"), 1])
            equal(call(query, [minimal, 0, 0, needed]), 0)
            size = machine.read_u32le(needed)
            output = machine.allocate(size = size)
            equal(call(query, [minimal, output, size, needed]), 1)
            equal(machine.read_cstring(machine.read_pointer(output + offsets[4]), encoding = encoding), "Minimal")
            equal(machine.read(machine.read_pointer(output + offsets[2]), 4 if wide else 2), b"\x00" * (4 if wide else 2))

def test_mapped_file_end_of_file():
    module = testing.module("@stdlib//windows/selfreg:win32.star")
    for architecture in ["x86", "amd64"]:
        for access in [1, 4]:  # copy-on-write and read-only views both hold a section
            machine = emulator.machine(code = b"\xc3", architecture = architecture)
            kernel = module["kernel32_plugin"](files = {r"C:\mapped.bin": b"abcdefgh", r"C:\source.bin": b"src"}, maximum_file_size = 32, volumes = {"C:": {"filesystem": "NTFS"}})
            machine.use(kernel)
            def call(name, args):
                result = machine.call(machine.resolve_export("kernel32.dll", name = name), args = args)
                equal(result.reason, "return", result.detail)
                return result.value
            path = machine.allocate(value = b"C:\\mapped.bin\x00")
            alias = machine.allocate(value = b"C:\\alias.bin\x00")
            source = machine.allocate(value = b"C:\\source.bin\x00")
            equal(call("CreateHardLinkA", [alias, path, 0]), 1)
            handle = call("CreateFileA", [path, 0xc0000000, 7, 0, 3, 0, 0])
            reader = call("CreateFileA", [path, 0x80000000, 7, 0, 3, 0, 0])
            equal(call("SetEndOfFile", [0]), 0)
            equal(call("GetLastError", []), 6)
            equal(call("SetEndOfFile", [reader]), 0)
            equal(call("GetLastError", []), 5)
            equal(call("SetFilePointer", [handle, 3, 0, 0]), 3)
            mapping = call("CreateFileMappingA", [handle, 0, 4, 0, 0, 0])
            true(mapping != 0)
            equal(call("SetEndOfFile", [handle]), 0)  # section, no views yet
            equal(call("GetLastError", []), 1224)
            view = call("MapViewOfFile", [mapping, access, 0, 0, 8])
            true(view != 0)
            invalid = 0xffffffffffffffff if architecture == "amd64" else 0xffffffff
            for disposition in [2, 5]:
                equal(call("CreateFileA", [alias, 0xc0000000, 7, 0, disposition, 0, 0]), invalid)
                equal(call("GetLastError", []), 1224)
            equal(call("CopyFileA", [source, alias, 0]), 0)
            equal(call("GetLastError", []), 1224)
            equal(call("CloseHandle", [mapping]), 1)
            equal(call("SetEndOfFile", [handle]), 0)  # view retains closed section
            equal(call("GetLastError", []), 1224)
            equal(machine.read(view, 8), b"abcdefgh")
            equal(call("GetFileSize", [handle, 0]), 8)
            equal(call("SetFilePointer", [handle, 0, 0, 1]), 3)
            equal(call("UnmapViewOfFile", [view]), 1)
            equal(call("SetEndOfFile", [handle]), 1)
            equal(call("GetFileSize", [handle, 0]), 3)
            equal(call("GetFileSize", [reader, 0]), 3)
            equal(call("SetFilePointer", [handle, 12, 0, 0]), 12)
            equal(call("SetEndOfFile", [handle]), 1)
            equal(call("GetFileSize", [reader, 0]), 12)
            # Last view gone is not enough while its mapping handle is open.
            mapping = call("CreateFileMappingA", [handle, 0, 4, 0, 0, 0])
            view = call("MapViewOfFile", [mapping, 4, 0, 0, 12])
            equal(machine.read(view, 3), b"abc")
            equal(call("UnmapViewOfFile", [view]), 1)
            equal(call("SetFilePointer", [handle, 2, 0, 0]), 2)
            equal(call("SetEndOfFile", [handle]), 0)
            equal(call("GetLastError", []), 1224)
            equal(call("CloseHandle", [mapping]), 1)
            equal(call("SetEndOfFile", [handle]), 1)
            equal(call("SetFilePointer", [handle, 33, 0, 0]), 33)
            equal(call("SetEndOfFile", [handle]), 0)
            equal(call("GetLastError", []), 112)
            equal(call("GetFileSize", [handle, 0]), 2)

TEST_SUITE = suite("native_registrar_blockers", [
    case("query_service_config", test_query_service_config),
    case("mapped_file_end_of_file", test_mapped_file_end_of_file),
])
