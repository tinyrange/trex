"""Tests for bounded emulated implementation conformance calls."""

load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/emulation:conformance.star", conformance_call = "call", "buffer", "c_memory_bindings", "output", "pointer", "resolve", "run", "sequence", conformance_session = "session", "size_of")
load("@stdlib//windows/selfreg:plugins.star", "override_plugin")
load("@stdlib//windows/selfreg:win32.star", "kernel32_plugin", "msvcrt_plugin")

def _u32(value):
    encoded = binary.builder(capacity = 4)
    encoded.u32le(value)
    return encoded.bytes()

def test_buffers_and_rva_calls_are_repeatable():
    # mov eax,[esp+8]; mov edx,[esp+0xc]; mov [edx],eax; ret 0xc
    session = conformance_session(code = b"\x8b\x44\x24\x08\x8b\x54\x24\x0c\x89\x02\xc2\x0c\x00")
    target = resolve(session, rva = 0)
    for value in [b"abc", b"longer input"]:
        result = conformance_call(
            session,
            target,
            buffers = {
                "input": buffer(value, capture = False),
                "output": output(4, expected = _u32(len(value))),
            },
            arguments = [pointer("input"), size_of("input"), pointer("output")],
            expected_return = len(value),
        )
        equal(result["buffers"]["output"], _u32(len(value)))
        equal(result["result"].reason, "return")

def test_declared_exports_are_callable():
    def fill(event):
        event.machine.write(event.args[0], b"pass")
        return 7
    session = conformance_session(
        code = b"\xc3",
        bindings = [{"module": "fixture.dll", "name": "Fill", "argc": 1, "callback": fill}],
    )
    result = conformance_call(
        session,
        resolve(session, module = "fixture.dll", name = "Fill"),
        buffers = {"value": output(4, expected = b"pass")},
        arguments = [pointer("value")],
        expected_return = 7,
    )
    equal(result["buffers"]["value"], b"pass")

def test_call_selectors():
    session = conformance_session(code = b"\xb8\x2a\x00\x00\x00\xc3")
    equal(conformance_call(session, rva = 0)["result"].value, 42)
    equal(conformance_call(session, address = session["raw_base"])["result"].value, 42)
    raises(conformance_call, args = [session], message = "exactly one")
    raises(conformance_call, args = [session, session["raw_base"]], kwargs = {"rva": 0}, message = "cannot combine")
    raises(conformance_call, args = [session], kwargs = {"rva": 0, "name": "Answer"}, message = "exactly one")
    def answer(event):
        return 42
    session["machine"].provide_export(answer, module = "fixture", ordinal = 7)
    equal(conformance_call(session, module = "fixture", ordinal = 7)["result"].value, 42)

def test_override_validation_and_replacement():
    machine = emulator.x86(code = b"\xc3")
    def base(event):
        return event.args[0]
    def replacement(event):
        return event.args[0] + 1
    raises(machine.override, args = [replacement], kwargs = {"module": "fixture", "name": "Answer"}, message = "install the base plugin first")
    for selector in [{}, {"name": "Answer", "ordinal": 1}, {"ordinal": -1}, {"ordinal": 65536}]:
        raises(machine.override, args = [replacement], kwargs = dict(selector, module = "fixture"), message = "exactly one")
    address = machine.provide_export(base, module = "fixture", ordinal = 7, argc = 1)
    equal(machine.override(replacement, module = "fixture", ordinal = 7), [address])
    equal(machine.call(address, args = [41]).value, 42)
    machine.provide_export(value = b"data", module = "fixture", name = "Data")
    raises(machine.override, args = [replacement], kwargs = {"module": "fixture", "name": "Data"}, message = "no semantic binding")
    machine.provide_export(base, module = "fixture", name = "Ambiguous", argc = 1)
    machine.provide_export(base, module = "fixture", name = "Ambiguous", argc = 2)
    raises(machine.override, args = [replacement], kwargs = {"module": "fixture", "name": "Ambiguous"}, message = "ambiguous base bindings")

def test_base_plugin_wrapping():
    state = {"calls": 0}
    def observe(event, previous):
        state["calls"] += 1
        return previous(event) + 1
    session = conformance_session(code = b"\xc3", plugins = [
        kernel32_plugin(),
        override_plugin("observe", [{"module": "kernel32", "name": "GetLastError", "callback": observe, "wrap": True}], state = state),
    ])
    machine = session["machine"]
    saved = machine.checkpoint()
    for unused in range(2):
        machine.restore(saved)
        conformance_call(session, module = "kernel32", name = "SetLastError", arguments = [41])
        conformance_call(session, module = "kernel32", name = "GetLastError", expected_return = 42)
        equal(state["calls"], 1)

def test_conformance_expectations_fail_closed():
    session = conformance_session(code = b"\xb8\x01\x00\x00\x00\xc3")
    target = resolve(session, address = session["raw_base"])
    raises(conformance_call, args = [session, target], kwargs = {"expected_return": 2}, message = "returned")
    raises(resolve, args = [session], kwargs = {"rva": 0, "address": target}, message = "exactly one")

def test_named_case_runner_preserves_order():
    observed = []
    def first():
        observed.append(1)
        return "one"
    def second():
        observed.append(2)
        return "two"
    result = run([
        {"name": "first", "call": first},
        {"name": "second", "call": second},
    ])
    equal(observed, [1, 2])
    equal(result, [{"name": "first", "result": "one"}, {"name": "second", "result": "two"}])

def test_sequence_shares_only_declared_memory():
    # add dword ptr [first argument],1; mov eax,[first argument]; ret 4
    session = conformance_session(code = b"\x8b\x54\x24\x04\x83\x02\x01\x8b\x02\xc2\x04\x00")
    result = sequence(session, [
        {"target": resolve(session, rva = 0), "arguments": [pointer("counter")], "expected_return": 1},
        {"target": resolve(session, rva = 0), "arguments": [pointer("counter")], "expected_return": 2},
    ], buffers = {"counter": output(4, expected = _u32(2))})
    equal(result["buffers"]["counter"], _u32(2))
    equal(len(result["results"]), 2)

def test_c_memory_bindings_are_explicit_and_bounded():
    session = conformance_session(code = b"\xc3", bindings = c_memory_bindings())
    result = conformance_call(
        session,
        resolve(session, module = "msvcrt.dll", name = "memset"),
        buffers = {"value": output(5, expected = b"AAAAA")},
        arguments = [pointer("value"), 0x41, size_of("value")],
    )
    equal(result["buffers"]["value"], b"AAAAA")

def test_locale_validation_is_explicit():
    session = conformance_session(code = b"\xc3", plugins = [kernel32_plugin()])
    for locale in [0x007f, 0x0409]:
        for flags in [1, 2]:
            conformance_call(session, module = "kernel32", name = "IsValidLocale", arguments = [locale, flags], expected_return = 1)
    conformance_call(session, module = "kernel32", name = "IsValidLocale", arguments = [0x0411, 1], expected_return = 0)
    conformance_call(session, module = "kernel32", name = "IsValidLocale", arguments = [0x0409, 0], expected_return = 0)
    conformance_call(session, module = "kernel32", name = "GetLastError", expected_return = 87)

def test_wide_stream_output_and_invalid_handle():
    kernel = kernel32_plugin()
    crt = msvcrt_plugin(kernel = kernel)
    session = conformance_session(code = b"\xc3", plugins = [kernel, crt])
    handle = conformance_call(session, module = "msvcrt", name = "fopen", buffers = {
        "path": buffer(b"C:\\output.txt\x00"), "mode": buffer(b"w\x00"),
    }, arguments = [pointer("path"), pointer("mode")])["result"].value
    equal(handle != 0, True)
    conformance_call(session, module = "msvcrt", name = "fputws", buffers = {
        "text": buffer(binary.encode("AppVerifier", encoding = "utf16le", nul = True)),
    }, arguments = [pointer("text"), handle], expected_return = 0)
    equal(kernel.state["file_data"](r"c:\output.txt"), b"AppVerifier")
    conformance_call(session, module = "msvcrt", name = "fclose", arguments = [handle], expected_return = 0)
    conformance_call(session, module = "msvcrt", name = "fputws", buffers = {
        "text": buffer(binary.encode("not written", encoding = "utf16le", nul = True)),
    }, arguments = [pointer("text"), handle], expected_return = 0xffffffff)
    equal(kernel.state["file_data"](r"c:\output.txt"), b"AppVerifier")

def test_global_atoms_are_case_insensitive_and_scoped():
    session = conformance_session(code = b"\xc3", plugins = [kernel32_plugin()])
    def atom(api, text):
        return conformance_call(session, module = "kernel32", name = api, buffers = {
            "name": buffer(binary.encode(text, encoding = "utf16le", nul = True)),
        }, arguments = [pointer("name")])["result"].value
    equal(atom("GlobalFindAtomW", "WcaVerboseLogging"), 0)
    conformance_call(session, module = "kernel32", name = "GetLastError", expected_return = 2)
    equal(atom("AddAtomW", "WcaVerboseLogging"), 0xc000)
    equal(atom("GlobalFindAtomW", "WcaVerboseLogging"), 0)
    first = atom("GlobalAddAtomW", "WcaVerboseLogging")
    equal(atom("GlobalFindAtomW", "wcaverboselogging"), first)
    equal(atom("GlobalAddAtomW", "WCAVERBOSELOGGING"), first)
    equal(atom("GlobalAddAtomW", "another"), first + 1)
    equal(atom("GlobalFindAtomW", "#123"), 123)
    equal(atom("GlobalAddAtomW", "x" * 256), 0)
    conformance_call(session, module = "kernel32", name = "GetLastError", expected_return = 87)

def test_wow64_uses_explicit_target_architecture():
    for native in [0x14c, 0x8664]:
        session = conformance_session(code = b"\xc3", plugins = [kernel32_plugin(version = {"native_machine": native})])
        conformance_call(session, module = "kernel32", name = "IsWow64Process2", buffers = {
            "process": output(2, expected = binary.u16le(0x14c if native == 0x8664 else 0)),
            "native": output(2, expected = binary.u16le(native)),
        }, arguments = [0xffffffff, pointer("process"), pointer("native")], expected_return = 1)
        conformance_call(session, module = "kernel32", name = "IsWow64Process", buffers = {
            "wow": output(4, expected = binary.u32le(int(native == 0x8664))),
        }, arguments = [0xffffffff, pointer("wow")], expected_return = 1)
        result = conformance_call(session, module = "kernel32", name = "GetNativeSystemInfo", buffers = {"info": output(36)}, arguments = [pointer("info")])
        equal(result["buffers"]["info"][:2], binary.u16le(9 if native == 0x8664 else 0))
        result = conformance_call(session, module = "kernel32", name = "GetSystemInfo", buffers = {"info": output(36)}, arguments = [pointer("info")])
        equal(result["buffers"]["info"][:2], binary.u16le(0))
        conformance_call(session, module = "kernel32", name = "IsWow64Process2", arguments = [0xffffffff, 0, 0], expected_return = 0)
        conformance_call(session, module = "kernel32", name = "GetLastError", expected_return = 87)

TEST_SUITE = suite("windows/emulation/conformance", [
    case("wow64_uses_explicit_target_architecture", test_wow64_uses_explicit_target_architecture),
    case("global_atoms_are_case_insensitive_and_scoped", test_global_atoms_are_case_insensitive_and_scoped),
    case("wide_stream_output_and_invalid_handle", test_wide_stream_output_and_invalid_handle),
    case("locale_validation_is_explicit", test_locale_validation_is_explicit),
    case("base_plugin_wrapping", test_base_plugin_wrapping),
    case("call_selectors", test_call_selectors),
    case("override_validation_and_replacement", test_override_validation_and_replacement),
    case("buffers_and_rva_calls_are_repeatable", test_buffers_and_rva_calls_are_repeatable),
    case("declared_exports_are_callable", test_declared_exports_are_callable),
    case("conformance_expectations_fail_closed", test_conformance_expectations_fail_closed),
    case("named_case_runner_preserves_order", test_named_case_runner_preserves_order),
    case("sequence_shares_only_declared_memory", test_sequence_shares_only_declared_memory),
    case("c_memory_bindings_are_explicit_and_bounded", test_c_memory_bindings_are_explicit_and_bounded),
])
