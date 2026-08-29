"""Tests for bounded emulated implementation conformance calls."""

load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/emulation:conformance.star", conformance_call = "call", "buffer", "c_memory_bindings", "output", "pointer", "resolve", "run", "sequence", conformance_session = "session", "size_of")

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

TEST_SUITE = suite("windows/emulation/conformance", [
    case("buffers_and_rva_calls_are_repeatable", test_buffers_and_rva_calls_are_repeatable),
    case("declared_exports_are_callable", test_declared_exports_are_callable),
    case("conformance_expectations_fail_closed", test_conformance_expectations_fail_closed),
    case("named_case_runner_preserves_order", test_named_case_runner_preserves_order),
    case("sequence_shares_only_declared_memory", test_sequence_shares_only_declared_memory),
    case("c_memory_bindings_are_explicit_and_bounded", test_c_memory_bindings_are_explicit_and_bounded),
])
