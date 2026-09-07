"""Calls a tiny owned x86 function with bounded named buffers."""

load("@stdlib//windows/emulation:conformance.star", "call", "output", "pointer", "session")

def main(args):
    if args:
        fail("usage: emulator_call.star")
    # mov edx,[esp+4]; mov dword ptr [edx],42; mov eax,42; ret 4
    target = session(code = b"\x8b\x54\x24\x04\xc7\x02\x2a\x00\x00\x00\xb8\x2a\x00\x00\x00\xc2\x04\x00", instruction_limit = 100)
    result = call(
        target,
        rva = 0,
        buffers = {"answer": output(4, expected = b"\x2a\x00\x00\x00")},
        arguments = [pointer("answer")],
        expected_return = 42,
    )
    print("reason=%s answer=%d" % (result["result"].reason, result["result"].value))
