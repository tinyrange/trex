"""Wraps a semantic plugin and restores its state from a checkpoint."""

load("@stdlib//windows/emulation:conformance.star", "call", "session")
load("@stdlib//windows/selfreg:plugins.star", "override_plugin")

def main(args):
    if args:
        fail("usage: emulator_override.star")
    state = {"calls": 0}
    def answer(event):
        return event.args[0] + 1
    def observe(event, previous):
        state["calls"] += 1
        return previous(event) * 2
    target = session(
        code = b"\xc3",
        bindings = [{"module": "example", "name": "Answer", "callback": answer, "argc": 1}],
        plugins = [override_plugin("observe answer", [{"module": "example", "name": "Answer", "callback": observe, "wrap": True}], state = state)],
        instruction_limit = 100,
    )
    machine = target["machine"]
    checkpoint = machine.checkpoint()
    for unused in range(2):
        machine.restore(checkpoint)
        call(target, module = "example", name = "Answer", arguments = [20], expected_return = 42)
        if state["calls"] != 1:
            fail("checkpoint did not restore plugin state")
    print("wrapped answer=42; checkpoint restored plugin state")
