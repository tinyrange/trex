"""Drive original IRIX 3.3.2 desktop programs through the IP12 input devices."""

load("//scripts/smoke:irix_ip12_system.star", "prepare")

def _advance(machine, console, cycles):
    stop = machine.run(cycles)
    data = console.read_available()
    if stop.kind != "budget":
        fail("IRIX stopped", stop.kind, hex(stop.pc), data)
    if data and (b"PANIC:" in data or b"Graphics FIFO timeout" in data or b"microcode error" in data):
        fail("IRIX stopped responding", repr(data))
    return data

def _login(machine, console):
    replies = {
        "Automatically reconfigure the operating system": b"n\r",
        "IRIS console login:": b"root\r",
        "TERM = (vt100)": b"\r",
    }
    transcript = ""
    for _ in range(64):
        data = _advance(machine, console, 9000000)
        if data:
            transcript += str(data)
        for prompt in list(replies):
            if prompt in transcript:
                console.write(replies.pop(prompt))
        if "TERM = (vt100)" in transcript and transcript.endswith("# "):
            return
    fail("IRIX serial login did not complete", repr(transcript[-1200:]))

def _move(machine, console, x, y, buttons = 0):
    for _ in range(90):
        graphics = machine.graphics()
        dx, dy = x - graphics.cursor_x, graphics.cursor_y - y
        if abs(dx) <= 3 and abs(dy) <= 3:
            return
        machine.mouse(max(-27, min(27, dx)), max(-27, min(27, dy)), buttons)
        _advance(machine, console, 1200000)
    fail("4Sight cursor did not reach", x, y)

def _place(machine, console, x, y, width, height):
    _move(machine, console, x, y)
    machine.mouse(0, 0, 4)
    _advance(machine, console, 1800000)
    _move(machine, console, x + width, y + height, buttons = 4)
    machine.mouse(0, 0, 0)
    _advance(machine, console, 18000000)

def _click(machine, console, x, y):
    # The 4Sight pointer hot spot in this scanout is below the BT431
    # sprite origin exposed by machine.graphics().
    _move(machine, console, x, y - 48)
    machine.mouse(0, 0, 4)
    _advance(machine, console, 1800000)
    machine.mouse(0, 0, 0)
    _advance(machine, console, 3000000)

def _open(machine, console, command, x, y, width, height):
    console.write(bytes(command + "\r"))
    _advance(machine, console, 24000000)
    _place(machine, console, x, y, width, height)

def _verify(frame):
    # Match app-specific output in small regions of the expected stock
    # scanout. Hash RGB bytes so PNG encoder differences do not matter.
    regions = [
        ("Calculator result 5", 414, 247, 35, 44, "812b595ba5b232d9aab68e8f2764845f447c560e47c9a6441ee9dd78f7ce9fc4"),
        ("Icon & Font Browser title", 580, 141, 160, 18, "521945dc7b31074b9f51949246c34947a1ca9e7a73364caf33b2d23210a1cb53"),
        ("Icon & Font Browser SUNCORE glyph", 641, 195, 69, 69, "2fd27b8433a6cea186925573daa995b72eb0df231a25fa3ea0d935e9d74f568a"),
        ("ItemClass Notify: Value=true", 230, 603, 152, 24, "ac83666a9af695ec0f39d4ad122baeb5054c8853692909e0ce98cdbe3dbb271d"),
        ("NeWS terminal uname output", 757, 595, 157, 15, "142701efaafab3b9d774d361bed5d71895a95961adccb32b731c3a4e5e5b698e"),
    ]
    screen = image.decode(frame)
    for label, x, y, width, height, expected in regions:
        pixels = [screen.pixel(px, py) for py in range(y, y + height) for px in range(x, x + width)]
        actual = hex(crypto.hash("sha256", bytes([v for p in pixels for v in [p.r, p.g, p.b]])))
        if actual != expected:
            fail("IRIX desktop did not render", label, "RGB hash", actual)

def main(args):
    if len(args) != 2:
        fail("usage: irix_ip12_desktop.star IRIX_3.3_ARCHIVE.7z DESKTOP.png")
    machine, _, _ = prepare(open(args[0]))
    console = machine.serial()
    _login(machine, console)
    console.write(b"/etc/gl/grcond &\r")
    for _ in range(14):
        _advance(machine, console, 18000000)
    console.write(b"setenv NEWSSERVER `/usr/sbin/setnewshost localhost`\r")
    _advance(machine, console, 5000000)

    _open(machine, console, "/usr/NeWS/demo/calcul &", 210, 160, 280, 320)
    # Clear, 2, +, 3, =.
    for x, y in [(398, 330), (297, 330), (402, 380), (347, 330), (402, 482)]:
        _click(machine, console, x, y)

    _open(machine, console, "/usr/NeWS/demo/iconbrowser &", 550, 90, 610, 385)
    _open(machine, console, "/usr/NeWS/demo/itemdemo &", 170, 510, 520, 380)
    _click(machine, console, 280, 829)

    # psterm inherits the foreground serial job before opening its own pty.
    _open(machine, console, "/usr/sbin/psterm", 750, 500, 475, 390)
    _move(machine, console, 805, 580)
    # Physical SGI key codes for 'uname -a' and Return.
    for code in [32, 36, 10, 43, 16, 82, 46, 10, 50]:
        machine.key_code(code)
        machine.key_code(code, down = False)
        _advance(machine, console, 1600000)
    _advance(machine, console, 16000000)

    frame = machine.screenshot()
    _verify(frame)
    write(args[1], frame)
    machine.close()
    print("IRIX 3.3.2 4Sight desktop verified")
    print("Calculator 2 + 3 = 5, Icon & Font Browser, ItemClass button callback, and NeWS terminal uname")
