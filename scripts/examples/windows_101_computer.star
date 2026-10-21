"""Public Windows 1.01 computer-use demo, with optional real-time boot video.

Supply three DOS 6.22 and five Windows 1.01 images in disk order.
Options: video=demo.mp4 screenshot=demo.png repl=true pace=false lossless=true. No StarAgent needed.
Default runs draw_demo once on the fresh desktop and shuts down. repl=true
instead enters an interactive trex REPL; EOF finalizes video and closes the VM.
"""
load("//scripts/images:windows_101.star", "windows_101_disk", "BIOS_CHS")
load("//scripts/guest/windows_extension:build.star", "compile_win16")
load("//scripts/guest/windows_extension:computer_client.star", "click", "drag", "draw_demo", "input_events", "key_chord", "type_text")
load("@stdlib//qemu:profiles.star", "dos")

def _ready(serial):
    expected = "WINEXT_READY\n"
    received = ""
    deadline = clock.monotonic() + 30
    for _ in range(len(expected)):
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            fail("Windows extension readiness timed out")
        part = str(serial.read_some(len(expected) - len(received), timeout = remaining))
        if not part:
            fail("Windows extension disconnected before readiness")
        received += part
        if received == expected:
            return
        if not expected.startswith(received):
            fail("invalid Windows extension readiness")
    fail("incomplete Windows extension readiness")

def _hold(vm, seconds):
    deadline = clock.monotonic() + seconds
    while clock.monotonic() < deadline:
        if debug.select([vm], timeout = max(0, deadline - clock.monotonic())) != None:
            vm.next_event(timeout = 0)

def _session(vm, options, owned):
    recorder = None
    if options["video"]:
        recorder = vm.record(width = 1440, height = 900, fps = 30, maximum = 64 << 20, duration = 600, lossless = options["lossless"] == "true")
        owned["recorder"] = recorder
    # Recording is ready BEFORE the first guest instruction, including BIOS.
    vm.resume()
    serial = vm.channel("extension")
    _ready(serial)
    device = channel.extension(serial, timeout = 5)
    owned["device"] = device
    pause = lambda seconds: _hold(vm, seconds)
    if options["repl"] == "true":
        print("Native device connected. help(device); print(channel.extension_protocol()); draw_demo(device, pause=pause)")
        print("Optional recorder is already capturing boot. EOF finalizes the video and closes the VM.")
        repl()
    else:
        if options["pace"] == "true":
            _hold(vm, 3)
            print(draw_demo(device, pause = pause))
        else:
            print(draw_demo(device))
    _hold(vm, 5 if options["pace"] == "true" else 2)
    if options["screenshot"]:
        write(options["screenshot"], vm.screenshot())
    if recorder != None:
        video = recorder.stop()
        print("RECORDING", {"frames": recorder.stats.frames, "duplicated": recorder.stats.duplicated, "elapsed": recorder.stats.elapsed, "bytes": video.size})
        write(options["video"], video)

def main(args):
    if len(args) < 8:
        fail("expected three DOS 6.22 disk paths and five Windows 1.01 disk paths, then optional video=, screenshot=, repl=true")
    options = {"video": "", "screenshot": "", "repl": "false", "pace": "true", "lossless": "false"}
    for arg in args[8:]:
        key, separator, value = arg.partition("=")
        if not separator or key not in options:
            fail("unknown option " + arg)
        options[key] = value
    for key in ["repl", "pace", "lossless"]:
        if options[key] not in ["true", "false"]:
            fail(key + " must be true or false")
    agent = compile_win16(computer_use = True)
    disk = windows_101_disk(modifications = [{"path": "/TREXEXT.EXE", "file": agent}],
        startup = "c:\\trexext.exe", *[open(p) for p in args[:8]])
    machine = vmm.machine(architecture = "i386", memory = 16 << 20, start_paused = True,
        disks = [vmm.disk(disk, name = "win101", bus = "ide", unit = 0, chs = BIOS_CHS, snapshot = True)],
        channels = [vmm.channel("serial", name = "extension")], display = vmm.display("capturable"))
    vm = vmm.start(machine, dos())
    owned = {}
    result = testing.attempt(_session, args = [vm, options, owned])
    # Cleanup runs even if capture, discovery, input, or output export failed.
    if "device" in owned:
        testing.attempt(owned["device"].close)
    if "recorder" in owned:
        testing.attempt(owned["recorder"].close)
    closed = testing.attempt(vm.close)
    if not result.ok:
        fail(result.error)
    if not closed.ok:
        fail(closed.error)
