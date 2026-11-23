"""Boot the April 1991 NT build on the in-process R3000 Jazz machine.

Pass media as separate files, select members of a ZIP, or use the prepared
bundle's positional shorthand. The smoke and console modes exercise the
checked April 1991 guest.
"""

USAGE = """Usage:
  trex scripts/debug/early_nt_jazz_repl.star PREPARED_ZIP [MODE]
  trex scripts/debug/early_nt_jazz_repl.star rom=FILE kernel=FILE disk=FILE [nvram=FILE] [station_id=FILE] [MODE]
  trex scripts/debug/early_nt_jazz_repl.star zip=FILE rom=MEMBER kernel=MEMBER disk=MEMBER [nvram=MEMBER] [station_id=MEMBER] [MODE]

MODE is repl, console-repl, or screenshots ABS_OUTPUT_DIR. With no mode,
run the MAZE boot smoke. In ZIP member names, / and backslash are equivalent.
Use a Jazz ROM, an early NT MIPS COFF kernel, and an MBR disk with a FAT
system partition first.
Omitted NVRAM and station ID inputs use the emulator defaults."""

FIRMWARE_PROMPT = "Microsoft Jazz firmware\r\n>>> "
BOOT_COMMAND = b"boot -f mop(1)/NTOSKRNL.EXE\r"

def zip_media(bundle, names):
    members = {}
    wanted = {name.replace("\\", "/"): True for name in names.values()}
    for entry in archive.zip(bundle).files:
        name = entry.name.replace("\\", "/")
        if name in wanted:
            if name in members:
                fail("ambiguous ZIP member " + repr(name))
            members[name] = entry
    media = {}
    for key, value in names.items():
        name = value.replace("\\", "/")
        if name not in members:
            fail("ZIP member for %s was not found: %s" % (key, name))
        media[key] = members[name]
    return media

def open_media(args):
    if len(args) == 1 and "=" not in args[0]:
        return zip_media(open(args[0]), {
            "rom": "j3rom.bin",
            "kernel": "ntold/NTOSKRNL.EXE",
            "disk": "nt.img",
            "nvram": "system.nvram",
            "station_id": "ethernet.nvram",
        })
    paths = {}
    for arg in args:
        option = arg.split("=", 1)
        if len(option) != 2 or option[0] not in ["zip", "rom", "kernel", "disk", "nvram", "station_id"] or not option[1]:
            fail("invalid media argument " + repr(arg) + "\n" + USAGE)
        key, value = option
        if key in paths:
            fail("duplicate media argument " + key)
        paths[key] = value
    for key in ["rom", "kernel", "disk"]:
        if key not in paths:
            fail("missing media argument " + key + "\n" + USAGE)
    bundle = paths.pop("zip", None)
    if bundle != None:
        return zip_media(open(bundle), paths)
    return {key: open(value) for key, value in paths.items()}

def patch_fat_member(disk, partition, member, offset, replacement):
    written = 0
    for part in member.volume_ranges(offset, len(replacement)):
        disk.write(partition.offset + part.offset, replacement[written:written + part.size])
        written += part.size

def repair_cmd_messages(disk):
    partition = filesystem.mbr(block.view(disk)).partitions[0]
    volume = filesystem.fat(partition.file)
    cmd_path = "/NT/BIN/CMD.EXE"
    if cmd_path not in volume:
        return
    cmd = volume[cmd_path]
    patches = binary.mips_coff_message_lengths(cmd)
    # Patch only the length words in the copy-on-write disk, through FAT's
    # file mapping. A length word may cross a fragmented cluster boundary.
    for patch in patches:
        if binary.read_u16le(cmd, patch.offset) != patch.before:
            fail("CMD.EXE message length changed before repair")
        patch_fat_member(disk, partition, cmd, patch.offset, binary.u16le(patch.after))
    if patches:
        partition = filesystem.mbr(block.view(disk)).partitions[0]
        if binary.mips_coff_message_lengths(filesystem.fat(partition.file)[cmd_path]):
            fail("CMD.EXE message lengths still require repair")
        print("Repaired %d CMD.EXE message entry lengths." % len(patches))

def select_console_server(disk):
    partition = filesystem.mbr(block.view(disk)).partitions[0]
    volume = filesystem.fat(partition.file)
    config = volume["/NTOS2.CFG"]
    text = config.read()
    line = "    SubSystem = "
    start = text.find(line)
    if start < 0:
        fail("Jazz NT configuration has no active Windows subsystem")
    end = text.find("\r\n", start)
    current = text.find("ServerDll=gdisrv,3", start, end)
    if current < 0:
        fail("Jazz NT configuration has an unexpected Windows server list")
    # The checked release uses separate graphics and console server profiles.
    patch_fat_member(disk, partition, config, current, b"ServerDll=consrv,2")
    # The release omits the startup batch file named by the console task manager.
    startup = "CommandLine = cmd.exe"
    arguments = " /k c:\\eachtime.cmd"
    options = text.find(startup + arguments)
    if options >= 0 and "/EACHTIME.CMD" not in volume:
        patch_fat_member(disk, partition, config, options + len(startup), b" " * len(arguments))

def open_jazz(media, graphics_fixture = False, console_profile = False):
    kernel = media["kernel"]
    image = binary.mips_coff(kernel)
    machine = emulator.r3000(
        media["rom"],
        memory = 64 << 20,
        nvram = media.get("nvram"),
        station_id = media.get("station_id"),
    )
    machine.serve_mop("NTOSKRNL.EXE", kernel)
    disk_image = media["disk"]
    if graphics_fixture:
        disk_image = with_plgblt_fixture(disk_image)
    disk = block.overlay(block.device(disk_image))
    repair_cmd_messages(disk)
    if console_profile:
        select_console_server(disk)
    system = filesystem.fat(filesystem.mbr(block.view(disk)).partitions[0].file)
    machine.attach_disk(0, disk)
    return {
        "machine": machine,
        "serial": machine.serial(),
        "symbols": {symbol.name: symbol.address for symbol in image.symbols if symbol.section > 0},
        "image": image,
        "kernel": kernel,
        "system": system,
    }

def read_serial(serial, maximum = 16384):
    data = serial.read_available(maximum)
    return b"" if data == None else data

def stop_summary(stop):
    return "%s at 0x%x, instruction 0x%x, exception %d, address 0x%x, physical 0x%x after %d cycles" % (
        stop.kind,
        stop.pc,
        stop.instruction,
        stop.exception,
        stop.address,
        stop.physical,
        stop.cycles,
    )

def boot_to_kernel(jazz):
    console = ""
    for _ in range(4):
        stop = jazz["machine"].run(250000000)
        if stop.kind != "budget":
            fail("Jazz firmware stopped: " + stop_summary(stop))
        console += str(read_serial(jazz["serial"]))
        if FIRMWARE_PROMPT in console:
            break
    if FIRMWARE_PROMPT not in console:
        fail("Jazz firmware prompt did not appear")
    if jazz["serial"].write_available(BOOT_COMMAND) != len(BOOT_COMMAND):
        fail("could not write Jazz firmware boot command")
    jazz["machine"].break_at(jazz["image"].entry)
    stop = jazz["machine"].run(125000000)
    jazz["machine"].clear_breaks()
    mop = jazz["machine"].mop_status()
    if stop.kind != "breakpoint" or stop.pc != jazz["image"].entry or not mop.complete:
        fail("Jazz MOP handoff failed: " + stop_summary(stop))
    code = [section for section in jazz["image"].sections if section.address <= stop.pc and stop.pc < section.address + section.size][0]
    expected = jazz["kernel"].bytes(code.offset + stop.pc - code.address, 16)
    if jazz["machine"].read(stop.pc & 0x1fffffff, 16) != expected:
        fail("kernel entry bytes differ from the MOP source")
    print("Jazz ROM transferred %d bytes and entered NT at 0x%x" % (mop.bytes_acknowledged, stop.pc))
    return read_serial(jazz["serial"])

def wait_for_kd(jazz, kd, kind, api = None, budget = 12500000):
    machine = jazz["machine"]
    for _ in range(8):
        for _ in range(512):
            event = kd.poll()
            if event == None:
                break
            if event.kind == kind and (api == None or event.api == api):
                return event
            if event.kind in ["exception", "reply", "load_symbols"]:
                fail("unexpected KD %s api 0x%x code 0x%x PC 0x%x" % (
                    event.kind, event.api, event.code, event.pc,
                ))
            if event.kind == "debug_io":
                print(event.text.rstrip())
        stop = machine.run(budget)
        if stop.kind != "budget":
            fail("Jazz stopped while waiting for KD: " + stop_summary(stop))
    fail("KD %s did not arrive at guest PC 0x%x" % (kind, machine.registers().pc))

def resume_initial_break(jazz, kd):
    stop = wait_for_kd(jazz, kd, "exception")
    expected = jazz["symbols"]["DbgBreakPoint"]
    if stop.code != 0x80000003 or stop.pc != expected or stop.address != expected:
        fail("unexpected initial NT break at 0x%x (0x%x)" % (stop.pc, stop.code))
    kd.context()
    context = wait_for_kd(jazz, kd, "reply", api = 0x3132, budget = 100000)
    if context.status != 0 or context.context == None or context.context.pc != expected:
        fail("KD register context did not match DbgBreakPoint")
    entry = jazz["image"].entry
    kd.read_virtual(entry, 16)
    memory = wait_for_kd(jazz, kd, "reply", api = 0x3130, budget = 100000)
    if memory.status != 0 or memory.data != jazz["machine"].read(entry & 0x1fffffff, 16):
        fail("KD virtual memory read did not match the loaded kernel")
    # The early kernel reports the BREAK instruction as FIR. Resuming the
    # deliberate DbgBreakPoint stop requires moving FIR to its following word.
    kd.set_context(context.data, pc = expected + 4)
    result = wait_for_kd(jazz, kd, "reply", api = 0x3133, budget = 100000)
    if result.status != 0:
        fail("KD set context failed with status 0x%x" % result.status)
    getattr(kd, "continue")()
    print("Early NT KD read the MIPS context and kernel memory, advanced FIR, and continued.")

def advance_to(jazz, kd, phase, observed, user_break = None, on_user_break = None):
    machine = jazz["machine"]
    stop = None
    for _ in range(96):
        for _ in range(512):
            event = kd.poll()
            if event == None:
                break
            if event.kind == "load_symbols":
                observed["loaded"][event.text.lower()] = True
                getattr(kd, "continue")()
            elif event.kind == "prompt":
                if event.text != "NT SM> ":
                    fail("unexpected NT debugger prompt " + repr(event.text))
                return "prompt"
            elif event.kind == "exception":
                if user_break == None or event.pc != user_break["pc"] or event.code != 0x80000003:
                    fail("NT stopped during %s at 0x%x with exception 0x%x" % (phase, event.pc, event.code))
                kd.context()
                context = wait_for_kd(jazz, kd, "reply", api = 0x3132, budget = 100000)
                if context.status != 0 or context.context == None or context.context.pc != event.pc:
                    fail("unable to read the user breakpoint context")
                caller = context.context.gpr[31]
                if caller not in user_break["callers"] or caller in observed["user_breaks"]:
                    fail("unexpected user breakpoint caller 0x%x" % caller)
                if on_user_break != None:
                    on_user_break(caller, machine)
                kd.set_context(context.data, pc = event.pc + 4)
                edited = wait_for_kd(jazz, kd, "reply", api = 0x3133, budget = 100000)
                if edited.status != 0:
                    fail("unable to resume the checked guest breakpoint")
                getattr(kd, "continue")()
                observed["user_breaks"][caller] = True
            elif event.kind == "debug_io":
                if "Initialization Complete" in event.text:
                    observed["initialized"] = True
                if " is running" in event.text and event.text.startswith("CLI: Process Handle "):
                    observed["running"] = True
                if "InitRoutine for" in event.text and " failed " in event.text:
                    fail("NT process initialization failed: " + event.text.strip())
        if stop != None and stop.kind == "breakpoint":
            return "breakpoint"
        stop = machine.run(5000000)
        if stop.kind not in ["budget", "breakpoint"]:
            fail("Jazz stopped during %s: %s" % (phase, stop_summary(stop)))
    fail("Jazz did not reach %s at guest PC 0x%x" % (phase, machine.registers().pc))

def session_manager(jazz, kd):
    observed = {"loaded": {}, "initialized": False, "running": False, "user_breaks": {}}
    if advance_to(jazz, kd, "Session Manager", observed) != "prompt":
        fail("expected the NT Session Manager prompt")
    if not observed["initialized"] or "\\smss.exe" not in observed["loaded"]:
        fail("Session Manager prompt arrived before NT initialization proof")
    print("NT Session Manager reached its COM1 prompt.")
    return observed

def image_symbol(executable, name):
    return [symbol.address for symbol in executable.symbols if symbol.name == name and symbol.section > 0][0]

def code_bytes(file, executable, address, size):
    section = [s for s in executable.sections if s.address <= address and address + size <= s.address + s.size][0]
    return file.bytes(section.offset + address - section.address, size)

def wait_for_console_server(jazz, kd):
    machine = jazz["machine"]
    csrsrv = binary.mips_coff(jazz["system"]["/NT/DLL/CSRSRV.DLL"])
    init_return = csrsrv.base + image_symbol(csrsrv, "CsrServerInitialization") + 0x138
    machine.break_at(init_return)
    observed = {"loaded": {}, "initialized": False, "running": False, "user_breaks": {}}
    for _ in range(12):
        outcome = advance_to(jazz, kd, "CSRSS console API port", observed)
        if outcome == "breakpoint":
            regs = machine.registers()
            if regs.pc != init_return or regs.gpr[2] != 0:
                fail("CsrApiPortInitialize failed at 0x%x with status 0x%x" % (regs.pc, regs.gpr[2]))
            machine.clear_breaks()
            print("CSRSS initialized the Windows console API port.")
            return observed
        # The SM debugger prompt pauses the checked guest until answered.
        kd.reply_prompt(b"DELAY 1000\n")
    fail("CSRSS did not initialize the console API port")

def wait_for_address(jazz, kd, observed, address, phase):
    machine = jazz["machine"]
    machine.break_at(address)
    for _ in range(12):
        outcome = advance_to(jazz, kd, phase, observed)
        if outcome == "breakpoint":
            machine.clear_breaks()
            if machine.registers().pc != address:
                fail("unexpected breakpoint while waiting for " + phase)
            return
        kd.reply_prompt(b"DELAY 1000\n")
    fail("NT did not execute %s at 0x%x" % (phase, address))

def start_interactive_cmd(jazz, kd, observed):
    system = jazz["system"]
    server = binary.mips_coff(system["/NT/DLL/CONSRV.DLL"])
    focus_return = server.base + image_symbol(server, "Executive") + 0x300
    # Activate the checked build's console from its task manager.
    jazz["machine"].type("\n")
    # The task manager finishes assigning keyboard focus after starting CMD.
    wait_for_address(jazz, kd, observed, focus_return, "console task manager focus")
    return binary.mips_coff(system["/NT/BIN/CMD.EXE"])

def capture_console(jazz, kd, observed, cmd, output_dir):
    machine = jazz["machine"]
    system = jazz["system"]
    console = binary.mips_coff(system["/NT/DLL/CONSOLE.DLL"])
    read = console.base + image_symbol(console, "ReadConsole")
    version = cmd.base + image_symbol(cmd, "eVersion")
    text_area = 1280 * 128
    before = machine.read(0x40000000, text_area)
    machine.type("ver\n")
    wait_for_address(jazz, kd, observed, version + 4, "keyboard VER")
    wait_for_address(jazz, kd, observed, read + 4, "CMD input after VER")
    if machine.read(0x40000000, text_area) == before:
        fail("CMD VER did not update the Jazz framebuffer")
    write(path.join(output_dir, "nt-cmd.png"), machine.screenshot())
    print("CMD executed VER from the emulated keyboard and rendered its response.")

def launch_maze(jazz, kd, observed, on_user_break = None):
    system = jazz["system"]
    maze = system["/NT/BIN/MAZE.EXE"]
    executable = binary.mips_coff(maze)
    ntdll = binary.mips_coff(system["/NT/DLL/NTDLL.DLL"])
    driver = binary.mips_coff(system["/NT/DLL/JAZZ.DLL"])
    startup = image_symbol(executable, "main")
    travel = image_symbol(executable, "vTravel")
    user_break = {
        "pc": ntdll.base + image_symbol(ntdll, "DbgBreakPoint"),
        # MAZE stops on startup. The checked Jazz display driver separately
        # stops after its palette diagnostic in DrvEnablePDEV.
        "callers": [
            executable.base + startup + 0x1c,
            driver.base + image_symbol(driver, "DrvEnablePDEV") + 0x388,
        ],
    }
    expected = code_bytes(maze, executable, travel, 32)
    pc = executable.base + travel
    machine = jazz["machine"]
    machine.break_at(pc + 4)
    kd.reply_prompt(b"ASYNC C:\\NT\\BIN\\MAZE.EXE\n")
    outcome = advance_to(jazz, kd, "MAZE.EXE startup", observed, user_break, on_user_break)
    if outcome == "prompt" and observed["running"]:
        kd.reply_prompt(b"DELAY 1000\n")
        outcome = advance_to(jazz, kd, "MAZE.EXE drawing", observed, user_break, on_user_break)
    machine.clear_breaks()
    if outcome != "breakpoint" or len(observed["user_breaks"]) != len(user_break["callers"]) or "\\nt\\bin\\maze.exe" not in observed["loaded"]:
        fail("MAZE.EXE did not reach its maze traversal")
    registers = machine.registers()
    if registers.pc != pc + 4 or registers.cp0[12] & 2 == 0 or machine.read_effective(pc, 32) != expected:
        fail("MAZE.EXE traversal did not execute the user-mode bytes from disk")
    print("MAZE.EXE executed user-mode vTravel at 0x%x with code matching the SCSI disk." % pc)

DIB_COLORS = [(16, 40, 78), (23, 158, 188), (250, 187, 35), (236, 68, 87), (242, 242, 236), (74, 90, 181)]

def plgblt_bitmap():
    width, height = 160, 112
    pixels = 14 + 12 + 256 * 3
    bitmap = binary.builder()
    bitmap.append(b"BM")
    bitmap.u32le(pixels + width * height)
    bitmap.u32le(0)
    bitmap.u32le(pixels)
    # This app expects the 12-byte BITMAPCOREHEADER and RGB triples.
    bitmap.u32le(12)
    bitmap.u16le(width)
    bitmap.u16le(height)
    bitmap.u16le(1)
    bitmap.u16le(8)
    for i in range(256):
        red, green, blue = DIB_COLORS[i % len(DIB_COLORS)]
        bitmap.u8(blue)
        bitmap.u8(green)
        bitmap.u8(red)
    for y in range(height):
        for x in range(width):
            border = x < 4 or y < 4 or x >= width - 4 or y >= height - 4
            bitmap.u8(4 if border else (x // 20 + 2 * (y // 16)) % len(DIB_COLORS))
    return bitmap.file()

def with_plgblt_fixture(disk_image):
    partition = filesystem.mbr(disk_image).partitions[0]
    source = filesystem.fat(partition.file)
    if "/DIBS/PAT.DIB" in source:
        fail("graphics smoke expects to supply its own test bitmap")
    root = directory()
    pending = ["/"]
    for _ in range(16):
        children = []
        for folder in pending:
            for name in source[folder].files:
                if name == "/$metadata":
                    continue
                member = source[name]
                if type(member) == "directory":
                    root.mkdir(name)
                    children.append(name)
                else:
                    root.write(name, member)
        pending = children
        if not pending:
            break
    if pending:
        fail("Jazz FAT traversal exceeded the expected directory depth")
    if "/DIBS" not in source:
        root.mkdir("/DIBS")
    root.write("/DIBS/PAT.DIB", plgblt_bitmap())
    volume = filesystem.fat16(
        root,
        size = partition.size,
        boot_code = partition.file.slice(0, 512),
        hidden_sectors = partition.start_lba,
    )
    return disk_image.splice(partition.offset, partition.size, volume)

def verify_bitblt(frame):
    points = [(1, 1), (10, 10), (25, 10), (45, 10), (65, 10), (105, 10), (145, 10)]
    expected = [DIB_COLORS[i] for i in [4, 0, 1, 2, 3, 5, 1]]
    for offset in [0, 200]:
        pixels = image.sample(frame, [(x + offset, y + offset) for x, y in points])
        if [(p.r, p.g, p.b) for p in pixels] != expected:
            fail("PLGBLT did not draw the expected test bitmap at (%d, %d)" % (offset, offset))

def capture_plgblt(jazz, kd, observed, output_dir):
    machine = jazz["machine"]
    # These return addresses identify the checked Jazz palette, app, and
    # GRE breakpoints before the first completed PlgBlt call.
    checked = {
        "pc": 0x6011a610,
        "callers": [0x61010c3c, 0x20118, 0x201a0, 0x62230154, 0x2024c],
    }
    frames = {}
    def capture(caller, m):
        if caller == 0x61010c3c:
            frame = m.screenshot()
            palette = image.sample(frame, [(x * 80 + 40, y * 64 + 32) for y in range(16) for x in range(16)])
            if len({(p.r, p.g, p.b): True for p in palette}) < 240:
                fail("Jazz palette diagnostic did not draw the color grid")
            frames["jazz-display-palette.png"] = frame
        elif caller == 0x201a0:
            frame = m.screenshot()
            verify_bitblt(frame)
            frames["nt-bitblt.png"] = frame
        elif caller == 0x2024c:
            frames["nt-plgblt.png"] = m.screenshot()

    machine.break_at(0x20250)
    kd.reply_prompt(b"ASYNC C:\\NT\\BIN\\PLGBLT.EXE\n")
    outcome = advance_to(jazz, kd, "PLGBLT.EXE startup", observed, checked, capture)
    if outcome == "prompt" and observed["running"]:
        kd.reply_prompt(b"DELAY 1000\n")
        outcome = advance_to(jazz, kd, "PLGBLT.EXE drawing", observed, checked, capture)
    machine.clear_breaks()
    if outcome != "breakpoint" or machine.registers().pc != 0x20250 or len(frames) != 3:
        fail("PLGBLT.EXE did not complete the checked drawing calls")
    points = [(20, 20), (75, 20), (130, 20), (180, 20), (30, 75), (80, 75), (145, 75), (20, 130)]
    expected = [DIB_COLORS[i] for i in [0, 1, 2, 3, 4, 5, 0, 2]]
    pixels = image.sample(frames["nt-plgblt.png"], points)
    if [(p.r, p.g, p.b) for p in pixels] != expected:
        fail("PlgBlt did not draw the transformed test bitmap")
    for name, frame in frames.items():
        write(path.join(output_dir, name), frame)
    print("Captured the Jazz palette, BitBlt, and PlgBlt from the NT framebuffer.")

def run_jazz(media, mode, output_dir = None):
    jazz = open_jazz(
        media,
        graphics_fixture = mode == "graphics",
        console_profile = mode in ["console-repl", "console"],
    )
    boot_to_kernel(jazz)
    kd = windows.kd_early(jazz["serial"])
    resume_initial_break(jazz, kd)
    if mode in ["console-repl", "console"]:
        observed = wait_for_console_server(jazz, kd)
        cmd = start_interactive_cmd(jazz, kd, observed)
        if mode == "console":
            capture_console(jazz, kd, observed, cmd, output_dir)
        else:
            print('Use jazz["machine"].type("ver\\n") and run the guest.')
            repl()
    else:
        observed = session_manager(jazz, kd)
        if mode == "repl":
            print('Use kd.reply_prompt(), kd.poll(), and jazz["machine"].run(budget).')
            repl()
        elif mode == "graphics":
            capture_plgblt(jazz, kd, observed, output_dir)
        else:
            launch_maze(jazz, kd, observed)
    kd.close()
    jazz["machine"].close()

def main(args):
    if not args or (len(args) == 1 and args[0] == "--help"):
        print(USAGE)
        return
    mode_args = []
    media_args = args
    for i in range(1, len(args)):
        if args[i] in ["repl", "console-repl", "screenshots"]:
            media_args = args[:i]
            mode_args = args[i:]
            break
    mode = mode_args[0] if mode_args else ""
    if len(mode_args) != {"": 0, "repl": 1, "console-repl": 1, "screenshots": 2}[mode]:
        fail(USAGE)
    media = open_media(media_args)
    if mode == "screenshots":
        run_jazz(media, "graphics", mode_args[1])
        run_jazz(media, "console", mode_args[1])
    else:
        run_jazz(media, mode)
