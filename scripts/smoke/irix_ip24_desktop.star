"""Exercise the archived IRIX 6.5.22 desktop on the native SGI Indy."""

load("//scripts/smoke:irix_ip24.star", "prepare")

def _advance(machine, console, cycles):
    stop = machine.run(cycles)
    data = console.read_available()
    if stop.kind != "budget" or (data and b"PANIC:" in data):
        fail("IRIX desktop stopped", stop.kind, hex(stop.pc), repr(data))
    return str(data) if data else ""

def _wait(machine, console, prompt, chunks):
    transcript = ""
    for _ in range(chunks):
        transcript = (transcript + _advance(machine, console, 8000000))[-4096:]
        if prompt in transcript:
            return transcript
    fail("IRIX desktop did not reach", prompt, repr(transcript))

def _issue(machine, console, line, chunks):
    console.write(bytes(line + "\r"))
    for _ in range(chunks):
        _advance(machine, console, 8000000)

def start_desktop(source, toolchest = True, data_disk = None):
    """Start stock Xsgi, 4Dwm, Toolchest, and an xterm on the archived system."""
    machine, _ = prepare(source, "system", newport = True)
    return start_desktop_on(machine, toolchest = toolchest, data_disk = data_disk)

def start_desktop_on(machine, toolchest = True, data_disk = None):
    """Enter the maintenance shell and start the stock Newport desktop."""
    if data_disk != None:
        machine.attach_disk(2, block.device(data_disk))
    console = machine.serial()
    _wait(machine, console, "(or give root password for Single User Mode): ", 65)
    console.write(b"\r")
    _wait(machine, console, "TERM = (iris-tp) ", 25)
    console.write(b"vt100\r")
    _wait(machine, console, "# ", 25)

    console.write(b"setenv PATH /usr/bin/X11:/usr/sbin:/usr/bin:/usr/bsd:/sbin:/etc; setenv DISPLAY :0\r")
    _wait(machine, console, "# ", 3)
    console.write(b"/usr/etc/ifconfig lo0 inet 127.0.0.1 up; /etc/mntproc\r")
    _wait(machine, console, "# ", 4)
    _issue(machine, console, "Xsgi :0 -ac -bs -nobitscale -c -pseudomap 4sight -solidroot sgilightblue >& /tmp/trex-xsgi.log &", 16)
    _issue(machine, console, "xterm -geometry 51x13+390+91 -title 'IRIX Terminal' >& /tmp/trex-xterm.log &", 10)
    _issue(machine, console, "4Dwm >& /tmp/trex-4dwm.log &", 10)
    if toolchest:
        _issue(machine, console, "toolchest -name ToolChest >& /tmp/trex-toolchest.log &", 8)
    return machine, console

def _fsn_media(distribution):
    if distribution == None:
        distribution = http_get(
            "https://ftp.zx.net.nz/pub/archive/ftp.sgi.com/sgi/fsn/fsn.tar.Z",
            maximum = 1 << 20,
        )
    if distribution.size != 215881 or hex(crypto.hash("sha256", distribution.read())) != "53ad2649c78798acd52f16fca2fde769d5df1f50645b496d8818f0ba76ab07ef":
        fail("Expected SGI's December 1996 ELF release of fsn.tar.Z")
    entries = archive.tar(archive.compress(distribution, maximum_bytes = 4 << 20), maximum_entries = 5).entries
    files = [{"path": entry.path.lstrip("/"), "mode": 0o100000 | entry.mode, "mtime": entry.mtime, "data": entry} for entry in entries]
    efs = filesystem.efs_build(files, 16 << 20, label = "fsn")
    return filesystem.sgi_build([(0, 7, efs)], swap = 0)

def start_fsn(source, distribution = None):
    """Launch SGI File System Navigator and scan the installed media sample tree."""
    machine, console = start_desktop(source, toolchest = False, data_disk = _fsn_media(distribution))
    console.write(b"mkdir -p /mnt; mount -t efs -o ro /dev/dsk/dks0d2s0 /mnt && /usr/etc/portmap && /usr/etc/inetd; echo FSN_READY=$status\r")
    ready = _wait(machine, console, "\nFSN_READY=", 65)
    if "\nFSN_READY=0\r\n" not in ready:
        fail("IRIX did not mount the fsn disk and start its File Alteration Monitor services", repr(ready))
    _issue(machine, console, "cd /mnt; setenv XAPPLRESDIR /mnt; /mnt/fsn /usr/share/data >& /tmp/trex-fsn.log &", 120)
    return machine, console

def click(machine, console, x, y):
    for _ in range(36):
        cursor = machine.graphics()
        # VC2 positions include the cursor glyph's offset from the pointer.
        dx, dy = x + 23 - cursor.cursor_x, cursor.cursor_y - (y + 24)
        if abs(dx) <= 2 and abs(dy) <= 2:
            machine.mouse(0, 0, buttons = 1)
            _advance(machine, console, 3600000)
            machine.mouse(0, 0)
            _advance(machine, console, 3600000)
            return
        machine.mouse(max(-18, min(18, dx)), max(-18, min(18, dy)))
        _advance(machine, console, 2200000)
    fail("Indy pointer did not reach", x, y)

def type_text(machine, console, text):
    shifted = "~!@#$%^&*()_+{}|:\"<>?"
    base = "\x601234567890-=[]\\;',./"
    for char in text.elems():
        index = shifted.find(char)
        key = "enter" if char == "\n" else (base[index] if index >= 0 else char.lower())
        shift = index >= 0 or ("A" <= char and char <= "Z")
        if shift:
            machine.key("shift")
        machine.key(key)
        machine.key(key, down = False)
        if shift:
            machine.key("shift", down = False)
        _advance(machine, console, 950000)
        if char == "\n":
            _advance(machine, console, 6000000)

def _rgb_hash(screen, x, y, width, height):
    pixels = [screen.pixel(px, py) for py in range(y, y + height) for px in range(x, x + width)]
    return hex(crypto.hash("sha256", bytes([v for p in pixels for v in [p.r, p.g, p.b]])))

def _verify(frame, regions):
    # Match the rendered application content. Hash RGB so the test is
    # independent of PNG encoding and unrelated redraws elsewhere.
    screen = image.decode(frame)
    for label, x, y, width, height, expected in regions:
        actual = _rgb_hash(screen, x, y, width, height)
        if actual != expected:
            fail("IRIX application content did not render", label, actual)

def _desktop_regions():
    return [
        ("Calculator result 5", 179, 181, 22, 20, "afe2351d19166d390ee6ddefe4086fca8b8db4416583f9a8257451dd03746bc7"),
        ("Terminal output from uname -aR", 512, 94, 425, 15, "4895d237c6d3234cc8d7172f503f1e5c6f2c5109184cd7b3597c98c817c32dd0"),
        ("Text editor displaying /etc/fstab", 34, 616, 355, 18, "c3f6e850410c61acbc7dce9dfc5d847960cda400ae8459a0b32f9c2c1ae8b3f7"),
        ("Font selector sample glyphs", 972, 579, 166, 49, "888b7054937ec368c8af935d451f9ecf787421954ce0390a57068cbc5db02079"),
        ("Clock date", 1001, 63, 81, 17, "55f0c400f14b542f2c3c358883176e9c6bb7ab99250bf0f19da31933a8a85908"),
        ("Toolchest title", 28, 11, 75, 18, "a4bb47a832771b2850382d567fc0844ba365285d30b184760c708a2ea82ecc8d"),
    ]

def verify_constructed_desktop(machine, console, output):
    """Verify the media-built root and calculate 2 + 3 in the stock desktop."""
    console.write(b"uname -aR; devnm /; mount; xwininfo -name 'IRIX Terminal' | grep IsViewable; echo SYSTEM_READY\r")
    readiness = _wait(machine, console, "\nSYSTEM_READY\r\n", 70)
    for proof in ["6.5 6.5.22m 10070055 IP22", "/dev/dsk/dks0d1s1 /", "on / type xfs (rw", "Map State: IsViewable"]:
        if proof not in readiness:
            fail("Media-built IRIX desktop startup", proof, repr(readiness))
    _issue(machine, console, "xcalc -geometry +35+169 >& /tmp/trex-xcalc.log &", 25)
    click(machine, console, 500, 146)
    type_text(machine, console, "clear\nuname -aR\ndevnm /\n")
    for x, y in [(137, 366), (209, 365), (173, 368), (207, 388)]:
        click(machine, console, x, y)
    _advance(machine, console, 60000000)
    console.write(b"xwininfo -name Toolchest | grep IsViewable; echo TOOLCHEST_READY\r")
    readiness = _wait(machine, console, "\nTOOLCHEST_READY\r\n", 30)
    if "Map State: IsViewable" not in readiness:
        fail("Toolchest did not map on the media-built system", repr(readiness))
    frame = machine.screenshot()
    _verify(frame, [_desktop_regions()[0]])
    write(output, frame)

def _image_smoke(source, output):
    machine, console = start_desktop(source, toolchest = False)
    _issue(machine, console, "imgview /usr/share/data/images/TestPattern.rgb &", 66)
    _issue(machine, console, "xlogo -geometry 144x144+867+704 &", 7)
    _issue(machine, console, "xmessage -geometry 280x100+620+840 'IRIX X11 Message' &", 16)
    frame = machine.screenshot()
    _verify(frame, [
        ("ImageView displaying the archived 320x240 test pattern", 71, 73, 320, 240, "fac7b77c707e403a484cc753597638d3d72ca729e76431bc601ee746275cc1d1"),
        ("X Logo geometry", 882, 713, 116, 77, "0b078fa475f73c944b46c7ed3778044352284f6f5f41d6263dd34192bb7c6e25"),
        ("Xmessage text", 637, 865, 164, 23, "f55277184ad86b79e28009983fadf971b262d8ea6867ffbee4b077d6624d2ae1"),
    ])
    click(machine, console, 655, 925)
    _advance(machine, console, 18000000)
    screen = image.decode(machine.screenshot())
    message, background = screen.pixel(681, 876), screen.pixel(605, 876)
    if (message.r, message.g, message.b) != (background.r, background.g, background.b):
        fail("Xmessage did not dismiss after clicking Okay")
    write(output, frame)
    machine.close()
    print("IRIX 6.5.22f ImageView, X Logo, and Xmessage verified")

def _window_position(machine, console, title, wait = False):
    probe = "xwininfo -name"
    if wait:
        probe = "/sbin/sh -c 'until xwininfo -name \"$1\" 2>/dev/null; do sleep 1; done' trex"
    console.write(bytes(probe + " '" + title + "'; echo WINDOW_DONE\r"))
    transcript = _wait(machine, console, "\nWINDOW_DONE\r\n", 330 if wait else 64)
    if "Map State: IsViewable" not in transcript:
        fail("IRIX window did not map", title, repr(transcript))
    positions = {}
    for line in transcript.splitlines():
        name, _, value = line.strip().partition(":")
        if name in ["Absolute upper-left X", "Absolute upper-left Y"]:
            positions[name[-1]] = int(value.strip())
    if len(positions) != 2:
        fail("Unable to read position of IRIX window", title, repr(transcript))
    # X client coordinates exclude the eight-pixel left border in REX3 scanout.
    return positions["X"] + 8, positions["Y"]

def _movie_smoke(source, output):
    machine, console = start_desktop(source, toolchest = False)
    _issue(machine, console, "mediaplayer /usr/share/data/movies/sampleQT.mov &", 68)
    x, y = _window_position(machine, console, "sampleQT.mov")
    still = image.decode(machine.screenshot())
    start = _rgb_hash(still, x + 34, y + 54, 136, 135)
    if start != "2b9f00050c228c6a779da4b67f1afe1abce1541c1980f9477a5be31511734b2d":
        fail("Media Player did not render the first frame of sampleQT.mov", start)
    clock = _rgb_hash(still, x + 6, y + 240, 54, 28)
    click(machine, console, x + 151, y + 255)
    _advance(machine, console, 285000000)
    frame = machine.screenshot()
    playing = image.decode(frame)
    if _rgb_hash(playing, x + 34, y + 54, 136, 135) == start or _rgb_hash(playing, x + 6, y + 240, 54, 28) == clock:
        fail("Media Player did not advance its frame and time after clicking Play")
    write(output, frame)
    machine.close()
    print("IRIX 6.5.22f Media Player QuickTime playback verified")

def _file_smoke(source, output):
    machine, console = start_desktop(source, toolchest = False)
    _issue(machine, console, "/usr/etc/portmap; /usr/etc/inetd; fm -b >& /tmp/trex-fm.log &", 68)
    _issue(machine, console, "fm /usr >& /tmp/trex-fm-view.log &", 8)
    _issue(machine, console, "iconcatalog -geometry +810+130 >& /tmp/trex-catalog.log &", 76)
    click(machine, console, 1219, 35)
    click(machine, console, 1219, 35)
    _advance(machine, console, 420000000)
    root_x, root_y = _window_position(machine, console, "/")
    catalog_x, catalog_y = _window_position(machine, console, "Icon Catalog: Applications (Page 1 of 10)")
    frame = machine.screenshot()
    _verify(frame, [
        ("File Manager CDROM folder in the root directory", root_x + 422, root_y + 99, 81, 74, "6f6dbd1c8c7bd5fbe252d0165195c452fb2f3c23c1cf9470595c34fa0eec499f"),
        ("Icon Catalog NEdit application entry", catalog_x + 360, catalog_y + 118, 76, 80, "a066390b72c5e4ad401c0f41ebe78e728e1bee82cbc0c5d8c0d9496549dd7b68"),
    ])
    write(output, frame)
    machine.close()
    print("IRIX 6.5.22f File Manager root view and Icon Catalog verified")

def _browser_smoke(source, output):
    machine, console = start_desktop(source, toolchest = False)
    _issue(machine, console, "/usr/etc/portmap; /usr/etc/inetd; /usr/etc/nsd", 38)
    console.write(b"setenv XAPPLRESDIR /usr/lib/X11/app-defaults; setenv XFILESEARCHPATH '/usr/lib/X11/app-defaults/%N'\r")
    _wait(machine, console, "# ", 12)
    console.write(b"xrdb -merge /usr/lib/X11/app-defaults/Netscape >& /tmp/trex-xrdb.log; echo NETSCAPE_RESOURCES\r")
    _wait(machine, console, "\nNETSCAPE_RESOURCES\r\n", 180)
    _issue(machine, console, "netscape file:///usr/share/Insight/library/SGI_bookshelves/index.html >& /tmp/trex-netscape.log &", 8)
    x, y = _window_position(machine, console, "Netscape: SGI Desktop Techpubs Library: List of Bookshelves", wait = True)
    click(machine, console, x + 78, y + 297)
    x, y = _window_position(machine, console, "Netscape: SGI Desktop Techpubs Library: End-User", wait = True)
    frame = machine.screenshot()
    _verify(frame, [
        ("Netscape rendering the local End-User bookshelf", x + 7, y + 234, 375, 25, "fd2d8df06247545b1aeaa5666c6c605ae92ab7feb6ed0066b26c95991dd20fe2"),
    ])
    write(output, frame)
    machine.close()
    print("IRIX 6.5.22f Netscape navigation through the archived SGI bookshelf verified")

def _fsn_smoke(source, output, distribution):
    machine, console = start_fsn(source, distribution)
    _verify(machine.screenshot(), [
        ("fsn's 12-bit sky colors", 315, 150, 54, 165, "25844e113be5ab1f02d9d309093467d7a0bb04950a26a5b370a725a7d7d90835"),
        ("File pedestals in the archived media tree", 446, 571, 161, 77, "ce8361df820d661c13f06955f534cfaf1ed55a185ad60179f369e323faf2f4e1"),
    ])
    click(machine, console, 166, 380)
    type_text(machine, console, "images")
    click(machine, console, 88, 520)
    _advance(machine, console, 200000000)
    _verify(machine.screenshot(), [
        ("fsn reports one search match", 55, 335, 130, 22, "b5dcdd2e3293bde40db65f178ee989aa0433061673718fd5df6db8ae77e6d3b0"),
    ])
    click(machine, console, 405, 648)
    _advance(machine, console, 240000000)
    frame = machine.screenshot()
    _verify(frame, [
        ("Selected images directory path", 312, 85, 175, 20, "6b26d6883d7dca7cc7752fcb378e90f1e5fd73432c66f139fbb0df723235b3ec"),
        ("The zoomed filesystem scene labels TestPattern.rgb", 531, 562, 106, 19, "b0a3c0d6ecd393ceec22ef1bd92b0da5a2861c4b8d07817feaf2d1aaa1c1eb9c"),
    ])
    write(output, frame)
    machine.close()
    print("IRIX 6.5.22f fsn rendered the media tree, found images, and zoomed to the selected directory")

def main(args):
    if len(args) in [3, 4] and args[2] == "fsn":
        _fsn_smoke(open(args[0]), args[1], open(args[3]) if len(args) == 4 else None)
        return
    modes = {"image": _image_smoke, "movie": _movie_smoke, "files": _file_smoke, "browser": _browser_smoke}
    if len(args) == 3 and args[2] in modes:
        modes[args[2]](open(args[0]), args[1])
        return
    if len(args) != 2:
        fail("usage: irix_ip24_desktop.star IRIX_6.5.22_CHD DESKTOP.png [image|movie|files|browser|fsn [FSN_TAR_Z]]")
    machine, console = start_desktop(open(args[0]))
    _issue(machine, console, "xcalc -geometry +35+169 >& /tmp/trex-xcalc.log &", 8)
    console.write(b"xwininfo -name 'IRIX Terminal' | grep IsViewable; echo TERMINAL_READY\r")
    readiness = _wait(machine, console, "\nTERMINAL_READY\r\n", 22)
    if "Map State: IsViewable" not in readiness:
        fail("The graphical terminal did not map", repr(readiness))

    click(machine, console, 500, 146)
    type_text(machine, console, "xclock -digital -geometry 255x50+985+55 &\nxedit -geometry 470x235+29+505 /etc/fstab &\nxfontsel -geometry 350x140+870+494 &\nclear\nuname -aR\n")
    _advance(machine, console, 100000000)
    click(machine, console, 500, 148)
    type_text(machine, console, "xsetroot -solid sgilightblue\n")
    for x, y in [(137, 366), (209, 365), (173, 368), (207, 388)]:
        click(machine, console, x, y)

    frame = machine.screenshot()
    _verify(frame, _desktop_regions())
    write(args[1], frame)
    machine.close()
    print("IRIX 6.5.22f desktop verified")
    print("Toolchest, xterm uname, Calculator 2 + 3 = 5, Clock, xedit /etc/fstab, and Font Selector")
