"""Boot the IRIX Interactive Desktop on the native SGI Indy."""

load("//_trex_lab_irix:irix_ip24.star", "prepare")
load("//_trex_lab_irix:irix_ip24_system.star", "build_system", "start_system", "system_catalog")

def _disc_indy(media):
    lab_phase("preparing", "Reading the original IRIX 6.5.22 discs")
    catalog = system_catalog(media["foundation1"], media["foundation2"], media["overlay1"],
                             media["overlay2"], media["overlay3"], media["applications"])
    lab_phase("preparing", "Constructing the IRIX XFS system disk in memory")
    machine, _ = start_system(build_system(catalog, autoconfig = False), single_user = False)
    return machine

def _login_region(frame, x, y, width, height):
    pixels = [frame.pixel(xx, yy) for yy in range(y, y + height) for xx in range(x, x + width)]
    return hex(crypto.hash("sha256", bytes([v for pixel in pixels for v in [pixel.r, pixel.g, pixel.b]])))

def _prepare_indy(media):
    machine = _disc_indy(media)
    serial = machine.serial()
    lab_phase("preparing", "Booting the Indy to the SGI login screen")
    tail = ""
    for _ in range(350):
        stop = machine.run(20000000)
        output = serial.read_available()
        if output:
            tail = (tail + str(output))[-2048:]
        if stop.kind != "budget" or "PANIC:" in tail:
            fail("Indy template boot failed", stop.kind, tail)
        if machine.graphics().commands < 160000:
            continue
        screen = image.decode(machine.screenshot())
        # Check the Login name label and Log In button, away from the caret
        # and the user icons that finish drawing after the prompt is ready.
        if (_login_region(screen, 335, 695, 110, 26) == "882a3129d0323b7a704a89b1f879f871fc41490560350c6fc3389cdeca521d68" and
            _login_region(screen, 805, 808, 74, 30) == "e90686b27fdcb6fb8725f4d1afb4038e88ed61ae06ee65a0e114406f01f45306"):
            checkpoint = machine.checkpoint()
            machine.close()
            return checkpoint
    fail("Indy template did not reach the SGI login screen", tail)

def indy(kind, cfg, media, lan, mac, trust):
    if cfg["source"] == "installed":
        lab_phase("preparing", "Reading the installed IRIX disk and kernel")
        machine, _ = prepare(media["system"], "system", newport = True, single_user = False)
    else:
        checkpoint = lab_indy_checkpoint(lambda: _prepare_indy(media))
        if checkpoint == None:
            machine = _disc_indy(media)
        else:
            lab_phase("preparing", "Restoring the prepared Indy login screen")
            machine = checkpoint.restore()
            return {"vm": machine, "console": machine.serial(), "message": "Indy restored at the IRIX graphical login."}
    return {"vm": machine, "console": machine.serial(), "message": "Indy started. The IRIX graphical login appears after startup."}
