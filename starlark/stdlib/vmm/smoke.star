"""Framebuffer-based guest smoke automation for unmodified disk recipes."""

load(":automation.star", "checkpoint", "paced_chord", "paced_tap", "wait_duration")

def frame_delta(before, after, threshold = 8):
    """Returns bounded pixel-difference metrics for two framebuffer captures."""
    return image.compare(before, after, threshold = threshold)

def wait_for_stable_frame(
        vm,
        timeout = 30,
        stable_samples = 3,
        sample_interval = 1,
        maximum_changed_pixels = 250):
    """Returns after the framebuffer remains materially stable for several samples."""
    if stable_samples < 1 or timeout <= 0 or sample_interval <= 0:
        fail("invalid stable-frame wait")
    deadline = clock.monotonic() + timeout
    baseline = checkpoint(vm)
    dimensions = image.info(baseline)
    stable = 0
    while vm.running and clock.monotonic() < deadline:
        wait_duration(vm, min(sample_interval, max(0, deadline - clock.monotonic())))
        candidate = checkpoint(vm)
        candidate_dimensions = image.info(candidate)
        if candidate_dimensions.width != dimensions.width or candidate_dimensions.height != dimensions.height:
            stable = 0
        elif frame_delta(baseline, candidate).changed_pixels <= maximum_changed_pixels:
            stable += 1
            if stable >= stable_samples:
                return candidate
        else:
            stable = 0
        baseline = candidate
        dimensions = candidate_dimensions
    return baseline

def wait_for_display_mode(
        vm,
        minimum_width,
        minimum_height,
        timeout = 90,
        sample_interval = 1):
    """Waits for a framebuffer large enough to represent the guest UI mode."""
    if minimum_width < 1 or minimum_height < 1 or timeout <= 0 or sample_interval <= 0:
        fail("invalid display-mode wait")
    deadline = clock.monotonic() + timeout
    latest = checkpoint(vm)
    dimensions = image.info(latest)
    while vm.running and (dimensions.width < minimum_width or dimensions.height < minimum_height):
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            break
        wait_duration(vm, min(sample_interval, remaining))
        latest = checkpoint(vm)
        dimensions = image.info(latest)
    return {
        "detail": "%dx%d framebuffer" % (dimensions.width, dimensions.height),
        "image": latest,
        "passed": dimensions.width >= minimum_width and dimensions.height >= minimum_height,
    }

def wait_for_material_change(
        vm,
        before,
        timeout = 20,
        settle = 2,
        minimum_changed_pixels = 1500,
        sample_interval = 0.75):
    """Waits for a material framebuffer change which remains after settling.

    The returned dictionary always contains `passed`, `image`, `comparison`,
    and `detail`. Cursor blinking and tiny animation changes remain below the
    default changed-pixel threshold.
    """
    if timeout <= 0 or sample_interval <= 0 or settle < 0:
        fail("invalid framebuffer wait timing")
    if minimum_changed_pixels < 1:
        fail("minimum_changed_pixels must be positive")
    deadline = clock.monotonic() + timeout
    latest = before
    dimensions = image.info(before)
    comparison = frame_delta(before, latest)
    while vm.running:
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            break
        wait_duration(vm, min(sample_interval, remaining))
        latest = checkpoint(vm)
        latest_dimensions = image.info(latest)
        if latest_dimensions.width != dimensions.width or latest_dimensions.height != dimensions.height:
            before = latest
            dimensions = latest_dimensions
            comparison = frame_delta(before, latest)
            continue
        comparison = frame_delta(before, latest)
        if comparison.changed_pixels < minimum_changed_pixels:
            continue
        if settle:
            wait_duration(vm, min(settle, max(0, deadline - clock.monotonic())))
            latest = checkpoint(vm)
            latest_dimensions = image.info(latest)
            if latest_dimensions.width != dimensions.width or latest_dimensions.height != dimensions.height:
                before = latest
                dimensions = latest_dimensions
                comparison = frame_delta(before, latest)
                continue
            comparison = frame_delta(before, latest)
        if comparison.changed_pixels >= minimum_changed_pixels:
            return {
                "comparison": comparison,
                "detail": "%d pixels changed (%d ppm)" % (comparison.changed_pixels, comparison.changed_ppm),
                "image": latest,
                "passed": True,
            }
    detail = "VM exited before framebuffer response" if not vm.running else "no material framebuffer response before timeout"
    return {
        "comparison": comparison,
        "detail": detail,
        "image": latest,
        "passed": False,
    }

def _activate_command_surface(vm, launcher):
    """Activates a guest shell's command surface without entering text."""
    if launcher == "run_dialog":
        # Modern Windows handles QEMU's atomic chord reliably even when the
        # shell has just completed first-logon setup. Separate key events can
        # be consumed by that transition without ever dispatching Win+R.
        vm.chord(["meta_l", "r"])
        wait_duration(vm, 0.5)
    elif launcher == "start_menu":
        paced_chord(vm, ["control", "escape"])
        wait_duration(vm, 2)
        paced_tap(vm, "r")
        wait_duration(vm, 1)
    elif launcher == "program_manager":
        # NT 3.x polls the legacy keyboard path slowly enough to miss QEMU's
        # aggregate chord. Explicit transitions also match physical input.
        paced_chord(vm, ["alt", "f"], interval = 0.2, hold = 0.2)
        wait_duration(vm, 2)
        paced_tap(vm, "r", hold = 0.2)
        wait_duration(vm, 1)
    elif launcher != "console":
        fail("unsupported smoke command launcher %s" % launcher)

def enter_command(vm, command, launcher = "run_dialog"):
    """Enters a command through a supported guest shell surface."""
    _activate_command_surface(vm, launcher)
    _submit_command(vm, command)

def _submit_command(vm, command):
    """Types a command and submits it through a guest-visible Enter press."""
    vm.send_text(command)
    paced_tap(vm, "enter", hold = 0.2)

def _open_command_surface(
        vm,
        launcher,
        timeout = 5,
        minimum_changed_pixels = 1500,
        attempts = 3):
    """Opens a shell command surface without submitting a command.

    A launcher shortcut may be dropped while the desktop is still accepting
    queued startup input. Retrying this empty surface is safe because no guest
    command has been entered; command submission remains exactly once.
    """
    if attempts < 1:
        fail("command surface attempts must be positive")
    initial = checkpoint(vm)
    if launcher == "console":
        return {
            "attempts": 1,
            "before": initial,
            "command_surface": initial,
            "detail": "console command surface is active",
            "image": initial,
            "passed": True,
        }
    result = None
    for attempt in range(1, attempts + 1):
        before = checkpoint(vm)
        _activate_command_surface(vm, launcher)
        result = wait_for_material_change(
            vm,
            before,
            timeout = timeout,
            # A command surface is an intermediate modal UI. Legacy display
            # drivers can briefly expose its saved backing frame on a
            # subsequent capture, so require the settled frame only after
            # command submission.
            settle = 0,
            minimum_changed_pixels = minimum_changed_pixels,
        )
        result["attempts"] = attempt
        result["before"] = before
        result["command_surface"] = result["image"]
        if result["passed"]:
            result["detail"] = "command surface opened; " + result["detail"]
            return result
        if not vm.running:
            return result
        # Normalize a partially handled launcher sequence before retrying.
        paced_tap(vm, "escape")
        wait_duration(vm, 1)
    return result

def _capture_command_result(
        vm,
        command,
        before,
        command_surface,
        timeout,
        settle,
        minimum_changed_pixels):
    """Submits one command and captures its response without retrying it."""
    _submit_command(vm, command)
    result = wait_for_material_change(
        vm,
        command_surface,
        timeout = timeout,
        settle = settle,
        minimum_changed_pixels = minimum_changed_pixels,
    )
    if result["passed"]:
        before_dimensions = image.info(before)
        result_dimensions = image.info(result["image"])
        if before_dimensions.width != result_dimensions.width or before_dimensions.height != result_dimensions.height:
            result["detail"] = "framebuffer resolution changed during command launch"
            result["passed"] = False
        elif frame_delta(before, result["image"]).changed_pixels < minimum_changed_pixels:
            result = wait_for_material_change(
                vm,
                before,
                timeout = timeout,
                settle = settle,
                minimum_changed_pixels = minimum_changed_pixels,
            )
    result["command_surface"] = command_surface
    result["before"] = before
    result["command"] = command
    return result

def wait_for_frame_match(
        vm,
        expected,
        timeout = 12,
        stable_samples = 2,
        sample_interval = 0.75,
        maximum_changed_pixels = 2500):
    """Waits until the framebuffer returns close to an expected frame."""
    if stable_samples < 1 or timeout <= 0 or sample_interval <= 0:
        fail("invalid frame-match wait")
    deadline = clock.monotonic() + timeout
    expected_dimensions = image.info(expected)
    latest = checkpoint(vm)
    comparison = frame_delta(expected, latest)
    stable = 0
    while vm.running and clock.monotonic() < deadline:
        latest_dimensions = image.info(latest)
        if latest_dimensions.width == expected_dimensions.width and latest_dimensions.height == expected_dimensions.height:
            comparison = frame_delta(expected, latest)
            if comparison.changed_pixels <= maximum_changed_pixels:
                stable += 1
                if stable >= stable_samples:
                    return {
                        "comparison": comparison,
                        "detail": "returned to the command surface (%d pixels differ)" % comparison.changed_pixels,
                        "image": latest,
                        "passed": True,
                    }
            else:
                stable = 0
        else:
            stable = 0
        wait_duration(vm, min(sample_interval, max(0, deadline - clock.monotonic())))
        latest = checkpoint(vm)
    detail = "VM exited before returning to the command surface" if not vm.running else "active window did not close back to the command surface"
    return {"comparison": comparison, "detail": detail, "image": latest, "passed": False}

def launch_and_capture(
        vm,
        command,
        launcher = "run_dialog",
        timeout = 20,
        settle = 2,
        minimum_changed_pixels = 1500):
    """Launches one guest command and captures its settled visual result."""
    surface = _open_command_surface(
        vm,
        launcher,
        timeout = min(5, timeout),
        minimum_changed_pixels = minimum_changed_pixels,
    )
    if not surface["passed"]:
        surface["command"] = command
        surface["detail"] = "command surface did not open: " + surface["detail"]
        return surface
    return _capture_command_result(
        vm,
        command,
        surface["before"],
        surface["command_surface"],
        timeout,
        settle,
        minimum_changed_pixels,
    )

def close_and_verify(vm, before, expected = None, timeout = 12, minimum_changed_pixels = 750):
    """Closes the active guest window and verifies continued UI responsiveness."""
    if not vm.running:
        return {"passed": False, "detail": "VM exited before window close", "image": before}
    paced_chord(vm, ["alt", "f4"])
    if expected != None:
        return wait_for_frame_match(vm, expected, timeout = timeout)
    return wait_for_material_change(
        vm,
        before,
        timeout = timeout,
        settle = 1,
        minimum_changed_pixels = minimum_changed_pixels,
    )

def wait_for_command_surface(
        vm,
        command,
        launcher = "run_dialog",
        timeout = 90,
        attempt_timeout = 12,
        stable_samples = 3,
        minimum_changed_pixels = 1500,
        verify_close = False,
        minimum_width = 0,
        minimum_height = 0):
    """Waits for a stable guest frame, then submits the probe exactly once.

    Opening an empty command surface can be retried when it produces no visual
    response. Smoke automation never repeats the command itself after an
    ambiguous response.
    """
    deadline = clock.monotonic() + timeout
    if minimum_width or minimum_height:
        if minimum_width < 1 or minimum_height < 1:
            fail("both minimum framebuffer dimensions must be positive")
        display = wait_for_display_mode(vm, minimum_width, minimum_height, timeout = timeout)
        if not display["passed"]:
            return {
                "attempts": 0,
                "boot_image": display["image"],
                "command": command,
                "detail": "guest UI display mode was not reached: " + display["detail"],
                "image": display["image"],
                "passed": False,
            }
    before = wait_for_stable_frame(
        vm,
        timeout = max(1, deadline - clock.monotonic()),
        stable_samples = stable_samples,
    )
    surface_timeout = min(5, attempt_timeout)
    remaining = max(0, deadline - clock.monotonic())
    # Opening an empty launcher is safe to retry for the complete readiness
    # deadline. Command submission remains exactly once, after a launcher has
    # produced an observable framebuffer response.
    surface_attempts = max(1, int(remaining // (surface_timeout + 1)))
    surface = _open_command_surface(
        vm,
        launcher,
        timeout = surface_timeout,
        minimum_changed_pixels = minimum_changed_pixels,
        attempts = surface_attempts,
    )
    if surface["passed"]:
        result = _capture_command_result(
            vm,
            command,
            surface["before"],
            surface["command_surface"],
            attempt_timeout,
            2,
            minimum_changed_pixels,
        )
        result["attempts"] = surface["attempts"]
    else:
        result = surface
        result["command"] = command
        result["detail"] = "command surface did not open: " + result["detail"]
    result["attempts"] = result.get("attempts", 1)
    result["boot_image"] = before
    if result["passed"] and verify_close:
        closed = close_and_verify(vm, result["image"], expected = result["before"])
        result["close"] = closed
        if not closed["passed"]:
            result["detail"] += "; " + closed["detail"]
            result["passed"] = False
    return result
