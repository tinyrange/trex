"""Framebuffer-based guest smoke automation for unmodified disk recipes."""

load(":automation.star", "checkpoint", "paced_chord", "paced_tap", "release_modifiers", "wait_duration")

SMOKE_SCHEMA = "trex.smoke.v1"

def media(name, kind = "file", secret = False):
    """Declares one caller-supplied smoke input without opening it."""
    if not name or kind not in ["file", "iso", "archive", "disk", "directory", "value"]:
        fail("invalid smoke media declaration")
    return {"kind": kind, "name": name, "secret": secret}

def case(id, name, media = [], **fields):
    """Returns validated, ordinary case data for a smoke suite."""
    if not id or not name:
        fail("smoke case requires a non-empty id and name")
    if regexp.compile("[a-z0-9_-]").replace_all(id, ""):
        fail("smoke case id contains unsupported characters: " + id)
    declared = {}
    for item in media:
        if item["name"] in declared:
            fail("duplicate smoke media name " + item["name"])
        declared[item["name"]] = item
    result = dict(fields)
    result.update({"id": id, "name": name, "media": list(media)})
    return result

def check(name, passed, detail, image = "", reason = ""):
    """Returns one portable smoke assertion and optional evidence reference."""
    if not name:
        fail("smoke check requires a name")
    return {
        "detail": detail,
        "image": image,
        "name": name,
        "passed": bool(passed),
        "reason": reason if reason else ("passed" if passed else "failed"),
    }

def phase(name, started_at, finished_at, detail = "", counters = {}):
    """Returns one measured phase using the caller's portable clock values."""
    if not name or finished_at < started_at:
        fail("invalid smoke phase")
    return {
        "counters": dict(counters),
        "detail": detail,
        "finished_at": finished_at,
        "name": name,
        "seconds": finished_at - started_at,
        "started_at": started_at,
    }

def result(case, checks, phases, metrics = {}, evidence = []):
    """Returns one complete case result in the authoritative schema."""
    normalized = []
    for item in checks:
        value = dict(item)
        value["image"] = value.get("image", "")
        value["reason"] = value.get("reason", "passed" if value["passed"] else "failed")
        normalized.append(value)
    passed = len(normalized) > 0 and all([item["passed"] for item in normalized])
    failure_category = ""
    for item in normalized:
        if not item["passed"]:
            failure_category = item["reason"]
            break
    measurements = dict(metrics)
    if "runtime" not in measurements:
        stats = runtime.stats()
        measurements["runtime"] = {
            "cache_peak_retained_bytes": stats.cache_peak_retained_bytes,
            "heap_alloc_bytes": stats.heap_alloc_bytes,
            "heap_sys_bytes": stats.heap_sys_bytes,
            "runtime_sys_bytes": stats.runtime_sys_bytes,
            "total_allocated_bytes": stats.total_allocated_bytes,
        }
    evidence_records = []
    for item in evidence:
        if type(item) == "string":
            evidence_records.append({"kind": "file", "path": item, "source": case["id"]})
        else:
            evidence_records.append(dict(item))
    return {
        "checks": normalized,
        "evidence": evidence_records,
        "id": case["id"],
        "failure_category": failure_category,
        "metrics": measurements,
        "name": case["name"],
        "passed": passed,
        "phases": list(phases),
    }

def suite(run_id, cases, results, started_at, finished_at, metadata = {}, complete = True, supersedes = ""):
    """Validates and returns one authoritative multi-case smoke result."""
    if not run_id or finished_at < started_at:
        fail("invalid smoke suite identity or timing")
    expected = [item["id"] for item in cases]
    if len(expected) != len({name: True for name in expected}):
        fail("smoke suite contains duplicate case ids")
    actual = [item["id"] for item in results]
    if len(actual) != len({name: True for name in actual}):
        fail("smoke suite contains duplicate result ids")
    missing = sorted([name for name in expected if name not in actual])
    unexpected = sorted([name for name in actual if name not in expected])
    if (complete and missing) or unexpected:
        fail("smoke result set mismatch: missing=%s unexpected=%s" % (missing, unexpected))
    return {
        "finished_at": finished_at,
        "metadata": dict(metadata),
        "complete": complete,
        "expected_case_ids": expected,
        "passed": complete and all([item["passed"] for item in results]),
        "results": list(results),
        "run_id": run_id,
        "schema": SMOKE_SCHEMA,
        "seconds": finished_at - started_at,
        "started_at": started_at,
        "supersedes": supersedes,
    }

def encode_suite(value):
    """Encodes the authoritative suite model as deterministic indented JSON."""
    if value.get("schema") != SMOKE_SCHEMA:
        fail("unsupported smoke suite schema")
    return json.encode(value, indent = 2) + "\n"

def _seconds(value):
    milliseconds = int(value * 1000)
    fraction = str(milliseconds % 1000)
    while len(fraction) < 3:
        fraction = "0" + fraction
    return "%d.%s" % (milliseconds // 1000, fraction)

def _phase_seconds(result, name):
    matches = [item["seconds"] for item in result["phases"] if item["name"] == name]
    return matches[0] if matches else 0

def _total_phase_seconds(result):
    total = 0
    for item in result["phases"]:
        total += item["seconds"]
    return total

def render_suite(value, title = "Operating-system smoke report"):
    """Renders the authoritative suite value as a self-contained HTML report."""
    if value.get("schema") != SMOKE_SCHEMA:
        fail("unsupported smoke suite schema")
    passed = len([item for item in value["results"] if item["passed"]])
    complete = value.get("complete", True)
    run_status = "PASS" if complete and value["passed"] else ("FAIL" if complete else "IN PROGRESS")
    run_status_class = "pass" if run_status == "PASS" else ("fail" if run_status == "FAIL" else "pending")
    supersedes = value.get("supersedes", "")
    supersession = " · supersedes %s" % html.escape(supersedes) if supersedes else ""
    rows = []
    sections = []
    for result in value["results"]:
        status = "PASS" if result["passed"] else "FAIL"
        rows.append("<tr><td><a href=\"#%s\">%s</a></td><td class=\"%s\">%s</td><td>%ss</td><td>%ss</td></tr>" % (
            html.escape(result["id"]),
            html.escape(result["name"]),
            "pass" if result["passed"] else "fail",
            status,
            _seconds(_phase_seconds(result, "build")),
            _seconds(_total_phase_seconds(result)),
        ))
        check_rows = []
        evidence = []
        for item in result["checks"]:
            check_rows.append("<tr><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td></tr>" % (
                html.escape(item["name"]),
                "pass" if item["passed"] else "fail",
                "PASS" if item["passed"] else "FAIL",
                html.escape(item["reason"]),
                html.escape(item["detail"]),
            ))
            if item["image"]:
                image_name = path.base(item["image"])
                evidence.append("<figure><a href=\"%s\"><img loading=\"lazy\" src=\"%s\" alt=\"%s\"></a><figcaption>%s</figcaption></figure>" % (
                    html.escape(image_name), html.escape(image_name), html.escape(item["name"]), html.escape(item["name"]),
                ))
        phase_rows = ["<tr><td>%s</td><td>%ss</td><td>%s</td></tr>" % (
            html.escape(item["name"]), _seconds(item["seconds"]), html.escape(item["detail"]),
        ) for item in result["phases"]]
        sections.append("""
<section id="{id}"><div class="heading"><h2>{name}</h2><strong class="{status_class}">{status}</strong></div>
<h3>Checks</h3><table><thead><tr><th>Check</th><th>Status</th><th>Reason</th><th>Detail</th></tr></thead><tbody>{checks}</tbody></table>
<h3>Phases</h3><table><thead><tr><th>Phase</th><th>Duration</th><th>Detail</th></tr></thead><tbody>{phases}</tbody></table>
<div class="evidence">{evidence}</div></section>""".format(
            id = html.escape(result["id"]), name = html.escape(result["name"]),
            status_class = "pass" if result["passed"] else "fail", status = status,
            checks = "".join(check_rows), phases = "".join(phase_rows), evidence = "".join(evidence),
        ))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title><style>
:root{{font:15px system-ui,sans-serif;color:#202124;background:#f5f6f7}}*{{box-sizing:border-box}}body{{margin:0}}header,main{{max-width:1320px;margin:auto;padding:24px}}header{{background:#fff;border-bottom:1px solid #d8dbdf;max-width:none}}header>div{{max-width:1272px;margin:auto}}h1{{margin:0 0 6px}}h2{{margin:0}}h3{{margin:20px 0 8px}}section{{background:#fff;border:1px solid #d8dbdf;margin:0 0 20px;padding:20px}}.heading{{display:flex;justify-content:space-between;gap:16px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:8px;border-bottom:1px solid #e5e7ea;text-align:left;vertical-align:top}}.pass{{color:#176b3a}}.fail{{color:#a12424}}.pending{{color:#8a5b12}}.evidence{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:16px}}figure{{margin:0;border:1px solid #d8dbdf}}img{{display:block;width:100%}}figcaption{{padding:7px}}@media(max-width:700px){{main{{padding:10px}}section{{padding:10px;overflow-x:auto}}}}
</style></head><body><header><div><h1>{title}</h1><p>{passed} of {total} cases passed · run {run_id} · {_seconds}s</p></div></header>
<main><section><div class="heading"><h2>Summary</h2><strong class="{run_status_class}">{run_status}</strong></div><p>{completion}{supersession}</p><table><thead><tr><th>Operating system</th><th>Status</th><th>Build</th><th>Measured phases</th></tr></thead><tbody>{rows}</tbody></table></section>{sections}</main></body></html>""".format(
        title = html.escape(title), passed = passed, total = len(value["results"]),
        run_id = html.escape(value["run_id"]), _seconds = _seconds(value["seconds"]),
        run_status = run_status, run_status_class = run_status_class,
        completion = "Complete result set" if complete else "Partial result: %d of %d expected cases finished" % (len(value["results"]), len(value["expected_case_ids"])),
        supersession = supersession, rows = "".join(rows), sections = "".join(sections),
    )

def parse_suite_options(args, cases, extra_options = []):
    """Parses one shared name=value surface and validates selected case inputs."""
    options = {}
    for argument in args:
        parts = argument.split("=", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            fail("smoke arguments must use name=value syntax")
        if parts[0] in options:
            fail("duplicate smoke argument " + parts[0])
        options[parts[0]] = parts[1]
    if "output" not in options:
        fail("missing output=<value>")
    by_id = {item["id"]: item for item in cases}
    if "case" in options and "only" in options:
        fail("specify only one of case=<id,...> and only=<id,...>")
    selected = options.get("case", options.get("only", ",".join([item["id"] for item in cases]))).split(",")
    if not selected or any([not name for name in selected]):
        fail("only=<case,...> must select at least one case")
    unknown_cases = sorted([name for name in selected if name not in by_id])
    if unknown_cases:
        fail("unknown smoke cases: " + ", ".join(unknown_cases))
    if len(selected) != len({name: True for name in selected}):
        fail("smoke case selection contains duplicates")
    allowed = {name: True for name in ["case", "display", "memory_budget", "only", "output", "preflight", "repl", "supersedes"] + extra_options}
    missing = []
    for name in selected:
        for item in by_id[name]["media"]:
            allowed[item["name"]] = True
            if item["name"] not in options:
                missing.append(item["name"])
    unknown_options = sorted([name for name in options if name not in allowed])
    if unknown_options:
        fail("unknown smoke arguments: " + ", ".join(unknown_options))
    if missing:
        fail("missing smoke inputs: " + ", ".join(sorted(missing)))
    display = options.get("display", "none")
    if display not in ["none", "gtk", "sdl", "cocoa"]:
        fail("unsupported display frontend " + display)
    repl_value = options.get("repl", "false")
    if repl_value not in ["true", "false"]:
        fail("repl must be true or false")
    options["display"] = display
    options["repl"] = repl_value == "true"
    preflight_value = options.get("preflight", "false")
    if preflight_value not in ["true", "false"]:
        fail("preflight must be true or false")
    options["preflight"] = preflight_value == "true"
    memory_budget = int(options.get("memory_budget", str(16 << 30)))
    if memory_budget < 1:
        fail("memory_budget must be positive")
    options["memory_budget"] = memory_budget
    options["selected"] = selected
    return options

def _preflight_case(selected, options):
    issues = []
    input_sizes = {}
    for declaration in selected["media"]:
        kind = declaration["kind"]
        if kind not in ["directory", "value"]:
            source = open(options[declaration["name"]])
            input_sizes[declaration["name"]] = source.size
    validator = selected.get("preflight")
    if validator != None:
        issues = validator(selected, options)
    detail = "%d required input(s); declared memory %d bytes" % (len(selected["media"]), selected.get("memory", 0))
    if input_sizes:
        detail += "; opened " + ", ".join(["%s=%d" % (name, input_sizes[name]) for name in sorted(input_sizes)])
    if issues:
        detail += "; " + "; ".join(["%s: %s" % (item.code, item.message) for item in issues])
    return {"detail": detail, "issues": issues}

def run(cases, args, title = "Operating-system smoke report", metadata = {}, extra_options = []):
    """Runs selected case functions and incrementally writes JSON and HTML."""
    options = parse_suite_options(args, cases, extra_options = extra_options)
    selected_cases = [item for item in cases if item["id"] in options["selected"]]
    started_at = clock.monotonic()
    run_id = "%d-%d-%s" % (clock.unix(), int(started_at * 1000), path.base(options["output"]))
    supersedes = options.get("supersedes", "")
    for selected in selected_cases:
        required_memory = selected.get("memory", 0)
        if required_memory > options["memory_budget"]:
            fail("smoke case %s requires %d bytes, over memory_budget=%d" % (selected["id"], required_memory, options["memory_budget"]))
    preflight = []
    preflight_failures = []
    for selected in selected_cases:
        inspected = _preflight_case(selected, options)
        preflight.append(inspected)
        if inspected["issues"]:
            preflight_failures.append(selected["id"] + ": " + inspected["detail"])
    if preflight_failures:
        fail("smoke preflight failed: " + "; ".join(preflight_failures))
    if options["preflight"]:
        checked_at = clock.monotonic()
        preflight_results = []
        for index in range(len(selected_cases)):
            selected = selected_cases[index]
            inspected = preflight[index]
            preflight_results.append(result(
                selected,
                [check("Preflight", True, inspected["detail"], reason = "preflight")],
                [phase("preflight", started_at, checked_at)],
            ))
        final = suite(run_id, selected_cases, preflight_results, started_at, clock.monotonic(), metadata = metadata, supersedes = supersedes)
        write(options["output"] + "-report.json", encode_suite(final))
        write(options["output"] + "-report.html", render_suite(final, title = title + " preflight"))
        return final
    results = []
    for selected in selected_cases:
        operation = selected.get("run")
        if operation == None:
            fail("smoke case %s has no run function" % selected["id"])
        results.append(operation(selected, options))
        current = suite(run_id, selected_cases, results, started_at, clock.monotonic(), metadata = metadata, complete = False, supersedes = supersedes)
        write(options["output"] + "-report.json", encode_suite(current))
        write(options["output"] + "-report.html", render_suite(current, title = title))
    final = suite(run_id, selected_cases, results, started_at, clock.monotonic(), metadata = metadata, supersedes = supersedes)
    write(options["output"] + "-report.json", encode_suite(final))
    write(options["output"] + "-report.html", render_suite(final, title = title))
    failures = [item["name"] for item in results if not item["passed"]]
    if failures:
        fail("operating-system smoke failures: " + ", ".join(failures))
    return final

def _vm_state(vm):
    value = {
        "backend": vm.backend_id,
        "running": vm.running,
        "status": vm.status,
    }
    final = vm.result
    if final != None:
        value["result"] = {
            "clean": final.clean,
            "code": final.code,
            "detail": final.detail,
            "reason": final.reason,
        }
    return value

def _finish_action(result, started_at, reason = None, inputs = [], vm = None):
    """Adds the common bounded action fields without changing existing keys."""
    result["started_at"] = started_at
    result["duration"] = max(0, clock.monotonic() - started_at)
    result["reason"] = reason if reason != None else result.get("reason", "passed" if result.get("passed", False) else "failed")
    result["attempts"] = result.get("attempts", 1)
    result["input"] = list(inputs) + list(result.get("input", []))
    if vm != None:
        result["vm"] = _vm_state(vm)
    return result

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
    started_at = clock.monotonic()
    deadline = started_at + timeout
    latest = checkpoint(vm)
    dimensions = image.info(latest)
    while vm.running and (dimensions.width < minimum_width or dimensions.height < minimum_height):
        remaining = deadline - clock.monotonic()
        if remaining <= 0:
            break
        wait_duration(vm, min(sample_interval, remaining))
        latest = checkpoint(vm)
        dimensions = image.info(latest)
    passed = dimensions.width >= minimum_width and dimensions.height >= minimum_height
    return _finish_action({
        "detail": "%dx%d framebuffer" % (dimensions.width, dimensions.height),
        "image": latest,
        "passed": passed,
    }, started_at, reason = "display-mode" if passed else ("vm-exited" if not vm.running else "deadline"), vm = vm)

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
    started_at = clock.monotonic()
    deadline = started_at + timeout
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
            return _finish_action({
                "before": before,
                "comparison": comparison,
                "detail": "%d pixels changed (%d ppm)" % (comparison.changed_pixels, comparison.changed_ppm),
                "image": latest,
                "passed": True,
            }, started_at, reason = "material-frame-change", vm = vm)
    detail = "VM exited before framebuffer response" if not vm.running else "no material framebuffer response before timeout"
    return _finish_action({
        "before": before,
        "comparison": comparison,
        "detail": detail,
        "image": latest,
        "passed": False,
    }, started_at, reason = "vm-exited" if not vm.running else "deadline", vm = vm)

def _activate_command_surface(vm, launcher):
    """Activates a guest shell's command surface without entering text."""
    release_modifiers(vm)
    if launcher == "run_dialog":
        # Modern Windows handles QEMU's atomic chord reliably even when the
        # shell has just completed first-logon setup. Separate key events can
        # be consumed by that transition without ever dispatching Win+R.
        vm.chord(["meta_l", "r"])
        wait_duration(vm, 0.5)
        return ["chord:meta_l+r"]
    elif launcher == "start_menu":
        paced_chord(vm, ["control", "escape"])
        wait_duration(vm, 2)
        paced_tap(vm, "r")
        wait_duration(vm, 1)
        return ["chord:control+escape", "tap:r"]
    elif launcher == "program_manager":
        # NT 3.x polls the legacy keyboard path slowly enough to miss QEMU's
        # aggregate chord. Explicit transitions also match physical input.
        paced_chord(vm, ["alt", "f"], interval = 0.2, hold = 0.2)
        wait_duration(vm, 2)
        paced_tap(vm, "r", hold = 0.2)
        wait_duration(vm, 1)
        return ["chord:alt+f", "tap:r"]
    elif launcher != "console":
        fail("unsupported smoke command launcher %s" % launcher)
    return []

def enter_command(vm, command, launcher = "run_dialog"):
    """Enters a command through a supported guest shell surface."""
    _activate_command_surface(vm, launcher)
    _submit_command(vm, command)

def _submit_command(vm, command):
    """Types a command and submits it through a guest-visible Enter press."""
    vm.send_text(command)
    paced_tap(vm, "enter", hold = 0.2)
    return ["text:" + command, "tap:enter"]

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
    started_at = clock.monotonic()
    inputs = []
    release_modifiers(vm)
    inputs.append("release:modifiers")
    initial = checkpoint(vm)
    if launcher == "console":
        return _finish_action({
            "attempts": 1,
            "before": initial,
            "command_surface": initial,
            "detail": "console command surface is active",
            "image": initial,
            "passed": True,
        }, started_at, reason = "command-surface", inputs = inputs, vm = vm)
    result = None
    for attempt in range(1, attempts + 1):
        before = checkpoint(vm)
        inputs.extend(_activate_command_surface(vm, launcher))
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
            return _finish_action(result, started_at, reason = "command-surface", inputs = inputs, vm = vm)
        if not vm.running:
            return _finish_action(result, started_at, reason = "vm-exited", inputs = inputs, vm = vm)
        # Normalize a partially handled launcher sequence before retrying.
        paced_tap(vm, "escape")
        inputs.append("tap:escape")
        release_modifiers(vm)
        inputs.append("release:modifiers")
        wait_duration(vm, 1)
    return _finish_action(result, started_at, reason = "deadline", inputs = inputs, vm = vm)

def _capture_command_result(
        vm,
        command,
        before,
        command_surface,
        timeout,
        settle,
        minimum_changed_pixels):
    """Submits one command and captures its response without retrying it."""
    started_at = clock.monotonic()
    inputs = _submit_command(vm, command)
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
    return _finish_action(result, started_at, inputs = inputs, vm = vm)

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
    started_at = clock.monotonic()
    deadline = started_at + timeout
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
                    return _finish_action({
                        "comparison": comparison,
                        "detail": "returned to the command surface (%d pixels differ)" % comparison.changed_pixels,
                        "image": latest,
                        "passed": True,
                    }, started_at, reason = "frame-match", vm = vm)
            else:
                stable = 0
        else:
            stable = 0
        wait_duration(vm, min(sample_interval, max(0, deadline - clock.monotonic())))
        latest = checkpoint(vm)
    detail = "VM exited before returning to the command surface" if not vm.running else "active window did not close back to the command surface"
    return _finish_action(
        {"comparison": comparison, "detail": detail, "image": latest, "passed": False},
        started_at,
        reason = "vm-exited" if not vm.running else "deadline",
        vm = vm,
    )

def launch_and_capture(
        vm,
        command,
        launcher = "run_dialog",
        timeout = 20,
        settle = 2,
        minimum_changed_pixels = 1500):
    """Launches one guest command and captures its settled visual result."""
    started_at = clock.monotonic()
    surface = _open_command_surface(
        vm,
        launcher,
        timeout = min(5, timeout),
        minimum_changed_pixels = minimum_changed_pixels,
    )
    if not surface["passed"]:
        surface["command"] = command
        surface["detail"] = "command surface did not open: " + surface["detail"]
        return _finish_action(surface, started_at, reason = surface["reason"], vm = vm)
    result = _capture_command_result(
        vm,
        command,
        surface["before"],
        surface["command_surface"],
        timeout,
        settle,
        minimum_changed_pixels,
    )
    return _finish_action(result, started_at, inputs = surface["input"], vm = vm)

def close_and_verify(vm, before, expected = None, timeout = 12, minimum_changed_pixels = 750):
    """Closes the active guest window and verifies continued UI responsiveness."""
    started_at = clock.monotonic()
    if not vm.running:
        return _finish_action(
            {"passed": False, "detail": "VM exited before window close", "image": before},
            started_at,
            reason = "vm-exited",
            vm = vm,
        )
    release_modifiers(vm)
    paced_chord(vm, ["alt", "f4"])
    if expected != None:
        result = wait_for_frame_match(vm, expected, timeout = timeout)
    else:
        result = wait_for_material_change(
            vm,
            before,
            timeout = timeout,
            settle = 1,
            minimum_changed_pixels = minimum_changed_pixels,
        )
    return _finish_action(result, started_at, inputs = ["chord:alt+f4"], vm = vm)

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
    started_at = clock.monotonic()
    deadline = started_at + timeout
    if minimum_width or minimum_height:
        if minimum_width < 1 or minimum_height < 1:
            fail("both minimum framebuffer dimensions must be positive")
        display = wait_for_display_mode(vm, minimum_width, minimum_height, timeout = timeout)
        if not display["passed"]:
            return _finish_action({
                "attempts": 0,
                "boot_image": display["image"],
                "command": command,
                "detail": "guest UI display mode was not reached: " + display["detail"],
                "image": display["image"],
                "passed": False,
            }, started_at, reason = display["reason"], vm = vm)
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
    return _finish_action(result, started_at, vm = vm)
