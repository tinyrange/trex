"""Fresh-image ReactOS desktop/version/application smoke using caller media."""
load("@stdlib//windows/reactos:image.star", "reactos_disk")
load("@stdlib//qemu:profiles.star", "reactos")
load("@stdlib//vmm:automation.star", "paced_chord", "wait_duration")
load("@stdlib//vmm:smoke.star", "close_and_verify", "wait_for_command_surface", "launch_and_capture", smoke_case = "case", smoke_media = "media", smoke_phase = "phase", smoke_result = "result", smoke_run = "run")

def _build_reactos(source, unused):
    return reactos_disk(source)

_CONFIG = {
    "builder": _build_reactos, "expected_product": "ReactOS", "launcher": "run_dialog",
    "license": "winver.exe", "license_check_name": "Guest version", "license_model": "not_applicable",
    "memory": 512 << 20, "minimum_boot": 35, "name": "ReactOS", "profile": reactos,
    "programs": [
        ("Notepad", "notepad.exe", "system32/notepad.exe"),
        ("Calculator", "calc.exe", "system32/calc.exe"),
        ("Minesweeper", "winmine.exe", "system32/winmine.exe"),
    ],
    "slug": "reactos", "system_root": "/ReactOS", "volume": "fat",
}

def _offline_inspection(case, disk):
    volume = filesystem.fat(filesystem.mbr(disk).partitions[0].file)
    software = windows.hive(volume["/ReactOS/system32/config/SOFTWARE"])
    product = software["/Microsoft/Windows NT/CurrentVersion"].values.get("ProductName", "")
    logon = software["/Microsoft/Windows NT/CurrentVersion/Winlogon"].values
    shell = logon.get("Shell", "")
    user = logon.get("DefaultUserName", "")
    sam = windows.hive(volume["/ReactOS/system32/config/SAM"])
    rid = sam["/SAM/Domains/Account/Users/Names"].values.get(user)
    account_ok = rid != None
    if account_ok:
        account = sam["/SAM/Domains/Account/Users/" + hex(binary.u32be(rid)).upper()].values
        account_ok = account["NTPwd"] == crypto.hash("md4", binary.encode(logon.get("DefaultPassword", ""), encoding = "utf16le"))
    profile_path = "/Documents and Settings/" + user + "/NTUSER.DAT"
    profile_ok = profile_path in volume
    if profile_ok:
        profile = windows.hive(volume[profile_path])
        profile_ok = profile["/Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders"].values["Desktop"] == "C:\\Documents and Settings\\" + user + "\\Desktop"
    return {
        "passed": "reactos" in product.lower() and shell == "explorer.exe" and account_ok and profile_ok and "/ReactOS/system32/agent-register.cmd" not in volume,
        "detail": product + "; native registration; autologon account " + user + (" and profile coherent" if account_ok and profile_ok else " or profile inconsistent"),
        "pagefile": None,
        "programs": {name: "/ReactOS/" + relative in volume for name, unused, relative in case["programs"]},
    }

def _offline_check_name(case):
    return "Generated product identity"

def _backend(case, display_frontend = "none"):
    return reactos(accelerator = "kvm", block_transport = "nbd", display_frontend = display_frontend, network = False, no_reboot = True)

def _write_evidence(prefix, slug, phase, capture):
    filename = "%s-%s-%s.png" % (prefix, slug, phase)
    write(filename, capture)
    return filename

def _runtime_fields(value):
    return {
        "decompressed_bytes": value.decompressed_bytes,
        "nbd_read_bytes": value.nbd_read_bytes,
        "nbd_write_bytes": value.nbd_write_bytes,
        "source_read_bytes": value.source_read_bytes,
        "streamed_bytes": value.streamed_bytes,
    }

def _memory_fields(value):
    return {
        "cache_peak_retained_bytes": value.cache_peak_retained_bytes,
        "heap_alloc_bytes": value.heap_alloc_bytes,
        "heap_sys_bytes": value.heap_sys_bytes,
        "runtime_sys_bytes": value.runtime_sys_bytes,
        "total_allocated_bytes": value.total_allocated_bytes,
    }

def _runtime_delta(before, after):
    return {name: after[name] - before[name] for name in before}

def _vm_exit_detail(vm):
    """Returns the backend termination reason after an unexpected guest exit."""
    status = vm.status
    if status != "stopped":
        return "VM status is " + status
    result = vm.wait(timeout = 2)
    detail = result.reason + " (exit code %d)" % result.code
    if result.detail:
        detail += ": " + result.detail
    return detail

def _smoke_case(case, media_path, product_key, prefix, display = "none"):
    print("SMOKE", case["name"], "building")
    started = clock.monotonic()
    initial_stats = runtime.stats()
    runtime_before = _runtime_fields(initial_stats)
    disk = case["builder"](open(media_path), product_key)
    built = clock.monotonic()
    offline = _offline_inspection(case, disk)
    inspected = clock.monotonic()
    phases = [
        smoke_phase("build", started, built),
        smoke_phase("offline-inspection", built, inspected, detail = offline["detail"]),
    ]
    checks = [{"detail": offline["detail"], "image": "", "name": _offline_check_name(case), "passed": offline["passed"]}]
    if offline["pagefile"] != None:
        checks.append({"detail": offline["pagefile"]["detail"], "image": "", "name": "Generated pagefile", "passed": offline["pagefile"]["passed"]})
    machine = vmm.machine(
        architecture = case.get("architecture", "x86_64" if case["slug"] == "validationos" else "i386"),
        memory = case["memory"],
        cpus = case.get("cpus", 1),
        disks = [vmm.disk(disk, bus = "ide", unit = case.get("disk_unit", -1), snapshot = True)],
        display = vmm.display("interactive" if display != "none" else "capturable"),
        required_capabilities = ["disk.snapshot", "input.key", "input.text", "screenshot"],
    )
    vm_starting = clock.monotonic()
    vm = vmm.start(machine, _backend(case, display_frontend = display))
    vm_started = clock.monotonic()
    phases.append(smoke_phase("vm-start", vm_starting, vm_started))
    minimum_started = clock.monotonic()
    wait_duration(vm, case["minimum_boot"])
    phases.append(smoke_phase("minimum-boot-guard", minimum_started, clock.monotonic()))
    for unused in range(case.get("dismiss_startup_windows", 0)):
        if not vm.running:
            break
        dismiss_key = case.get("dismiss_startup_key", "")
        if dismiss_key:
            vm.tap(dismiss_key)
        else:
            vm.chord(["alt", "f4"])
        wait_duration(vm, 2)
    minimum_pixels = 300 if case["launcher"] == "console" else 1500
    probe_command = case.get("probe", case["programs"][0][1])
    readiness_started = clock.monotonic()
    readiness = wait_for_command_surface(
        vm,
        probe_command,
        launcher = case["launcher"],
        timeout = case.get("boot_timeout", 90),
        attempt_timeout = 15,
        stable_samples = case.get("readiness_stable_samples", 3),
        minimum_changed_pixels = minimum_pixels,
        verify_close = False,
        minimum_width = case.get("minimum_width", 0 if case["launcher"] == "console" else 800),
        minimum_height = case.get("minimum_height", 0 if case["launcher"] == "console" else 600),
    )
    phases.append(smoke_phase("desktop-readiness", readiness_started, clock.monotonic(), detail = readiness["detail"], counters = {"attempts": readiness["attempts"]}))
    boot_image = _write_evidence(prefix, case["slug"], "boot", readiness["boot_image"])
    license_command = case.get("license")
    license_result = None
    if license_command != None and readiness["passed"] and vm.running:
        if case["launcher"] != "console":
            paced_chord(vm, ["alt", "f4"])
            wait_duration(vm, 2)
        if vm.running:
            license_started = clock.monotonic()
            license_result = launch_and_capture(
                vm,
                license_command,
                launcher = case["launcher"],
                timeout = 25,
                settle = case.get("license_settle", 2),
                minimum_changed_pixels = minimum_pixels,
            )
            phases.append(smoke_phase("license-check", license_started, clock.monotonic(), detail = license_result["detail"], counters = {"attempts": license_result["attempts"]}))
    checks.append({
        "detail": "%s after %d command-surface attempt(s); %s" % (readiness["detail"], readiness["attempts"], _vm_exit_detail(vm)),
        "image": boot_image,
        "name": "Boot and interactive shell",
        "passed": readiness["passed"] and vm.running,
    })
    if license_command != None:
        if license_result == None:
            license_result = {
                "detail": "skipped because the guest shell was unavailable",
                "image": readiness["image"],
                "passed": False,
            }
        license_image = _write_evidence(prefix, case["slug"], "license", license_result["image"])
        checks.append({
            "detail": license_result["detail"],
            "image": license_image,
            "name": case["license_check_name"],
            "passed": offline["passed"] and readiness["passed"] and license_result["passed"] and vm.running,
        })
    elif readiness["passed"] and vm.running and case["launcher"] != "console":
        # The readiness probe launches the first real application. Cases with
        # a licensing probe close it as part of the transition to that probe;
        # identity-only cases need the same normalization before their next
        # Run dialog, otherwise the modal surface can open behind the probe.
        close_and_verify(vm, readiness["image"])
    if license_result != None and vm.running and case["launcher"] != "console" and license_result["passed"] and case.get("license_close", True):
        close_and_verify(vm, license_result["image"])
    elif license_result != None and vm.running and case["launcher"] != "console" and license_result["passed"]:
        wait_duration(vm, case.get("license_post_wait", 5))
    pagefile_command = case.get("pagefile")
    if pagefile_command != None:
        pagefile_result = None
        if readiness["passed"] and vm.running:
            pagefile_started = clock.monotonic()
            pagefile_result = launch_and_capture(
                vm,
                pagefile_command,
                launcher = case["launcher"],
                timeout = 30,
                settle = 15,
                minimum_changed_pixels = minimum_pixels,
            )
            phases.append(smoke_phase("pagefile-check", pagefile_started, clock.monotonic(), detail = pagefile_result["detail"], counters = {"attempts": pagefile_result["attempts"]}))
        if pagefile_result == None:
            pagefile_result = {"detail": "skipped because the guest shell was unavailable", "image": readiness["image"], "passed": False}
        pagefile_image = _write_evidence(prefix, case["slug"], "pagefile", pagefile_result["image"])
        checks.append({
            "detail": pagefile_result["detail"],
            "image": pagefile_image,
            "name": "Guest pagefile status",
            "passed": offline["pagefile"]["passed"] and pagefile_result["passed"] and vm.running,
        })
        if pagefile_result["passed"] and vm.running and case["launcher"] != "console":
            close_and_verify(vm, pagefile_result["image"])
    for index in range(len(case["programs"])):
        name, command, unused = case["programs"][index]
        present = offline["programs"].get(name, False)
        if not readiness["passed"] or not vm.running:
            checks.append({"detail": "skipped because the guest shell was unavailable", "image": "", "name": name, "passed": False})
            continue
        program_started = clock.monotonic()
        launched = launch_and_capture(
            vm,
            command,
            launcher = case["launcher"],
            timeout = 20,
            settle = 3,
            minimum_changed_pixels = minimum_pixels,
        )
        program_image = _write_evidence(prefix, case["slug"], "program-%d" % (index + 1), launched["image"])
        responsive = {"passed": vm.running, "detail": "console remained responsive"}
        if case["launcher"] != "console" and launched["passed"]:
            responsive = close_and_verify(vm, launched["image"])
        detail = "%s; executable %s; %s" % (
            launched["detail"],
            "present" if present else "missing",
            responsive["detail"],
        )
        checks.append({
            "detail": detail,
            "image": program_image,
            "name": "Run " + name,
            "passed": present and launched["passed"] and responsive["passed"] and vm.running,
        })
        phases.append(smoke_phase("program-%d" % (index + 1), program_started, clock.monotonic(), detail = detail, counters = {"attempts": launched["attempts"]}))
    block_stats = qemu.extension(vm).block_stats()[0]
    teardown_started = clock.monotonic()
    if vm.status != "stopped":
        vm.stop(timeout = 10)
    # QEMU exits promptly after `quit`, but a WIM-backed NBD request already in
    # flight may still be completing while the transport drains. Keep teardown
    # bounded without turning that cleanup latency into a false guest failure.
    vm.wait(timeout = case.get("teardown_timeout", 120))
    vm.close()
    finished = clock.monotonic()
    phases.append(smoke_phase("teardown", teardown_started, finished))
    passed = True
    for check in checks:
        if not check["passed"]:
            passed = False
    final_stats = runtime.stats()
    runtime_after = _runtime_fields(final_stats)
    schema_case = {"id": case["slug"], "name": case["name"]}
    value = smoke_result(schema_case, checks, phases, metrics = {
        "block": {
            "command_errors": block_stats.command_errors,
            "last_error": block_stats.last_error,
            "read_bytes": block_stats.read_bytes,
            "reads": block_stats.reads,
            "write_bytes": block_stats.write_bytes,
            "writes": block_stats.writes,
        },
        "runtime": _runtime_delta(runtime_before, runtime_after),
        "memory": _memory_fields(final_stats),
    })
    value.update({
        "block": {
            "command_errors": block_stats.command_errors,
            "last_error": block_stats.last_error,
            "read_bytes": block_stats.read_bytes,
            "reads": block_stats.reads,
            "write_bytes": block_stats.write_bytes,
            "writes": block_stats.writes,
        },
        "build_seconds": built - started,
        "id": case["slug"],
        "name": case["name"],
        "passed": passed,
        "phases": phases,
        "runtime": _runtime_delta(runtime_before, runtime_after),
        "slug": case["slug"],
        "total_seconds": finished - started,
    })
    return value

def _case_runner(config):
    def execute(unused_case, options):
        return _smoke_case(
            config,
            options[config["slug"]],
            options.get(config["slug"] + "_product_key", ""),
            options["output"],
            display = options["display"],
        )
    return execute

def _case_preflight(config):
    def validate(unused_case, options):
        placeholder = binary.extents(size = 512, extents = [])
        machine = vmm.machine(
            architecture = config.get("architecture", "x86_64" if config["slug"] == "validationos" else "i386"),
            memory = config["memory"],
            cpus = config.get("cpus", 1),
            disks = [vmm.disk(placeholder, bus = "ide", unit = config.get("disk_unit", -1), snapshot = True)],
            display = vmm.display("interactive" if options["display"] != "none" else "capturable"),
            required_capabilities = ["disk.snapshot", "input.key", "input.text", "screenshot"],
        )
        return vmm.validate(machine, _backend(config, display_frontend = options["display"]))
    return validate

REACTOS_CASE = smoke_case("reactos", "ReactOS", media = [smoke_media("reactos", kind = "file")], preflight = _case_preflight(_CONFIG), run = _case_runner(_CONFIG), family = "reactos", architecture = "i386", memory = 512 << 20, cpus = 1)

def reactos_smoke_case(builder):
    """Reuses the identical smoke for a customized file-to-disk builder."""
    def build(source, unused):
        return builder(source)
    config = dict(_CONFIG, builder = build)
    return smoke_case("reactos", "ReactOS", media = [smoke_media("reactos", kind = "file")], preflight = _case_preflight(config), run = _case_runner(config), family = "reactos", architecture = "i386", memory = 512 << 20, cpus = 1)

def main(args):
    smoke_run([REACTOS_CASE], args, title = "trex ReactOS smoke report")
