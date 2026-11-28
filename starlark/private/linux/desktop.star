"""Installed Linux desktop configuration and CC session checks."""

load("@stdlib//vmm:automation.star", "wait_duration")
load(":disk.star", "launch_cc")
load(":installed.star", "inspect_root")
load(":tree.star", "file_entry", "symlink_entry")

_DESKTOP_USER = "trex-desktop"
_DESKTOP_UID = 1637

_XFCE_START = """#!/bin/sh
exec >/dev/ttyS0 2>&1
set -eu
trap 'rc=$?; [ "$rc" = 0 ] || echo DESKTOP_START_FAILED' EXIT
install -d -m 0700 -o trex-desktop -g trex-desktop /run/user/1637
export XAUTHORITY=/run/user/1637/Xauthority
touch "$XAUTHORITY"
chmod 0600 "$XAUTHORITY"
xauth add :0 MIT-MAGIC-COOKIE-1 "$(hexdump -n 16 -e '16/1 "%02x"' /dev/urandom)"
chown trex-desktop:trex-desktop "$XAUTHORITY"
DISPLAY_MODULE
if ! xinit /usr/libexec/trex-xfce-session -- /usr/bin/Xorg :0 DISPLAY_VT -auth "$XAUTHORITY" -nolisten tcp; then
    tail -n 45 /var/log/Xorg.0.log || :
    exit 1
fi
"""

_XFCE_SESSION = """#!/bin/sh
echo DESKTOP_X11_SESSION_STARTED
(
    for attempt in $(seq 1 90); do
        if pgrep -u 1637 -x xfce4-panel >/dev/null &&
           pgrep -u 1637 -x xfdesktop >/dev/null &&
           pgrep -u 1637 -x xfwm4 >/dev/null &&
           timeout 3 xprop -root _NET_SUPPORTING_WM_CHECK | grep -q 'window id # 0x[1-9a-f]'; then
            if ! ( DESKTOP_OWNER_CHECK ); then
                echo DESKTOP_PACKAGE_CHECK_FAILED
                exit 1
            fi
            printf '\n%s\n' 'DESKTOP_MARKER'
            exit 0
        fi
        if [ "$attempt" = 12 ]; then
            echo DESKTOP_XFCE_WAITING
            cat /proc/uptime
            ps -u 1637 -o pid,stat,wchan,comm || :
            timeout 3 xprop -root _NET_SUPPORTING_WM_CHECK || :
        fi
        sleep 1
    done
    echo DESKTOP_FAILED_SESSION
) &
# Keep the observer as a child of this shell while su waits for the session.
su -s /bin/sh trex-desktop -c '
    export XDG_RUNTIME_DIR=/run/user/1637 XDG_SESSION_TYPE=x11 XFWM4_USE_PRESENT=0
    export DISPLAY=:0 XAUTHORITY=/run/user/1637/Xauthority
    cd "$HOME" || exit 1
    if ! xprop -root _NET_SUPPORTING_WM_CHECK >/dev/null; then
        echo DESKTOP_X11_AUTH_FAILED
        exit 1
    fi
    if [ -S "$XDG_RUNTIME_DIR/bus" ]; then
        export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
        exec startxfce4
    fi
    exec dbus-run-session -- startxfce4
'
exit $?
"""

def _account_record(entries, path, name, id_column, number, fields):
    entry = dict(entries[path])
    value = entry["data"]
    if type(value) != "string":
        value = value.read()
    rows = [line.split(":") for line in value.splitlines() if line]
    for row in rows:
        if row[0] == name:
            if row != fields:
                fail("existing account differs in " + path + ": " + name)
            return
        if id_column != None and row[id_column] == str(number):
            fail("account number is already in use in " + path + ": " + str(number))
    entry["data"] = value.rstrip("\n") + "\n" + ":".join(fields) + "\n"
    entries[path] = entry

def add_desktop_account(entries, name, number, home = None, shell = "/bin/sh"):
    """Declare a locked local account before the VM boots."""
    value = str(number)
    directory = home or "/dev/null"
    _account_record(entries, "etc/passwd", name, 2, number, [name, "x", value, value, name, directory, shell])
    _account_record(entries, "etc/group", name, 2, number, [name, "x", value, ""])
    _account_record(entries, "etc/shadow", name, None, number, [name, "!", "19000", "0", "99999", "7", "", "", ""])
    if "etc/gshadow" in entries:
        _account_record(entries, "etc/gshadow", name, None, number, [name, "!", "", ""])
    if home:
        path = home.lstrip("/")
        entries[path] = {"path": path, "mode": 0o040700, "uid": number, "gid": number}

def add_login_group(entries, name, number = None, user = _DESKTOP_USER):
    """Add the test account to the group named by the vendor's PAM policy."""
    for path, password in [("etc/group", "x"), ("etc/gshadow", "!")]:
        if path not in entries:
            continue
        entry = entries[path]
        data = entry["data"]
        lines = (data if type(data) == "string" else data.read()).splitlines()
        rows = [(i, line.split(":")) for i, line in enumerate(lines) if line.startswith(name + ":")]
        if not rows and number != None:
            is_group = path == "etc/group"
            _account_record(entries, path, name, 2 if is_group else None, number, [name, password, str(number) if is_group else "", user])
            continue
        if len(rows) != 1 or len(rows[0][1]) != 4:
            fail("missing or invalid login group " + name + " in " + path)
        i, fields = rows[0]
        members = fields[3].split(",") if fields[3] else []
        if user not in members:
            fields[3] = ",".join(members + [user])
            lines[i] = ":".join(fields)
            entries[path] = dict(entry, data = "\n".join(lines) + "\n")

def install_shared_mime(entries):
    """Compile the shared MIME lookup files from the installed package XML."""
    directory = "usr/share/mime/"
    source = directory + "packages/freedesktop.org.xml"
    for name, file in database.shared_mime_info(entries[source]["data"]).items():
        path = directory + name
        entries[path] = file_entry(path, file)

def configure_xfce_x11(entries, init, marker, ownership_check, display_modules = ()):
    """Enable an unprivileged Xfce session using CC's installed Linux display."""
    _smoke_desktop_account(entries)
    config = "etc/X11/xorg.conf.d/20-cc-display.conf"
    entries[config] = file_entry(config, '''Section "Device"
    Identifier "CC display"
    Driver "fbdev"
    Option "fbdev" "/dev/fb0"
EndSection
''')
    program = "usr/libexec/trex-desktop"
    session = "usr/libexec/trex-xfce-session"
    prepare_display = ["modprobe " + name for name in display_modules]
    display_vt = "vt7" if init == "sysv" else "vt1"
    if init == "sysv":
        prepare_display.append("chvt 7")
        ownership_check += " && { printf 'Active Xorg terminal: '; cat /sys/class/tty/tty0/active; }"
    entries[program] = file_entry(program, _XFCE_START.replace("DISPLAY_MODULE", "\n".join(prepare_display)).replace("DISPLAY_VT", display_vt), 0o755)
    entries[session] = file_entry(session, _XFCE_SESSION.replace("DESKTOP_MARKER", marker).replace("DESKTOP_OWNER_CHECK", ownership_check), 0o755)
    tab = dict(entries["etc/inittab"])
    value = tab["data"] if type(tab["data"]) == "string" else tab["data"].read()
    runlevel = "::once:" if init == "busybox" else "td:3:once:"
    tab["data"] = value + "\n" + runlevel + "/" + program + "\n"
    entries["etc/inittab"] = tab

def _preserve_attributes(entries, path, data):
    entry = file_entry(path, data)
    existing = entries.get(path, {})
    if existing.get("xattrs"):
        entry["xattrs"] = existing["xattrs"]
    entries[path] = entry

def _smoke_desktop_account(entries):
    home = "/home/" + _DESKTOP_USER
    add_desktop_account(entries, _DESKTOP_USER, _DESKTOP_UID, home = home)
    if entries.get("usr/bin/bash", {}).get("xattrs", {}).get("security.selinux"):
        entries[home[1:]]["xattrs"] = {"security.selinux": b"system_u:object_r:user_home_dir_t:s0\x00"}

def _configure_section(entries, path, section, values):
    source = entries.get(path, {}).get("data")
    config = source if type(source) == "string" else source.read() if source != None else ""
    settings = [name + "=" + value for name, value in values.items()]
    lines, current, found = [], "", False
    for line in config.splitlines():
        value = line.strip()
        if value.startswith("[") and value.endswith("]"):
            current = value
            lines.append(line)
            if current == section and not found:
                lines.extend(settings)
                found = True
        elif current != section or value.partition("=")[0].strip() not in values:
            lines.append(line)
    if not found:
        if lines:
            lines.append("")
        lines.extend([section] + settings)
    _preserve_attributes(entries, path, "\n".join(lines) + "\n")

def configure_gdm_desktop(entries, service, path, marker, session = None, ownership_check = ":"):
    """Boot a normal GDM session with an unprivileged test account."""
    _smoke_desktop_account(entries)
    _configure_section(entries, path, "[daemon]", {"AutomaticLoginEnable": "True", "AutomaticLogin": _DESKTOP_USER})
    if session:
        _preserve_attributes(entries, "var/lib/AccountsService/users/" + _DESKTOP_USER, "[User]\nXSession=" + session + "\nSession=" + session + "\nSystemAccount=false\n")
    enable_display_manager(entries, service)
    install_desktop_observer(entries, ["gnome-shell"], marker, require_shell_bus = True, ownership_check = ownership_check)

def configure_lightdm_desktop(entries, session, processes = (), marker = None, ownership_check = ":", user = _DESKTOP_USER, uid = _DESKTOP_UID):
    """Start a normal LightDM session for the test account."""
    configure_lightdm_login(entries, session, user = user)
    enable_display_manager(entries, "lightdm.service")
    alias = "etc/systemd/system/display-manager.service"
    service = "etc/systemd/system/lightdm.service"
    original = entries[entries[alias]["target"].lstrip("/")]
    entries[service] = dict(original, path = service)
    entries[alias] = symlink_entry(alias, "lightdm.service")
    enabled = "etc/systemd/system/graphical.target.wants/lightdm.service"
    entries[enabled] = symlink_entry(enabled, "../lightdm.service")
    if marker != None:
        install_desktop_observer(entries, processes, marker, ownership_check = ownership_check, user = user, uid = uid)

def configure_desktop_console(entries):
    """Make the locked test account available on the isolated smoke VM's serial console."""
    unit = "etc/systemd/system/serial-getty@ttyS0.service.d/99-trex-smoke.conf"
    entries[unit] = file_entry(unit, """[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --autologin trex-desktop --noreset --noclear --keep-baud 115200 - vt100
""")
    path = "home/trex-desktop/.profile"
    entries[path] = dict(file_entry(path, """if [ "$(tty)" = /dev/ttyS0 ]; then
    printf '\nTREX_DESKTOP_CONSOLE\n'
fi
"""), uid = _DESKTOP_UID, gid = _DESKTOP_UID)

def configure_lightdm_login(entries, session, user = _DESKTOP_USER):
    """Declare the desktop account and session for a LightDM seat."""
    if user == _DESKTOP_USER:
        _smoke_desktop_account(entries)
    path = "etc/lightdm/lightdm.conf"
    if path not in entries:
        path = "etc/lightdm/lightdm.conf.d/99-trex-smoke.conf"
    _configure_section(entries, path, "[Seat:*]", {
        "autologin-user": user,
        "autologin-user-timeout": "0",
        "autologin-session": session,
        "user-session": session,
    })

def enable_display_manager(entries, name):
    """Set the systemd graphical boot target and load CC display modules."""
    systemd = "usr/lib/systemd/system/"
    if systemd + name not in entries:
        systemd = "usr/lib64/systemd/system/"
        if systemd + name not in entries:
            fail("missing desktop service " + name)
    entries["etc/systemd/system/display-manager.service"] = symlink_entry("etc/systemd/system/display-manager.service", "/" + systemd + name)
    entries["etc/systemd/system/default.target"] = symlink_entry("etc/systemd/system/default.target", "/" + systemd + "graphical.target")
    _preserve_attributes(entries, "etc/modules-load.d/trex-display.conf", "virtio_mmio\nvirtio_gpu\n")

def install_desktop_observer(entries, processes, marker, require_shell_bus = False, ownership_check = ":", user = _DESKTOP_USER, uid = _DESKTOP_UID):
    """Report the desktop once its user processes and native records are ready."""
    program = "usr/libexec/trex-desktop-observer"
    service = "etc/systemd/system/trex-desktop-observer.service"
    enabled = "etc/systemd/system/graphical.target.wants/trex-desktop-observer.service"
    session_processes = " && ".join(["pgrep -u DESKTOP_UID -x " + process + " >/dev/null" for process in processes])
    session_bus = '&& runuser -u DESKTOP_USER -- env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/DESKTOP_UID/bus gdbus call --session --timeout 3 --dest org.gnome.Shell --object-path /org/gnome/Shell --method org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1' if require_shell_bus else ""
    report = """printf '\n%s\n' "$1" >/dev/ttyS0""" if require_shell_bus else """printf '<4>%s\n' "$1" >/dev/kmsg || printf '\n%s\n' "$1" >/dev/ttyS0"""
    entries[program] = file_entry(program, """#!/bin/sh
report() {
    REPORT
}
report DESKTOP_OBSERVER_STARTED
for attempt in $(seq 1 60); do
    if SESSION_PROCESSES SESSION_BUS; then
        if ! ( OWNERSHIP_CHECK ); then
            report DESKTOP_PACKAGE_CHECK_FAILED
            exit 1
        fi
        report 'DESKTOP_MARKER'
        exit 0
    fi
    if [ "$attempt" = 5 ] || [ "$attempt" = 25 ]; then
        report "DESKTOP_OBSERVER_WAITING attempt=$attempt"
        ps -u DESKTOP_UID -o comm= || :
        ls /sys/class/drm
    fi
    sleep 2
done
report DESKTOP_FAILED_SESSION
exit 1
""".replace("REPORT", report).replace("SESSION_PROCESSES", session_processes).replace("SESSION_BUS", session_bus).replace("DESKTOP_MARKER", marker).replace("OWNERSHIP_CHECK", ownership_check).replace("DESKTOP_USER", user).replace("DESKTOP_UID", str(uid)), 0o755)
    entries[service] = file_entry(service, """[Unit]
Description=Check installed graphical desktop session
After=display-manager.service systemd-user-sessions.service

[Service]
Type=exec
ExecStart=/usr/libexec/trex-desktop-observer
""")
    entries[enabled] = symlink_entry(enabled, "../trex-desktop-observer.service")
    for path, exemplar in [(program, "usr/bin/bash"), (service, "usr/lib/systemd/system/systemd-user-sessions.service"), (enabled, "usr/lib/systemd/system/systemd-user-sessions.service")]:
        context = entries.get(exemplar, {}).get("xattrs", {}).get("security.selinux")
        if context != None:
            entries[path]["xattrs"] = {"security.selinux": context}

def verify_desktop_cc(disk, marker, memory = 1536 << 20, timeout = 130, cpus = 1, virtio_gpu = False, console_check = None, serial = True):
    """Require a guest session proof and a rendered 1280-by-720 display."""
    vm = launch_cc(disk, memory = memory, overlay_limit = 768 << 20, run_timeout = timeout + 5, capturable = True, cpus = cpus, virtio_gpu = virtio_gpu, serial = serial)
    result = testing.attempt(_watch_desktop, args = [vm, marker, timeout, console_check, serial])
    logs = ""
    if not result.ok:
        captured = testing.attempt(_desktop_failure_logs, args = [vm])
        if captured.ok:
            logs = captured.value
    vm.close()
    if not result.ok:
        fail(result.error + logs)
    print(marker)

def _desktop_failure_logs(vm):
    root = inspect_root(vm.extension("cc.v1").disk(), [])
    result = []
    for path in ["var/log/Xorg.0.log", "var/log/lightdm/lightdm.log", "var/log/lightdm/x-0.log", "home/trex-desktop/.xsession-errors", "home/linux/.xsession-errors"]:
        node = root.find(path)
        if node != None and node.file != None:
            size = node.file.size
            result.append(path + "\n" + node.file.slice(max(0, size - 4000)).read().rstrip())
    return "\n" + "\n".join(result) if result else ""

def _reported(lines, marker):
    return marker in lines or any([line.startswith("[") and line.rsplit("]", 1)[-1].strip() == marker for line in lines])

def _watch_desktop(vm, marker, timeout, console_check, serial):
    channel = vm.channel("console") if serial else None
    inspect = vm.extension("cc.v1")
    deadline = clock.monotonic() + timeout
    last = ""
    session_ready = False
    colors = {}
    while clock.monotonic() < deadline and vm.running:
        if channel == None:
            last = inspect.state()["console"].replace("\r", "")
        else:
            read = testing.attempt(channel.read_some, kwargs = {"maximum": 65536, "timeout": 1})
            if read.ok:
                last = (last + str(read.value).replace("\r", ""))[-65536:]
            if console_check != None and console_check[0] in last:
                channel.write(bytes(console_check[1] + "\n"))
                console_check = None
        lines = last.splitlines()
        if any([_reported(lines, error) for error in ["DESKTOP_START_FAILED", "DESKTOP_FAILED_SESSION", "DESKTOP_X11_AUTH_FAILED", "DESKTOP_PACKAGE_CHECK_FAILED"]]):
            break
        session_ready = session_ready or _reported(lines, marker)
        if session_ready:
            frame = image.decode(vm.screenshot())
            if frame.width < 800 or frame.height < 600:
                fail("desktop framebuffer is too small")
            points = [(x, y) for y in range(5, frame.height, 23) for x in range(5, frame.width, 29)]
            colors = {}
            for x, y in points:
                pixel = frame.pixel(x, y)
                colors[(pixel.r, pixel.g, pixel.b)] = True
            if len(colors) >= 12:
                return
        if channel == None:
            wait_duration(vm, 5)
    if session_ready:
        fail("graphical session reported ready, but the capture had only " + str(len(colors)) + " sampled colors\n" + last[-5200:])
    inspected = testing.attempt(inspect.state)
    nvme = inspected.value.get("nvme") if inspected.ok else None
    storage = ""
    if nvme != None:
        storage = " CC reads=" + str(nvme["read_commands"]) + " slow=" + str(nvme["backing_slow_count"]) + " failures=" + str(nvme["backing_failure_count"])
        if nvme["backing_failures"]:
            storage += "\nLast backing I/O failure: " + nvme["backing_failures"][-1]["error"]
    stop = vm.result
    detail = "\nCC stopped: " + stop.reason + " " + stop.detail if stop != None else ""
    fail("desktop session proof did not become ready." + storage + detail + "\n" + last[-9500:])
