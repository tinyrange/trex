"""Compile with Renvo, boot pinned ReactOS, and verify a guest-written result."""
load("@stdlib//windows/reactos:image.star", "reactos_disk")
load("@stdlib//qemu:profiles.star", "reactos")
load("@stdlib//vmm:automation.star", "wait_duration")
load("@stdlib//vmm:smoke.star", "wait_for_command_surface")

MEDIA_VERSION = "0.4.16"
MEDIA_NAME = "ReactOS-0.4.16-i386.zip"
# Published on the version-specific SourceForge download page.
MEDIA_SHA256 = "e5851510cf5b79ef51a76b8155dd5ef7faca1155f44d0a1d41c35b77ece4ce2a"
MEDIA_URL = "https://downloads.sourceforge.net/project/reactos/ReactOS/0.4.16/" + MEDIA_NAME
RESULT_SIZE = 512

SOURCE = """
package main
import "fmt"
import "os"

// renvo:linkstatic kernel32.dll,CreateFileA
func createFile(name *byte, access uint32, share uint32, security uintptr, disposition uint32, flags uint32, template uintptr) uintptr { return 0 }
// renvo:linkstatic kernel32.dll,WriteFile
func writeFile(handle uintptr, data *byte, size uint32, written *uint32, overlapped uintptr) int { return 0 }
// renvo:linkstatic kernel32.dll,FlushFileBuffers
func flushFile(handle uintptr) int { return 0 }
// renvo:linkstatic kernel32.dll,CloseHandle
func closeHandle(handle uintptr) int { return 0 }

func fib(n int) int { if n < 2 { return n }; return fib(n-1) + fib(n-2) }
func main() {
    nonce, err := os.ReadFile("D:\\\\INPUT.TXT")
    if err != nil || len(nonce) != 32 { panic("input read failed") }
    answer := fib(10) - 13
    if answer != 42 { panic("calculation failed") }
    message := fmt.Sprintf("PASS %s fib=%d\\n", string(nonce), answer)
    data := make([]byte, 512)
    copy(data, []byte(message))
    name := append([]byte("D:\\\\RESULT.TXT"), 0)
    // GENERIC_WRITE, no sharing, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH.
    handle := createFile(&name[0], 0x40000000, 0, 0, 3, 0x80000000, 0)
    if handle == 0xffffffff { panic("result open failed") }
    written := uint32(0)
    if writeFile(handle, &data[0], uint32(len(data)), &written, 0) == 0 || written != uint32(len(data)) { panic("result write failed") }
    if flushFile(handle) == 0 { panic("result flush failed") }
    if closeHandle(handle) == 0 { panic("result close failed") }
    fmt.Print(message)
}
"""

def compile_guest():
    source = directory()
    source.write("go.mod", "module smoke\n")
    source.write("main.go", SOURCE)
    result = renvo.go(source = source, input = ".", target = "windows/386", arena_size = 1 << 20)
    if not result.ok:
        fail(result.diagnostic)
    return result.binary

def expected_result(nonce):
    if len(nonce) != 32 or any([c not in "0123456789abcdef" for c in nonce.elems()]):
        fail("nonce must be 32 lowercase hexadecimal characters")
    return binary.encode("PASS " + nonce + " fib=42\n", encoding = "ascii")

def result_matches(data, nonce):
    expected = expected_result(nonce)
    return len(data) == RESULT_SIZE and data == bytes_concat([expected, b"\x00" * (RESULT_SIZE - len(expected))])

def guest_passed(data, completion, nonce):
    return result_matches(data, nonce) and completion == b"EXIT 0\r\n"

def test_disk(binary_file, nonce):
    expected_result(nonce)
    root = directory()
    root.write("RENVO.EXE", binary_file)
    root.write("INPUT.TXT", nonce)
    root.write("RESULT.TXT", b"\x00" * RESULT_SIZE)
    root.write("EXIT.TXT", b"")
    # Let the guest shell witness normal process termination. The data file
    # alone must not pass if the program writes its answer and then crashes.
    # Prefix redirection: a digit immediately before '>' is a handle number,
    # while adding a separating space would include that space in echo output.
    root.write("RUN.CMD", "@echo off\r\nD:\\RENVO.EXE\r\nif errorlevel 1 goto failed\r\n>D:\\EXIT.TXT echo EXIT 0\r\ngoto end\r\n:failed\r\n>D:\\EXIT.TXT echo FAIL\r\n:end\r\n")
    volume = filesystem.fat16(root, size = 16 << 20, label = "RENVO")
    return filesystem.mbr(20 << 20).partition(volume, type = 0x06, start_lba = 63)

def read_result(working, name = "/RESULT.TXT"):
    # RESULT.TXT is preallocated; EXIT.TXT is written by cmd on process exit.
    # Each parse uses one immutable snapshot of the guest-visible disk.
    volume = filesystem.fat(filesystem.mbr(working.snapshot()).partitions[0].file)
    return volume[name].bytes()

def write_report(prefix, report):
    write(prefix + ".json", json.encode(report) + "\n")
    status = "PASS" if report["passed"] else "FAIL / incomplete"
    write(prefix + ".md", "## Renvo / ReactOS smoke\n\n" +
        "| Result | ReactOS | Target | Phase |\n| --- | --- | --- | --- |\n" +
        "| " + status + " | " + MEDIA_VERSION + " | windows/386 | " + report["phase"] + " |\n\n" +
        report["detail"] + "\n\nMedia SHA-256: `" + MEDIA_SHA256 + "`\n")

def main(args):
    options = {"output": "local/renvo-reactos", "cache": "local/media-cache", "accelerator": "tcg", "timeout": "180"}
    for arg in args:
        fields = arg.split("=", 1)
        if len(fields) != 2 or fields[0] not in options.keys() + ["media"]:
            fail("Usage: renvo_reactos.star [output=prefix] [cache=directory] [media=pinned.zip] [accelerator=tcg|kvm] [timeout=seconds]")
        options[fields[0]] = fields[1]
    timeout = int(options["timeout"])
    if timeout < 1 or timeout > 600 or options["accelerator"] not in ["tcg", "kvm"]:
        fail("invalid timeout or accelerator")
    prefix = options["output"]
    report = {"passed": False, "phase": "download", "detail": "Smoke did not finish; see the action log.", "media_version": MEDIA_VERSION, "media_sha256": MEDIA_SHA256}
    write_report(prefix, report)
    media = open(options["media"]) if "media" in options else mirror_file([MEDIA_URL], cache = options["cache"], key = MEDIA_NAME, sha256 = MEDIA_SHA256, maximum = 256 << 20, timeout = 300)
    if hex(crypto.hash("sha256", media)) != MEDIA_SHA256:
        fail("ReactOS media SHA-256 mismatch")
    report["phase"] = "compile-and-build"
    write_report(prefix, report)
    binary_file = compile_guest()
    nonce = hex(crypto.random(16))
    disk = reactos_disk(media)
    working = block.overlay(block.device(test_disk(binary_file, nonce)), max_dirty_bytes = 8 << 20)
    system = block.overlay(block.cache(block.device(disk)), max_dirty_bytes = 256 << 20)
    machine = vmm.machine(architecture = "i386", memory = 512 << 20,
        disks = [vmm.disk(system, name = "reactos", bus = "ide", unit = 0), vmm.disk(working, name = "renvo", bus = "ide", unit = 1)],
        display = vmm.display("capturable"))
    report["phase"] = "boot-and-launch"
    write_report(prefix, report)
    vm = vmm.start(machine, reactos(accelerator = options["accelerator"], block_transport = "nbd", display_frontend = "none", network = False))
    wait_duration(vm, 35)
    launch = wait_for_command_surface(vm, "cmd.exe /c D:\\RUN.CMD", timeout = timeout, minimum_width = 800, minimum_height = 600)
    write(prefix + "-launch.png", launch["image"])
    report["phase"] = "guest-result"
    report["detail"] = launch["detail"]
    write_report(prefix, report)
    deadline = clock.monotonic() + timeout
    data = read_result(working)
    completion = read_result(working, "/EXIT.TXT")
    while not guest_passed(data, completion, nonce) and completion != b"FAIL\r\n" and vm.running and clock.monotonic() < deadline:
        wait_duration(vm, 1)
        data = read_result(working)
        completion = read_result(working, "/EXIT.TXT")
    transports = qemu.extension(vm).block_stats()
    report["block_command_errors"] = 0
    for stats in transports:
        report["block_command_errors"] += stats.command_errors
    report["passed"] = guest_passed(data, completion, nonce) and report["block_command_errors"] == 0
    report["phase"] = "complete"
    report["detail"] = "Guest read the per-run input, computed fib(10)-13=42, formatted and flushed the exact expected result, and exited with code 0; no disk command errors." if report["passed"] else "Missing or incorrect guest result, nonzero exit, timeout, or disk command error. See screenshots, guest records and action log."
    report["binary_bytes"] = len(binary_file)
    write(prefix + "-guest-result.bin", data)
    write(prefix + "-guest-exit.txt", completion)
    write(prefix + "-desktop.png", vm.screenshot())
    vm.stop()
    vm.wait(timeout = 10)
    vm.close()
    write_report(prefix, report)
    print("Renvo / ReactOS", "PASS" if report["passed"] else "FAIL", report["detail"])
    if not report["passed"]:
        fail(report["detail"])
