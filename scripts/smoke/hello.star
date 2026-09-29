"""Build pinned GNU Hello entirely in memory, then exercise the generated ELF."""
load("@stdlib//unix:build.star", "check", "install", "run", "unpack")

VERSION = "2.12.1"
SHA256 = "8d99142afd92576f30b0cd7cb42a8dc6809998bc5d607d88761f512e26c7db20"
URL = "https://ftp.gnu.org/gnu/hello/hello-" + VERSION + ".tar.gz"
ROOT = "/hello-" + VERSION
# 2000-01-21, full moon: upstream greeting-2 must run rather than skip.
EPOCH = 948412800

CASES = [
    {"name": "default", "args": [], "status": 0, "want": "Hello, world!\n"},
    {"name": "greeting", "args": ["--greeting=From memory"], "status": 0, "want": "From memory\n"},
    {"name": "long-greeting", "args": ["-g", "xyz" * 1000], "status": 0, "want": "xyz" * 1000 + "\n"},
    {"name": "traditional", "args": ["--traditional"], "status": 0, "want": "hello, world\n"},
    {"name": "help", "args": ["--help"], "status": 0, "want": "Usage:"},
    {"name": "version", "args": ["--version"], "status": 0, "want": "hello (GNU Hello) " + VERSION},
    {"name": "invalid-option", "args": ["--not-an-option"], "status": 1, "want": ""},
    {"name": "extra-operand", "args": ["operand"], "status": 1, "want": ""},
    {"name": "full-device", "args": [], "status": 1, "want": "", "full": True},
]

def build(media):
    if media.size > 8 << 20 or hex(crypto.hash("sha256", media)) != SHA256:
        fail("Hello source checksum/size mismatch")
    files = emulator.shell.filesystem(maximum = 64 << 20)
    unpack(files, archive.tar(archive.gzip(media, maximum_bytes = 32 << 20), maximum_entries = 10000))
    commands = install(files, epoch = EPOCH)
    configured = run(files, commands, files.find(ROOT + "/configure"), dir = ROOT, name = "./configure")
    if configured.status != 0:
        fail("configure failed\n" + files.find(ROOT + "/config.log").read()[-6000:] + configured.stderr[-2000:])
    for name in ["config.status", "config.h", "Makefile"]:
        files.stat(ROOT + "/" + name)
    built = check(run(files, commands, "make && make check && ./hello", dir = ROOT))
    for name in ["atexit-1", "greeting-1", "greeting-2", "hello-1", "last-1", "operand-1", "traditional-1"]:
        if "PASS: tests/" + name not in built.stdout:
            fail("upstream test did not pass: " + name + "\n" + built.stdout[-4000:])
    if not built.stdout.endswith("Hello, world!\n"):
        fail("missing default greeting")
    results = []
    for case in CASES:
        script = './hello "$@"' + (" >/dev/full" if case.get("full", False) else "")
        result = run(files, commands, script, dir = ROOT, args = case["args"])
        if result.status != case["status"] or case["want"] not in result.stdout:
            fail("Hello case failed: " + case["name"] + "\n" + result.stderr)
        results.append(result)
    return {"binary": files.find(ROOT + "/hello"), "cases": results, "summary": built.stdout[-1200:]}

def main(args):
    if args:
        fail("Usage: hello.star (no arguments; sources and build products stay in memory)")
    media = http_file([URL], size = None, cache_bytes = 8 << 20)
    result = build(media)
    print(result["summary"])
    print("PASS: 7 upstream tests and " + str(len(result["cases"])) + " ELF cases")
    return result
