//go:build renvo_bundle

package starlarkfrontend

import "testing"

func TestUnixBuildRecipe(t *testing.T) {
	architectureScript(t, `
load("@stdlib//unix:build.star", "install", "run", "check")
def exercise():
    files = emulator.shell.filesystem(maximum=8<<20)
    commands = install(files, epoch=948412800)
    files.mkdir("/work")
    files.write("/work/main.c", '#include <stdio.h>\nint main(void) { puts("PASS"); return 0; }')
    result = check(run(files, commands, "cc -c main.c -o main.o && ar cr libmain.a main.o && ranlib libmain.a && cc libmain.a -o app && ./app", dir="/work"))
    if result.stdout != "PASS\n":
        fail(result.stdout + result.stderr)
    # Compiled output is an ordinary portable file, directly composable with directory.
    image = files.find("/work/app")
    output = directory()
    output.write("app", image)
    if output.find("app").bytes() != image.bytes():
        fail("portable output changed")
    # The recipe owns dispatch, including nonstandard executable locations.
    files.mkdir("/other")
    files.write("/other/compiler", "", mode=0o755)
    commands["/other/compiler"] = commands.pop("/bin/cc")
    check(run(files, commands, "/other/compiler main.c -o second && ./second", dir="/work"))
exercise()
`)
}
