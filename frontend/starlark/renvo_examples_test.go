package starlarkfrontend

import (
	"fmt"
	"testing"

	"go.starlark.net/starlark"
)

func TestRenvoAMD64Execute(t *testing.T) {
	for _, compiler := range []string{"cc", "go", "make"} {
		t.Run(compiler, func(t *testing.T) {
			architectureScript(t, fmt.Sprintf(`
load("@stdlib//windows/emulation:runner.star", "run")
source = directory()
compiler = %q

def compile():
    if compiler == "go":
        source.write("go.mod", "module smoke\n")
        source.write("main.go", "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"PASS\") }\n")
        return renvo.go(source=source, input=".", target="windows/amd64", arena_size=1<<20)
    source.write("main.c", "int fib(int n) { if (n < 2) return n; return fib(n-1)+fib(n-2); } int main(void) { return fib(10)-13; }")
    if compiler == "make":
        source.write("Makefile", "all: app.exe\napp.exe: main.c\n\trenvo cc main.c -o app.exe\n")
        return renvo.make(source=source, input="Makefile", target="windows/amd64", arena_size=1<<20, targets=["all"], output="app.exe")
    return renvo.cc(source=source, input="main.c", target="windows/amd64", arena_size=1<<20)

compiled = compile()
def check(condition, message):
    if not condition:
        fail(message)
check(compiled.ok, compiled.diagnostic)
output = []

def execute(machine):
    if machine.architecture != "amd64":
        fail("wrong execution architecture")
    def get_std_handle(event):
        return 0x70000001 if event.args[0] & 0xffffffff == 0xfffffff5 else 0x70000002
    def write_file(event):
        if event.args[0] != 0x70000001 or event.args[4] != 0:
            fail("unexpected output handle or asynchronous write")
        data = event.machine.read(event.args[1], event.args[2])
        output.append(str(data))
        if event.args[3]:
            event.machine.write_u32le(event.args[3], len(data))
        return 1
    machine.hook(get_std_handle, address=machine.resolve_export("kernel32.dll", name="GetStdHandle"), argc=1)
    machine.hook(write_file, address=machine.resolve_export("kernel32.dll", name="WriteFile"), argc=5)
    return machine.call(machine.entry)

execution = run(binary.concat([compiled.binary]), "renvo.exe", execute=execute, executable=True)
result = execution["result"]
expected = 0 if compiler == "go" else 42
check(result.reason == "process-exit" and result.value == expected and result.detail == str(expected), "emulation failed: " + result.reason + ": " + result.detail)
check("".join(output) == ("PASS\n" if compiler == "go" else ""), "unexpected stdout: " + str(output))
`, compiler))
		})
	}
}

func TestRenvoExamplesExecute(t *testing.T) {
	for _, test := range []struct{ name, want string }{{"renvo_cc", "C returned 42\n"}, {"renvo_make", "Make returned 42\n"}} {
		t.Run(test.name, func(t *testing.T) {
			thread, env, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			var output string
			env["stdout"] = starlark.NewBuiltin("stdout", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				output += string(args[0].(starlark.Bytes))
				return starlark.None, nil
			})
			globals, err := thread.Load(thread, "//scripts/examples:"+test.name+".star")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := starlark.Call(thread, globals["main"], starlark.Tuple{starlark.Tuple{}}, nil); err != nil {
				t.Fatal(err)
			}
			if output != test.want {
				t.Fatalf("output = %q, want %q", output, test.want)
			}
		})
	}
}
