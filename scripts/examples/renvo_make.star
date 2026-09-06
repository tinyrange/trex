"""Build a C executable through two in-memory Makefile recipes and execute it."""

load("//scripts/examples:renvo_support.star", "execute")

def main(args):
    source = directory()
    source.mkdir("project/include")
    source.write("project/include/answer.h", "#define ANSWER 42\n")
    source.write("project/main.c", """
#include "answer.h"
int main(void) {
    int total = 0;
    for (int i = 0; i < ANSWER; i++) total++;
    return total;
}
""")
    source.write("project/Makefile", """
RENVO := renvo
.PHONY: all
all: app.exe
app.exe: generated/main.i
\t$(RENVO) cc $< -o $@
generated/main.i: main.c include/answer.h
\t$(RENVO) cc -E -P -Iinclude $< -o $@
""")
    result = renvo.make(source=source, input="project/Makefile", target="windows/386", arena_size=1 << 20, targets=["all"], output="app.exe")
    if not result.ok:
        fail(result.diagnostic)
    if "generated/main.i" not in result.outputs:
        fail("preprocessing recipe did not produce its virtual output")
    execute(result.binary, expected_exit=42)
    stdout(b"Make returned 42\n")
