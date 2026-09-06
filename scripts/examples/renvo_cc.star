"""Compile C with a virtual header, then execute and check its return value."""

load("//scripts/examples:renvo_support.star", "execute")

def main(args):
    source = directory()
    source.mkdir("include")
    source.write("include/answer.h", "#define OFFSET 13\n")
    source.write("main.c", """
#include "answer.h"
int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}
int main(void) { return fib(10) - OFFSET; }
""")
    result = renvo.cc(source=source, input="main.c", target="windows/386", arena_size=1 << 20, flags=["-Iinclude"])
    if not result.ok:
        fail(result.diagnostic)
    execute(result.binary, expected_exit=42)
    stdout(b"C returned 42\n")
