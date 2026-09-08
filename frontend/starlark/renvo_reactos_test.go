package starlarkfrontend

import "testing"

func TestRenvoReactOSSmokeConstruction(t *testing.T) {
	architectureScript(t, `
load("//scripts/smoke:renvo_reactos.star", "compile_guest", "expected_result", "result_matches", "guest_passed", "test_disk", "read_result", "MEDIA_SHA256", "MEDIA_URL")
def check(value, detail):
    if not value:
        fail(detail)
nonce = "0123456789abcdef0123456789abcdef"
expected = expected_result(nonce)
record = bytes_concat([expected, b"\x00" * (512-len(expected))])
check(result_matches(record, nonce), "complete result rejected")
check(not result_matches(b"\x00" * 512, nonce), "initial file accepted")
check(not result_matches(expected, nonce), "partial write accepted")
check(not result_matches(record, "f" * 32), "stale nonce accepted")
check(not result_matches(bytes_concat([record[:-1], b"x"]), nonce), "trailing garbage accepted")
check(not result_matches(binary.encode(str(record).replace("42", "41"), encoding="ascii"), nonce), "wrong calculation accepted")
check(guest_passed(record, b"EXIT 0\r\n", nonce), "normal exit rejected")
check(not guest_passed(record, b"", nonce), "answer without exit accepted")
check(not guest_passed(record, b"FAIL\r\n", nonce), "failed exit accepted")
check(len(MEDIA_SHA256) == 64 and "/0.4.16/ReactOS-0.4.16-i386.zip" in MEDIA_URL, "media is not pinned")
compiled = compile_guest()
disk = test_disk(compiled, nonce)
volume = filesystem.fat(filesystem.mbr(disk).partitions[0].file)
check(volume["/RENVO.EXE"].bytes() == compiled, "installed PE differs")
check(volume["/INPUT.TXT"].bytes() == binary.encode(nonce, encoding="ascii"), "input differs")
check(">D:\\EXIT.TXT echo EXIT 0\r\n" in str(volume["/RUN.CMD"].bytes()), "numeric exit must not be parsed as a redirection handle")
working = block.overlay(block.device(disk), max_dirty_bytes=1<<20)
check(read_result(working) == b"\x00" * 512, "result must start empty")
check(not result_matches(read_result(working), nonce), "unbooted image passed")
check(read_result(working, "/EXIT.TXT") == b"", "completion must start empty")
pe = windows.pe(volume["/RENVO.EXE"])
check(any([i.get("name") == "FlushFileBuffers" for i in pe.imports]), "missing native durability API")
`)
}
