package windows

import (
	"bytes"
	"encoding/binary"
	"testing"

	"go.starlark.net/starlark"
)

func TestStateRepositoryHash(t *testing.T) {
	// Matched 26100.9444 DLL: native hash_base32 input observation yields
	// LE64(0) plus lowercase UTF-16 text, without terminators. Native Base32
	// conversion of its SHA-256 digest yields this exact 52-character key.
	got, err := StateRepositoryHash([]any{int64(0), nil, "LockSpotlight.BackgroundTask.Configuration", nil, nil, nil})
	if err != nil || got != "j6mcms52s817jt9rsbnw6tszmtax48cdpe08rzk37gfssfqnasmg" {
		t.Fatalf("native task key = %q, %v", got, err)
	}
	sequence := make([]byte, 32)
	for i := range sequence {
		sequence[i] = byte(i)
	}
	// Independently executed native base32 converter, RVA 288740.
	if got := stateRepositoryBase32.EncodeToString(sequence); got != "000g40r40m30e209185gr38e1w8124gk2gahc5rr34d1p70x3rfg" {
		t.Fatalf("native base32 = %s", got)
	}
	hash := func(values ...any) string {
		t.Helper()
		value, err := StateRepositoryHash(values)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if hash("AzZÄΣİ") != hash("azzÄΣİ") || hash("ÄΣİ") == hash("äσi") {
		t.Fatal("text folding is not ASCII-only")
	}
	if hash(nil, "", []byte{}) != hash() || hash("AB", "CD") != hash("abcd") || hash("AB\x00ignored") != hash("ab") {
		t.Fatal("NULL, empty, concatenation or NUL semantics differ")
	}
	var integer [8]byte
	binary.LittleEndian.PutUint64(integer[:], 0x0102030405060708)
	if hash(int64(0x0102030405060708)) != hash(integer[:]) || hash(int64(-1)) != hash(bytes.Repeat([]byte{255}, 8)) {
		t.Fatal("integer is not signed LE64")
	}
	for _, bad := range [][]any{{true}, {1.5}, {"\xff"}, make([]any, 1025)} {
		if _, err := StateRepositoryHash(bad); err == nil {
			t.Fatalf("accepted invalid input %T", bad[0])
		}
	}
}

func TestStateRepositoryHashBuiltin(t *testing.T) {
	env := starlark.StringDict{"hash": Builtins()["state_repository_hash"]}
	result, err := starlark.Eval(&starlark.Thread{}, "hash.star", `hash([0, None, "LockSpotlight.BackgroundTask.Configuration", None, None, None])`, env)
	if err != nil || result != starlark.String("j6mcms52s817jt9rsbnw6tszmtax48cdpe08rzk37gfssfqnasmg") {
		t.Fatalf("hash builtin = %v, %v", result, err)
	}
	for _, expression := range []string{`hash([1.5])`, `hash([True])`, `hash([9223372036854775808])`, `hash([-9223372036854775809])`, `hash([[]])`} {
		if _, err := starlark.Eval(&starlark.Thread{}, "invalid.star", expression, env); err == nil {
			t.Fatalf("accepted %s", expression)
		}
	}
}
