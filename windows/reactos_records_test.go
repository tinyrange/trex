package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReactOSFixedRecords(t *testing.T) {
	domain := ReactOSDomainRecord{Revision: ReactOSRecordRevision, CreationTime: 123, NextRID: 1002, MaximumPasswordAge: -42, ForceLogoff: -1 << 63, LockoutThreshold: 5, ServerState: 1, ServerRole: 3}
	raw, err := domain.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 104 {
		t.Fatalf("domain size %d", len(raw))
	}
	var decoded ReactOSDomainRecord
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != domain {
		t.Fatalf("domain changed: %+v", decoded)
	}
	user := ReactOSUserRecord{Revision: ReactOSRecordRevision, RID: 1001, PrimaryGroupRID: 513, AccountExpires: 1<<63 - 1, AccountControl: 16, BadPasswordCount: 2, LogonCount: 3}
	raw, err = user.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 72 {
		t.Fatalf("user size %d", len(raw))
	}
	var decodedUser ReactOSUserRecord
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decodedUser); err != nil {
		t.Fatal(err)
	}
	if user != decodedUser {
		t.Fatal("user round trip changed fields")
	}
	// Independent layout checks for the ABI identity fields and adjacent counters.
	if binary.LittleEndian.Uint32(raw[48:]) != 1001 || binary.LittleEndian.Uint32(raw[52:]) != 513 || binary.LittleEndian.Uint16(raw[64:]) != 2 || binary.LittleEndian.Uint16(raw[66:]) != 3 {
		t.Fatal("SAM user ABI layout mismatch")
	}
	group, err := (ReactOSGroupRecord{Revision: ReactOSRecordRevision, RID: 513, Attributes: 7}).MarshalBinary()
	if err != nil || len(group) != 16 || binary.LittleEndian.Uint32(group[8:]) != 513 {
		t.Fatalf("group %x %v", group, err)
	}
}

func TestReactOSRecordValidationAndVariableFields(t *testing.T) {
	for _, tc := range []struct{ kind, fields string }{
		{"domain", `{"typo":1}`}, {"domain", `{"next_rid":-1}`}, {"domain", `{"revision":2}`},
		{"domain", `null`}, {"domain", `{} {}`},
		{"domain", `{"maximum_password_age":1}`}, {"domain", `{"alignment":1}`},
		{"user", `{"rid":500}`}, {"user", `{"rid":500,"primary_group_rid":513,"code_page":65536}`},
		{"group", `{"rid":0}`}, {"logon_hours", `{"allowed":[true]}`},
		{"policy_audit", `{"options":[0]}`}, {"policy_quota", `{"alignment":1}`}, {"unknown", `{}`},
	} {
		if _, err := BuildReactOSRecord(tc.kind, []byte(tc.fields)); err == nil {
			t.Fatalf("accepted %s %s", tc.kind, tc.fields)
		}
	}
	raw, err := BuildReactOSRecord("policy_string", []byte(`{"value":"WorkΩ"}`))
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(raw) != 10 || binary.LittleEndian.Uint16(raw[2:]) != 12 || binary.LittleEndian.Uint32(raw[4:]) != 8 || decodeUTF16LE(raw[8:len(raw)-2]) != "WorkΩ" {
		t.Fatalf("counted string %x", raw)
	}
	raw, err = BuildReactOSRecord("privileges", []byte(`{"privileges":[{"luid":23,"attributes":3}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 20 || binary.LittleEndian.Uint32(raw) != 1 || binary.LittleEndian.Uint64(raw[8:]) != 23 || binary.LittleEndian.Uint32(raw[16:]) != 3 {
		t.Fatalf("privilege set %x", raw)
	}
}
