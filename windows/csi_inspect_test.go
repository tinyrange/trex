package windows

import (
	"encoding/binary"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestCSIInspectionBuiltins(t *testing.T) {
	primary := "Package~31bf3856ad364e35~amd64~~10.0.1.2.update.with.dots"
	data := make([]byte, 8+len(primary)+1)
	binary.LittleEndian.PutUint32(data, uint32(len(primary)))
	binary.LittleEndian.PutUint32(data[4:], 1)
	copy(data[8:], primary+"8")
	globals := starlark.StringDict{"source": starlark.Bytes(data), "decode": Builtins()["cbs_deployment_source"], "identity": Builtins()["csi_identity"], "identity_hash": Builtins()["csi_identity_hash"], "deployment_key": Builtins()["csi_deployment_key"]}
	_, err := starlark.ExecFile(&starlark.Thread{Name: "CSI inspect"}, "inspect.star", `
def check():
    s = decode(source)
    if s.package != "Package~31bf3856ad364e35~amd64~~10.0.1.2" or s.update != "update.with.dots" or s.secondary != b"8":
        fail("source boundaries")
    persisted = b"0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=amd64, versionScope=NonSxS"
    if deployment_key(persisted) != "0074283ce7e..0edcf95464e_b77a5c561934e089_4.0.15920.100_3fb84cbf20555c08":
        fail("native canonical deployment name")
    if deployment_key(b"0074283ce7ee52524aaa00edcf95464e, Culture=neutral, Version=4.0.15920.100, PublicKeyToken=b77a5c561934e089, ProcessorArchitecture=x86, versionScope=NonSxS") == deployment_key(persisted):
        fail("architecture lost from canonical key")
    i = identity(b"deployment, Culture=neutral, Type=win32, Version=10.0.1.2, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS")
    if i.name != "deployment" or i.type != "win32" or i.version_scope != "nonSxS" or i.language != "neutral":
        fail("identity attributes")
    key = identity_hash(b"Microsoft-Windows-Kernel32, Culture=neutral, Version=10.0.26100.9444, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=NonSxS", omit_version=True)
    if key != int("b8cd4325e211ffa2", 16):
        fail("native family hash lost unsigned precision")
check()
`, globals)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"csi_identity", "csi_identity_hash", "csi_deployment_key", "cbs_deployment_source"} {
		for _, input := range []starlark.Value{starlark.String("not bytes"), starlark.Bytes(""), starlark.Bytes(strings.Repeat("x", (64<<10)+1))} {
			if _, err := starlark.Call(&starlark.Thread{}, Builtins()[name], starlark.Tuple{input}, nil); err == nil {
				t.Fatalf("%s accepted invalid input", name)
			}
		}
	}
}
