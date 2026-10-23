package starlarkfrontend

import (
	"go.starlark.net/starlark"
	"strings"
	"testing"
)

func TestOfflineWinTrustVerifiedImageAndState(t *testing.T) {
	thread, predeclared, err := newStarlarkRuntime("-")
	if err != nil {
		t.Fatal(err)
	}
	predeclared["image"] = relocatablePE32TestImage(t, 0x200000)
	_, err = starlark.ExecFile(thread, "wintrust-test.star", offlineWinTrustScript, predeclared)
	if err != nil {
		if e, ok := err.(*starlark.EvalError); ok {
			t.Fatal(e.Backtrace())
		}
		t.Fatal(err)
	}
}

const offlineWinTrustScript = `
load("@stdlib//windows/emulation:wintrust.star","offline_wintrust_plugin")
def check(value):
    if not value:
        fail("offline trust contract")
identity=windows.test_signing_identity("Offline trust regression",1700000000,2000000000)
signed=windows.pe_sign(image,identity)
def exercise(arch,blocked):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    plugin=offline_wintrust_plugin({"C:\\signed.exe":signed},[identity.certificate],blocked,1800000000,0x23c00)
    m.use(plugin)
    fn=m.resolve_export("wintrust.dll",name="WinVerifyTrustEx")
    wide=arch=="amd64"
    info=m.allocate(size=32 if wide else 16)
    m.write_u32le(info,32 if wide else 16)
    path=m.allocate(value=binary.encode("c:/SIGNED.exe",encoding="utf16le",nul=True))
    m.write_pointer(info+(8 if wide else 4),path)
    action=m.allocate(value=b"\x6b\xc5\xaa\x00\x44\xcd\xd0\x11\x8c\xc2\x00\xc0\x4f\xc2\x95\xee")
    data=m.allocate(size=88 if wide else 52)
    m.write_u32le(data,88 if wide else 52)
    m.write_u32le(data+(24 if wide else 12),2)
    m.write_u32le(data+(28 if wide else 16),1)
    m.write_u32le(data+(32 if wide else 20),1)
    m.write_pointer(data+(40 if wide else 24),info)
    m.write_u32le(data+(48 if wide else 28),1)
    m.write_u32le(data+(72 if wide else 40),0x1440)
    result=m.call(fn,args=[0,action,data])
    check(result.reason=="return" and result.value==(0x800b0111 if blocked else 0))
    handle=m.read_pointer(data+(56 if wide else 32))
    check(handle in plugin.state["handles"])
    check(plugin.state["checks"][0]["revocation"]=="unavailable-offline")
    check(not plugin.state["checks"][0]["revocation_checked"])
    helper=m.resolve_export("wintrust.dll",name="WTHelperProvDataFromStateData")
    get_signer=m.resolve_export("wintrust.dll",name="WTHelperGetProvSignerFromChain")
    result=m.call(helper,args=[handle])
    if result.reason != "return":
        fail(result.detail)
    provider=result.value
    if not provider or m.read_u32le(provider)!=(240 if wide else 136):
        fail("provider size: " + str(m.read_u32le(provider)))
    check(m.call(helper,args=[handle]).value==provider)
    signer=m.call(get_signer,args=[provider,0,0,0]).value
    check(signer and m.read_u32le(signer)==(64 if wide else 44))
    check(m.read_u32le(signer+12)==1)
    certs=m.read_pointer(signer+16)
    check(m.read_u32le(certs)==(88 if wide else 60))
    certificate=m.read_pointer(certs+(8 if wide else 4))
    der=m.read_pointer(certificate+(8 if wide else 4))
    size=m.read_u32le(certificate+(16 if wide else 8))
    check(m.read(der,size)==identity.certificate)
    chain=m.read_pointer(signer+(56 if wide else 40))
    check(m.read_u32le(chain)==(72 if wide else 56))
    check(m.read_u32le(chain+4)==0 and m.read_u32le(chain+12)==1)
    check(m.call(get_signer,args=[provider,1,0,0]).value==0)
    check(m.call(get_signer,args=[provider,0,1,0]).value==0)
    policy=m.resolve_export("crypt32.dll",name="CertVerifyCertificateChainPolicy")
    para=m.allocate(size=16 if wide else 12)
    m.write_u32le(para,16 if wide else 12)
    m.write_u32le(para+4,0x10000)
    status=m.allocate(size=24 if wide else 20)
    for cb in [0,24 if wide else 20]:
        m.write_u32le(status,cb)
        result=m.call(policy,args=[7,chain,para,status])
        check(result.reason=="return" and result.value==1)
        # A valid, explicitly trusted certificate is not a Microsoft root.
        check(m.read_u32le(status+4)==0x800b0109 and m.read_u32le(status)==cb)
    m.write_u32le(data+(48 if wide else 28),2)
    check(m.call(fn,args=[0,action,data]).value==0)
    check(m.read_pointer(data+(56 if wide else 32))==0 and not plugin.state["handles"])
    check(m.call(fn,args=[0,action,data]).value==0x80070057)
    check(m.call(helper,args=[handle]).value==0)
    check(m.call(get_signer,args=[provider,0,0,0]).value==0)
    check(not plugin.state["providers"] and not plugin.state["chains"] and not plugin.state["certificates"])
exercise("x86",[])
exercise("amd64",[])
exercise("x86",[identity.certificate])
exercise("amd64",[identity.certificate])
`

func TestOfflineWinTrustRejectsInvalidInputs(t *testing.T) {
	for _, tc := range []struct{ name, old, replacement, want string }{
		{"tampered image", "signed=windows.pe_sign(image,identity)", "builder=binary.builder()\nbuilder.append(windows.pe_sign(image,identity))\nbuilder.patch_u8(2,255)\nsigned=builder.bytes()", "image digest mismatch"},
		{"untrusted signer", "[identity.certificate],blocked,1800000000", "[],blocked,1800000000", "unknown authority"},
		{"expired signer", "blocked,1800000000", "blocked,2100000000", "expired"},
		{"unsupported policy", "1800000000,0x23c00", "1800000000,0x200", "supported Windows policy"},
		{"unsupported provider flags", "40),0x1440", "40),0x1040", "unsupported WinTrust file verification options"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			thread, predeclared, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			predeclared["image"] = relocatablePE32TestImage(t, 0x200000)
			source := strings.Replace(offlineWinTrustScript, tc.old, tc.replacement, 1)
			if source == offlineWinTrustScript {
				t.Fatal("missing mutation target")
			}
			source = strings.Replace(source, "    check(result.reason==", "    if result.reason != \"return\":\n        fail(result.detail)\n    check(result.reason==", 1)
			_, err = starlark.ExecFile(thread, "wintrust-reject.star", source, predeclared)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}
