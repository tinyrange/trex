package starlarkfrontend

import "testing"

func TestMandatoryLabelSDDLNativeAndEmulator(t *testing.T) {
	architectureScript(t, `
load("@stdlib//windows:security.star", sddl="sddl_security_descriptor")
def exercise():
    # Medium integrity, NO_READ_UP | NO_WRITE_UP, no inheritance/audit flags.
    want=binary.decode("02001c00010000001100140003000000010100000000001000200000","hex")
    for make in [windows.compile_sddl,sddl]:
        descriptor=make("O:BAG:SYD:(A;;GR;;;SY)S:(ML;;NRNW;;;ME)")
        parts=windows.security_descriptor_parts(descriptor)
        if parts["sacl"]!=want: fail("mandatory label bytes differ: "+hex(parts["sacl"]))
        # Generic bits on a neighboring allow ACE must not be remapped.
        if binary.read_u32le(parts["dacl"],12)!=0x80000000: fail("generic access mask changed")
        for text in ["D:(ML;;NW;;;ME)","S:(ML;SA;NW;;;ME)","S:(ML;;GA;;;ME)","S:(ML;;NW;;;SY)","S:(ML;;0x8;;;ME)","S:(ML;;NW;00000000-0000-0000-0000-000000000000;;ME)"]:
            if testing.attempt(make,args=[text]).ok: fail("invalid mandatory label accepted: "+text)
exercise()
`)
}
