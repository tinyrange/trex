package starlarkfrontend

import (
	"fmt"
	"testing"
	"time"
)

func TestNativeTimeFieldsCalendarAndBounds(t *testing.T) {
	dates := []time.Time{time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2000, 2, 29, 23, 59, 58, 999000000, time.UTC), time.Date(2100, 3, 1, 0, 0, 0, 0, time.UTC)}
	cases := ""
	for _, d := range dates {
		ticks := (d.Unix()+11644473600)*10000000 + int64(d.Nanosecond()/100)
		cases += fmt.Sprintf("(%d,[%d,%d,%d,%d,%d,%d,%d,%d]),", ticks, d.Year(), d.Month(), d.Day(), d.Hour(), d.Minute(), d.Second(), d.Nanosecond()/1000000, d.Weekday())
	}
	architectureScript(t, fmt.Sprintf(`
load("@stdlib//windows/selfreg:win32.star","kernel32_plugin")
def exercise(arch):
    m=emulator.machine(architecture=arch,code=b"\xc3")
    m.use(kernel32_plugin())
    target=m.resolve_export("ntdll.dll",name="RtlTimeToTimeFields")
    source=m.allocate(size=8)
    output=m.allocate(size=20)
    for ticks,want in [%s]:
        m.write_u64le(source,ticks+9999)
        m.write(output,b"\xa5"*20)
        result=m.call(target,args=[source,output+2])
        if result.reason!="return": fail("time conversion failed: "+result.detail)
        actual=[m.read_u16le(output+2+i*2) for i in range(8)]
        if actual!=want: fail("TIME_FIELDS mismatch: "+str(actual))
        if m.read_u16le(output)!=0xa5a5 or m.read_u16le(output+18)!=0xa5a5: fail("TIME_FIELDS overwrite")
    m.write_u64le(source,0x8000000000000000)
    m.write(output,b"\xa5"*20)
    if m.call(target,args=[source,output+2]).reason=="return": fail("unsupported signed time accepted")
    if m.read(output,20)!=b"\xa5"*20: fail("failure partially wrote output")
exercise("x86")
exercise("amd64")
`, cases))
}
