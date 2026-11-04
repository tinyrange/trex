package emulator

import (
	"go.starlark.net/starlark"
	"testing"
)

func TestAMD64SemanticCallProfile(t *testing.T) {
	_, err := starlark.ExecFile(&starlark.Thread{Name: "call profile"}, "profile.star", `
def check(ok):
    if not ok: fail("call profile check failed")
m = machine(architecture="amd64",code=b"\xc3",profile_limit=2)
def inner(e): return e.args[0]+1
inner_address=m.provide_export(inner,module="profile.dll",name="Inner",argc=1)
def outer(e):
    nested=e.machine.invoke(inner_address,args=[e.args[0]])
    check(nested.reason=="return")
    return nested.value+e.args[-1]
outer_address=m.provide_export(outer,module="profile.dll",name="Outer",argc=17)
arguments=list(range(17))
check(m.call(outer_address,args=arguments).value==17)
check(not m.profile().calls_enabled and m.profile().call_tracked==0)
check(m.profile(calls=True).enabled==False)
check(m.call(outer_address,args=arguments).value==17)
p=m.profile()
check(p.call_tracked==2 and p.call_dropped==0 and p.operations==0)
by_name={c.name:c for c in p.calls}
check(by_name['Inner'].address==inner_address and by_name['Inner'].count==1)
check(by_name['Inner'].arguments==[0] and not by_name['Inner'].arguments_truncated)
check(by_name['Outer'].module=='profile.dll' and by_name['Outer'].count==1)
check(by_name['Outer'].arguments==arguments[:16] and by_name['Outer'].arguments_truncated)
check(by_name['Outer'].seconds>=by_name['Inner'].seconds and by_name['Inner'].seconds>=0)
check(by_name['Outer'].max_seconds==by_name['Outer'].seconds)
check(len(m.profile(limit=1).calls)==1)
clone=m.snapshot()
clone.profile(reset=True)
check(clone.profile().call_tracked==0 and m.profile().call_tracked==2)
check(clone.call(outer_address,args=arguments).value==17)
check(m.profile().calls[0].count==1)
other=m.provide_export(inner,module="profile.dll",name="Third",argc=1)
check(m.call(other,args=[9]).value==10)
check(m.profile().call_tracked==2 and m.profile().call_dropped==1)
m.profile(calls=False)
check(m.call(inner_address,args=[8]).value==9)
check({c.name:c.count for c in m.profile().calls}['Inner']==1)
def broken(e): fail("original callback failure")
bad=m.provide_export(broken,module="profile.dll",name="Broken",argc=0)
m.profile(calls=True,reset=True)
failed=m.call(bad)
check(failed.reason=='plugin' and 'original callback failure' in failed.detail)
check(m.profile().calls[0].name=='Broken' and m.profile().calls[0].count==1)
`, Builtins())
	if err != nil {
		t.Fatal(err)
	}
}
