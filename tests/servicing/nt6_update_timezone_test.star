"""Timezone publication tests and media-backed native installer regression."""
load("//tests:testing.star", "case", "equal", "suite", "raises", "contains")
load("@stdlib//windows/servicing:timezone.star", "publish_timezone_effects")
load("@stdlib//windows/servicing:installer.star", "run_basic_installer")

_ZONES="/Microsoft/Windows NT/CurrentVersion/Time Zones"
_CURRENT="/ControlSet002/Control/TimeZoneInformation"
_SECURITY=windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")

def _fixture(disabled=0,literal=False):
    root=directory()
    values={"MUI_Display":"@tzres.dll,-100","MUI_Std":"@tzres.dll,-102","MUI_Dlt":"@tzres.dll,-101","Std":"Old standard","Unrelated":"keep"}
    patches=[dict(key=_ZONES+"/Example",name=n,type="REG_SZ",value=v) for n,v in values.items()]
    patches.append(dict(key=_ZONES+"/Example",name="dLT",type="REG_BINARY",value=b"wrong type"))
    root.write("/Windows/System32/config/SOFTWARE",windows.hive_from_patches("SOFTWARE",patches,keys=[dict(key_parts=(_ZONES+"/Example")[1:].split("/"),security=_SECURITY)]))
    current={"TimeZoneKeyName":"Example","StandardName":"Literal name" if literal else "@tzres.dll,-202","DaylightName":"@tzres.dll,-202" if disabled else "@tzres.dll,-201"}
    patches=[dict(key=_CURRENT,name=n,type="REG_SZ",value=v) for n,v in current.items()]
    patches.extend([dict(key="/Select",name="Current",type="REG_DWORD",value=2),dict(key="/ControlSet002/Control/Nls/Language",name="InstallLanguage",type="REG_SZ",value="0409"),dict(key=_CURRENT,name="DynamicDaylightTimeDisabled",type="REG_DWORD",value=disabled),dict(key=_CURRENT.replace("002","001"),name="StandardName",type="REG_SZ",value="inactive")])
    root.write("/Windows/System32/config/SYSTEM",windows.hive_from_patches("SYSTEM",patches,keys=[dict(key_parts=_CURRENT[1:].split("/"),security=_SECURITY)]))
    return root

def _effect(hive,key,name,text):
    return dict(hive=hive,key=key,name=name,type=1,raw=binary.encode(text+chr(0),encoding="utf16le"))

def test_publication_and_readback():
    root=_fixture()
    effects=[_effect("SOFTWARE",_ZONES+"/Example","Display","New display"),_effect("SOFTWARE",_ZONES+"/Example","Dlt","New daylight"),_effect("SYSTEM",_CURRENT,"StandardName","@tzres.dll,-102")]
    result=publish_timezone_effects(root,effects)
    equal([len(result[h]) for h in ["SOFTWARE","SYSTEM"]],[2,1])
    actual=windows.hive(root.find("/Windows/System32/config/SOFTWARE")).find(_ZONES+"/Example")
    equal(actual.values["dLT"],"New daylight")
    equal(actual.values["Unrelated"],"keep")
    equal(actual.security,_SECURITY)
    equal(windows.hive(root.find("/Windows/System32/config/SYSTEM")).find(_CURRENT.replace("002","001")).values["StandardName"],"inactive")
    equal(publish_timezone_effects(root,effects),{"SOFTWARE":[],"SYSTEM":[]})

def test_late_unauthorized_effect_is_atomic():
    root=_fixture()
    before={h:digest(root.find("/Windows/System32/config/"+h)) for h in ["SOFTWARE","SYSTEM"]}
    first=_effect("SOFTWARE",_ZONES+"/Example","Display","New display")
    for bad in [_effect("SYSTEM",_CURRENT.replace("002","001"),"StandardName","wrong"),_effect("SOFTWARE",_ZONES+"/Missing","Display","wrong"),dict(first,raw=b"x"),first]:
        raises(publish_timezone_effects,args=[root,[first,bad]])
        equal({h:digest(root.find("/Windows/System32/config/"+h)) for h in before},before)

def verify_timezone_installer(file):
    # Independent test resource, not an emulated installer decision table.
    block=binary.builder()
    for index in range(16):
        text={4:"New display",5:"New daylight",6:"New standard"}.get(index,"")
        data=binary.encode(text,encoding="utf16le")
        block.u16le(len(data)//2)
        block.append(data)
    resource=windows.pe(binary.concat([windows.pe32_executable(b"\xcc",{"entry":0},[])])).with_resources([dict(type="#6",name="#7",lang="#1033",data=block.bytes())])
    rows=[]
    for disabled,literal in [(0,False),(1,False),(0,True)]:
        root=_fixture(disabled=disabled,literal=literal)
        sources={h:root.find("/Windows/System32/config/"+h) for h in ["SOFTWARE","SYSTEM"]}
        before={h:digest(f) for h,f in sources.items()}
        hives={h:windows.hive(f) for h,f in sources.items()}
        primary=run_basic_installer(file,"timezone",hives)
        equal(primary["patches"],[])
        native=run_basic_installer(file,"timezone-resource",hives,files={"C:/Windows/System32/en-US/tzres.dll.mui":resource})
        expected={"Display":"New display","Dlt":"New daylight","Std":"New standard"}
        equal({p["name"]:binary.text(p["raw"][:-2],encoding="utf16le") for p in native["patches"] if p["hive"]=="SOFTWARE"},expected)
        current={} if literal else {"StandardName":"@tzres.dll,-102","DaylightName":"@tzres.dll,-102" if disabled else "@tzres.dll,-101"}
        equal({p["name"]:binary.text(p["raw"][:-2],encoding="utf16le") for p in native["patches"] if p["hive"]=="SYSTEM"},current)
        equal({h:digest(f) for h,f in sources.items()},before)
        publish_timezone_effects(root,native["patches"])
        updated={h:windows.hive(root.find("/Windows/System32/config/"+h)) for h in sources}
        equal(updated["SOFTWARE"].find(_ZONES+"/Example").values["Unrelated"],"keep")
        equal(updated["SOFTWARE"].find(_ZONES+"/Example").security,_SECURITY)
        replay=run_basic_installer(file,"timezone-resource",updated,files={"C:/Windows/System32/en-US/tzres.dll.mui":resource})
        equal(replay["patches"],[])
        failure=raises(run_basic_installer,args=[file,"timezone-resource",hives],kwargs=dict(files={"C:/Windows/System32/en-US/tzres.dll.mui":resource},instruction_limit=native["result"].steps-100))
        contains(failure,"instruction-limit")
        contains(failure,"writes=3" if literal else "writes=4")
        equal({h:digest(f) for h,f in sources.items()},before)
        rows.append(dict(disabled=disabled,literal=literal,writes=len(native["patches"]),steps=native["result"].steps,replay_writes=0,budget_failure=failure))
    return dict(passed=True,cases=rows)

TEST_SUITE=suite("nt6/update-timezone",[
    case("publication_and_readback",test_publication_and_readback),
    case("late_unauthorized_effect_is_atomic",test_late_unauthorized_effect_is_atomic),
])
