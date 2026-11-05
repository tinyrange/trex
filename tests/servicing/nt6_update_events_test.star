"""Offline event identity handoff, shared-session masks and atomic rejection."""

load("//tests:testing.star", "case", "equal", "raises", "suite")

events = testing.module("@stdlib//windows/servicing:events.star")
commit = testing.module("@stdlib//windows/servicing:registry_effects.star")

_OLD = "{af0a42a1-3725-4b61-b476-3694bf352f1b}"
_NEW = "{fa8b6373-5a3d-5411-8d69-fa704c43d68c}"
_ROOT = ["Microsoft", "Windows", "CurrentVersion", "WINEVT"]


def _item(guid, channels):
    return dict(fields=dict(guid=guid,name="Example",resourceFileName="%SystemRoot%/system32/example.dll",messageFileName="%SystemRoot%/system32/example.dll"),channels=channels,unsupported_attributes=[])


def _channel(name, enabled="true", value=None):
    attrs=dict(name=name,type="Operational",isolation="System",enabled=enabled)
    if value!=None: attrs["value"]=value
    return dict(kind="channel",namespace="http://schemas.microsoft.com/win/2004/08/events",attributes=attrs,configuration=[])


def _fixture():
    # Independently captured registry NULL-creator fixed point. This fixture
    # deliberately uses real hive serialization, not mocked lookup/write calls.
    security=binary.decode("01000480580000006400000000000000140000000200440003000000000214003f000f0001010000000000051200000000021400000002000101000000000003040000000002140019000200010100000000000100000000010100000000000512000000010100000000000512000000","hex")
    root=directory()
    keys=[dict(key_parts=_ROOT+[p],security=security) for p in ["Publishers","Channels"]]
    root.write("/Windows/System32/config/SOFTWARE",windows.hive_from_patches("SOFTWARE",[],keys=keys))
    root.write("/Windows/System32/config/SYSTEM",windows.hive_from_patches("SYSTEM",[],keys=[dict(key_parts=["controlset001","Control","WMI","Autologger","EventLog-System"],security=security)]))
    return root


def _apply(root,before,after):
    planned=events["plan_update_event_registry"](root,dict(before=before,after=after),"controlset001")
    commit["apply_update_registry_effects"](root,planned["plans"])
    return windows.hive(root.find("/Windows/System32/config/SOFTWARE")),windows.hive(root.find("/Windows/System32/config/SYSTEM"))


def test_provider_handoff_preserves_channel_and_changes_logger_identity():
    root=_fixture()
    channels=[_channel("Example/Operational")]
    old=_item(_OLD,channels)
    _apply(root,{}, {_OLD:old})
    software,system=_apply(root,{_OLD:old},{_NEW:_item(_NEW,channels)})
    equal(software.find(_ROOT+["Publishers",_OLD]),None)
    publisher=software.find(_ROOT+["Publishers",_NEW])
    equal(publisher.value_records["ResourceFileName"].type,2)
    equal(software.find(_ROOT+["Publishers",_NEW,"ChannelReferences","0"]).values,{"(default)":"Example/Operational","Flags":0,"Id":16})
    equal(software.find(_ROOT+["Channels","Example/Operational"]).values["OwningPublisher"],_NEW)
    prefix=["controlset001","Control","WMI","Autologger","EventLog-System"]
    equal(system.find(prefix+[_OLD]),None)
    logger=system.find(prefix+[_NEW])
    equal(logger.values,{"EnableLevel":0,"EnableProperty":1,"Enabled":1,"LoggerName":"EventLog-System","MatchAllKeyword":0,"MatchAnyKeyword":0x8000000000000000})
    equal(logger.value_records["MatchAnyKeyword"].type,11)
    software,system=_apply(root,{_NEW:_item(_NEW,channels)},{})
    equal(software.find(_ROOT+["Channels","Example/Operational"]),None)
    equal(system.find(prefix+[_NEW]),None)


def test_shared_keywords_use_ordinal_not_id_and_disabled_has_no_logger():
    root=_fixture()
    channels=[_channel("Example/First",value="42"),_channel("Example/Second",value="16"),_channel("Example/Disabled","false")]
    software,system=_apply(root,{}, {_NEW:_item(_NEW,channels)})
    references=_ROOT+["Publishers",_NEW,"ChannelReferences"]
    equal([software.find(references+[str(i)]).values["Id"] for i in range(3)],[42,16,17])
    prefix=["controlset001","Control","WMI","Autologger","EventLog-System"]
    equal(system.find(prefix+[_NEW]).values["MatchAnyKeyword"],0xc000000000000000)
    root=_fixture()
    software,system=_apply(root,{}, {_NEW:_item(_NEW,[_channel("Example/Disabled","false")])})
    equal(software.find(_ROOT+["Channels","Example/Disabled"]).values["Enabled"],0)
    equal(system.find(prefix+[_NEW]),None)


def test_foreign_channel_state_rejects_before_any_hive_publication():
    root=_fixture()
    old=_item(_OLD,[_channel("Example/Operational")])
    _apply(root,{}, {_OLD:old})
    path="/Windows/System32/config/SOFTWARE"
    root.write(path,windows.hive_from_patches("SOFTWARE",[dict(key_parts=_ROOT+["Channels","Example/Operational"],name="Enabled",type="REG_DWORD",value=0)],source=root.find(path)))
    hashes={name:digest(root.find("/Windows/System32/config/"+name)) for name in ["SOFTWARE","SYSTEM"]}
    raises(events["plan_update_event_registry"],args=[root,dict(before={_OLD:old},after={_NEW:_item(_NEW,old["channels"])}),"controlset001"],message="unestablished current configuration")
    equal({name:digest(root.find("/Windows/System32/config/"+name)) for name in hashes},hashes)
    raises(events["plan_update_event_registry"],args=[root,dict(before={},after={}),"CurrentControlSet"],message="canonical selected control set")


TEST_SUITE=suite("private/nt6_update_events",[
    case("identity_handoff",test_provider_handoff_preserves_channel_and_changes_logger_identity),
    case("shared_keywords",test_shared_keywords_use_ordinal_not_id_and_disabled_has_no_logger),
    case("foreign_configuration",test_foreign_channel_state_rejects_before_any_hive_publication),
])
