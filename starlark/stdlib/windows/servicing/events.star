"""Native offline event publisher/channel and shared-autologger registration.

This models the bounded Admin/Operational registration delta, not the whole
advanced-installer queue. Event definitions remain in hash-qualified PE payloads.
No host wevtutil invocation or installer emulator participates in construction.
"""

load("@stdlib//windows/servicing:registry_effects.star", "build_update_driver_key_security", "plan_update_registry_effects")

_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events"
_EVENT_ROOT = ["Microsoft", "Windows", "CurrentVersion", "WINEVT"]
_APPLICATION_ACCESS = "O:BAG:SYD:(A;;0x2;;;S-1-15-2-1)(A;;0x2;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x7;;;SO)(A;;0x3;;;IU)(A;;0x3;;;SU)(A;;0x3;;;S-1-5-3)(A;;0x3;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)"
_SYSTEM_ACCESS = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x3;;;BO)(A;;0x5;;;SO)(A;;0x1;;;IU)(A;;0x3;;;SU)(A;;0x1;;;S-1-5-3)(A;;0x2;;;S-1-5-33)(A;;0x1;;;S-1-5-32-573)"


def _event_attributes(node):
    return {a["name"]:a["value"] for a in node.attributes if not a["namespace"]}


def _event_nodes(node):
    result = []
    if (node.namespace,node.name) == (_EVENT_NS,"provider"):
        return [node]
    for child in node.children:
        result.extend(_event_nodes(child))
    return result


def _event_xml(node):
    return (node.namespace,node.name,sorted([(a["namespace"],a["name"],a["value"]) for a in node.attributes]),node.text,[_event_xml(c) for c in node.children])


def prepare_update_event_registration(runtime):
    """Reduce registration fields globally by GUID before deciding removals.

    Event/task/template definitions are intentionally not treated as registry
    data. Unsupported changed channel configuration is rejected by the planner.
    Equal shared GUID declarations must agree, including channel order.
    """
    result = dict(before={},after={})
    for change in runtime["transitions"]:
        for side in ["before","after"]:
            if change[side] == None:
                continue
            captured = change.get("documents",{}).get(side)
            root = captured[1] if captured != None and captured[0] == change[side] else binary.xml(change[side],discard_whitespace=True).root
            for provider in _event_nodes(root):
                attrs = _event_attributes(provider)
                guid = attrs.get("guid", "").lower()
                windows.guid_bytes(guid)
                if len(guid)!=38 or guid[0]!="{" or guid[-1]!="}":
                    fail("event provider requires canonical braced GUID")
                fields = {n:attrs[n] for n in ["guid","name","messageFileName","resourceFileName","parameterFileName"] if n in attrs}
                fields["guid"] = guid
                channels = []
                for child in provider.children:
                    if (child.namespace,child.name) != (_EVENT_NS,"channels"):
                        continue
                    for channel in child.children:
                        channels.append(dict(kind=channel.name,namespace=channel.namespace,attributes={n:v for n,v in _event_attributes(channel).items() if n not in ["message","symbol","chid"]},configuration=[_event_xml(n) for n in channel.children]))
                item = dict(fields=fields,channels=channels,unsupported_attributes=sorted([n for n in attrs if n not in ["guid","name","messageFileName","resourceFileName","parameterFileName","message","symbol","controlGuid"]]))
                previous = result[side].get(guid)
                if previous != None and previous != item:
                    fail("conflicting event provider owners: "+guid)
                result[side][guid] = item
    return result


def _event_path(parts):
    return "/"+"/".join([p.replace("%","%25").replace("/","%2f") for p in parts])


def _event_value(value, expand=False):
    if type(value)=="string":
        return dict(type=2 if expand else 1,value=binary.encode(value+chr(0),encoding="utf16le"))
    return dict(type=4,value=binary.u32le(value))


def _event_write(effects,hive,parts,name,value,expand=False,qword=False):
    raw = dict(type=11,value=binary.u64le(value)) if qword else _event_value(value,expand)
    effects["values"].append(dict(hive=hive,key=_event_path(parts),name=name,**raw))


def _event_key(effects,states,hive,parts):
    identity = tuple([p.lower() for p in parts])
    state = states[hive]
    if identity in state["keys"]:
        return state["keys"][identity]
    existing = state["hive"].find(parts)
    if existing != None:
        security = existing.security
    else:
        if not parts:
            fail("event registration cannot create a hive")
        security = build_update_driver_key_security(_event_key(effects,states,hive,parts[:-1]))
    state["keys"][identity] = security
    effects["keys"].append(dict(hive=hive,key=_event_path(parts),security=security))
    return security


def _event_channel_refs(item):
    ids = {}
    for channel in item["channels"]:
        value = channel["attributes"].get("value")
        if value != None:
            number = int(value,0)
            if number < 0 or number > 255 or number in ids:
                fail("invalid or duplicate event channel value")
            ids[number] = True
    result = []
    next_id = 16
    for channel in item["channels"]:
        attrs = channel["attributes"]
        if channel["namespace"] != _EVENT_NS or channel["kind"] not in ["channel","importChannel"] or not attrs.get("name"):
            fail("unsupported event channel declaration")
        number = int(attrs["value"],0) if "value" in attrs else None
        if number == None:
            for unused in range(256):
                if next_id not in ids:
                    break
                next_id += 1
            if next_id>255:
                fail("event channel values exhausted")
            number = next_id
            next_id += 1
        result.append(dict(channel=channel,id=number,imported=channel["kind"]=="importChannel"))
    return result


def _event_channel_values(guid,channel):
    attrs=channel["attributes"]
    if channel["configuration"] or any([n not in ["name","type","isolation","enabled","value"] for n in attrs]):
        fail("event channel configuration requires separate policy")
    if attrs.get("type") not in ["Admin","Operational"] or attrs.get("isolation","Application") not in ["Application","System"] or attrs.get("enabled","false") not in ["true","false"]:
        fail("unsupported changed event channel kind or policy")
    isolation = int(attrs.get("isolation","Application")=="System")
    return dict(Type=int(attrs["type"]=="Operational"),Isolation=isolation,Enabled=int(attrs.get("enabled","false")=="true"),OwningPublisher=guid,ChannelAccess=_SYSTEM_ACCESS if isolation else _APPLICATION_ACCESS)


def _event_expected_publisher(item):
    fields=item["fields"]
    if not fields.get("name") or not fields.get("resourceFileName") or item["unsupported_attributes"]:
        fail("unsupported changed event publisher fields")
    return {"(default)":fields["name"]} | {name[0].upper()+name[1:]:fields[name] for name in ["resourceFileName","messageFileName","parameterFileName"] if name in fields}


def plan_update_event_registry(root,declarations,control_set):
    """Construct exact bounded publisher/channel/shared-session hive effects.

    Preexisting changed publishers must match the old declared registration.
    Unknown extra child state is not destroyed. Changed channel modes, custom
    access/logging/publishing, external user configuration and unestablished
    key-creation security fail before any hive publication.
    """
    if not control_set.startswith("controlset") or len(control_set)!=13 or not control_set[10:].isdigit() or int(control_set[10:])==0:
        fail("event registration requires a canonical selected control set")
    states={}
    bindings=[]
    effects=dict(keys=[],values=[],key_deletions=[],value_deletions=[])
    for name in ["SOFTWARE","SYSTEM"]:
        path="/Windows/System32/config/"+name
        source=root.find(path)
        if source==None:
            fail("event registration requires physical hive "+name)
        states[name]=dict(hive=windows.hive(source),keys={})
        bindings.append(dict(hive=name,prefix="/",target=name,path=path,source=source))
    before,after=declarations["before"],declarations["after"]
    changed=sorted({g:True for side in [before,after] for g in side if before.get(g)!=after.get(g)})
    owners={}
    for guid,item in after.items():
        for ref in _event_channel_refs(item):
            if not ref["imported"]:
                name=ref["channel"]["attributes"]["name"].lower()
                if name in owners and owners[name]!=guid:
                    fail("conflicting final event channel owners")
                owners[name]=guid
    software=states["SOFTWARE"]["hive"]
    system=states["SYSTEM"]["hive"]
    sessions={}
    report=dict(changed_publishers=changed,installed_publishers=0,removed_publishers=0,channels=0,autologgers=0)
    for guid in changed:
        old,new=before.get(guid),after.get(guid)
        parts=_EVENT_ROOT+["Publishers",guid]
        existing=software.find(parts)
        if old!=None:
            if existing==None or existing.values!=_event_expected_publisher(old):
                fail("changed publisher does not match old registration: "+guid)
            references=_event_channel_refs(old)
            if sorted([c.name for c in existing.children]) != (["ChannelReferences"] if references else []):
                fail("changed publisher contains undeclared child state")
            if references:
                parent=software.find(parts+["ChannelReferences"])
                if parent.values!={"Count":len(references)} or sorted([c.name for c in parent.children])!=sorted([str(i) for i in range(len(references))]):
                    fail("changed publisher references disagree")
                for i,ref in enumerate(references):
                    child=software.find(parts+["ChannelReferences",str(i)])
                    expected={"(default)":ref["channel"]["attributes"]["name"],"Id":ref["id"],"Flags":int(ref["imported"])}
                    if child.values!=expected or child.children:
                        fail("changed publisher reference metadata disagrees")
        elif existing!=None:
            fail("new event publisher unexpectedly exists: "+guid)
        if new==None:
            effects["key_deletions"].append(dict(hive="SOFTWARE",key=_event_path(parts)))
            report["removed_publishers"]+=1
        else:
            expected_new = _event_expected_publisher(new)
            if old!=None and sorted(_event_expected_publisher(old)) != sorted(expected_new):
                fail("changed publisher optional fields require explicit replacement policy")
            _event_key(effects,states,"SOFTWARE",parts)
            for name,value in expected_new.items():
                _event_write(effects,"SOFTWARE",parts,name,value,expand=name!="(default)")
            refs=_event_channel_refs(new)
            if old!=None and _event_channel_refs(old)!=refs:
                fail("changed reference layout requires explicit replacement policy")
            if refs:
                refparts=parts+["ChannelReferences"]
                _event_key(effects,states,"SOFTWARE",refparts)
                _event_write(effects,"SOFTWARE",refparts,"Count",len(refs))
                for i,ref in enumerate(refs):
                    child=refparts+[str(i)]
                    _event_key(effects,states,"SOFTWARE",child)
                    for name,value in {"(default)":ref["channel"]["attributes"]["name"],"Id":ref["id"],"Flags":int(ref["imported"])}.items():
                        _event_write(effects,"SOFTWARE",child,name,value)
            report["installed_publishers"]+=1
        # Shared Admin/Operational sessions use the channel reference ordinal,
        # not the explicit/allocated event channel ID, for the keyword bit.
        for side,item in [("before",old),("after",new)]:
            if item==None:
                continue
            refs=_event_channel_refs(item)
            if len(refs)>8:
                fail("event provider exceeds shared-session channel capacity")
            for i,ref in enumerate(refs):
                channel=ref["channel"]
                name=channel["attributes"]["name"]
                cparts=_EVENT_ROOT+["Channels",name]
                current=software.find(cparts)
                if ref["imported"]:
                    if current==None or current.values.get("Type") not in [0,1] or current.values.get("Isolation") not in [0,1]:
                        fail("unsupported imported event channel")
                    values=current.values
                else:
                    values=_event_channel_values(guid,channel)
                    if side=="before":
                        if current==None or current.values!=values or current.children:
                            fail("changed channel has unestablished current configuration")
                        if name.lower() not in owners:
                            effects["key_deletions"].append(dict(hive="SOFTWARE",key=_event_path(cparts)))
                    else:
                        if current!=None:
                            old_owner=current.values.get("OwningPublisher","").lower()
                            if old_owner not in before or not any([r["channel"]["attributes"].get("name","").lower()==name.lower() and not r["imported"] for r in _event_channel_refs(before[old_owner])]):
                                fail("channel reparenting has no old declaration")
                            for field,value in values.items():
                                if field!="OwningPublisher" and current.values.get(field)!=value:
                                    fail("channel reparenting changes existing configuration")
                        _event_key(effects,states,"SOFTWARE",cparts)
                        for field,value in values.items():
                            _event_write(effects,"SOFTWARE",cparts,field,value)
                        report["channels"]+=1
                session="EventLog-System" if values["Isolation"] else "EventLog-Application"
                pair=sessions.setdefault((session,guid),dict(before=0,after=0))
                if values["Enabled"]:
                    pair[side] |= 1 << (63-i)
    for (session,guid),bits in sessions.items():
        parts=[control_set,"Control","WMI","Autologger",session,guid]
        current=system.find(parts)
        common=dict(EnableLevel=0,EnableProperty=1,Enabled=1,LoggerName=session,MatchAllKeyword=0)
        if bits["before"]:
            expected=dict(common,MatchAnyKeyword=bits["before"])
            if current==None or current.values!=expected or current.children:
                fail("autologger does not match declared old provider channels")
        elif current!=None:
            fail("new event autologger unexpectedly exists")
        if bits["after"]:
            _event_key(effects,states,"SYSTEM",parts)
            for name,value in dict(common,MatchAnyKeyword=bits["after"]).items():
                _event_write(effects,"SYSTEM",parts,name,value,qword=name in ["MatchAllKeyword","MatchAnyKeyword"])
            report["autologgers"]+=1
        elif current!=None:
            effects["key_deletions"].append(dict(hive="SYSTEM",key=_event_path(parts)))
    plans=plan_update_registry_effects(root,effects,bindings)
    return dict(plans=plans,report=report)


def validate_update_event_resources(root,declarations):
    """Validate newly registered GUIDs in the actual final projected PE bytes."""
    checked={}
    names={p.lower():p for p in root.files}
    if len(names)!=len(root.files):
        fail("event resources have ambiguous case-insensitive image paths")
    for guid,item in declarations["after"].items():
        if declarations["before"].get(guid)==item:
            continue
        fields=item["fields"]
        for field in ["resourceFileName","messageFileName","parameterFileName"]:
            if field not in fields:
                continue
            name=fields[field].replace(chr(92),"/")
            if not name.lower().startswith("%systemroot%/") or any([p in [".","..",""] for p in name.split("/")]):
                fail("event resource has an unbound image path")
            path="/Windows/"+name[len("%systemroot%/"):]
            file=root.find(names.get(path.lower(),path))
            if file==None:
                fail("missing final event resource: "+path)
            if field=="resourceFileName":
                if path.lower() not in checked:
                    pe=windows.pe(file)
                    resources=[r for r in pe.resources if r["type"]=="WEVT_TEMPLATE"]
                    if not resources:
                        fail("event resource has no WEVT_TEMPLATE")
                    checked[path.lower()]={g:True for resource in resources for g in windows.event_template_providers(resource["data"])}
                if guid not in checked[path.lower()]:
                    fail("final event resource does not contain its registered provider: "+guid)
    return len(checked)
