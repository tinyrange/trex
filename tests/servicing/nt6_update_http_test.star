"""Physical HTTP URL ACL state must not be inferred from unchanged manifests."""
load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//windows/servicing:http.star", "http_installer_jobs", "publish_http_effects")

_NS = "urn:schemas-microsoft-com:asm.v3"
_PATH = "/Windows/System32/config/SYSTEM"
_KEY = "/ControlSet002/Services/HTTP/Parameters/UrlAclInfo"
_ID = b"Microsoft-Windows-PeerDist, Culture=neutral, Version=10.0.26100.9703, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS"
# Native ConvertStringSecurityDescriptorToSecurityDescriptor representation:
# self-relative DACL, allow ACE, GENERIC_EXECUTE (not a mapped file/registry mask), NS.
_SD = binary.decode("010004800000000000000000000000001400000002001c00010000000000140000000020010100000000000514000000", "hex")
_SECURITY = windows.compile_sddl("O:SYG:SYD:P(A;;KA;;;SY)")

def _runtime(changed=False):
    template = '<assembly xmlns="%s"><HTTPAI>%s</HTTPAI></assembly>'
    declarations = ''.join(['<AddUrl url="http://+:80/%s/" sddl="D:(A;;GX;;;NS)"/>' % n for n in ["missing", "stale", "wrongtype", "correct"]])
    before = template % (_NS, declarations)
    after = before.replace("GX", "GA") if changed else before
    docs = {s: (text, binary.xml(text).root) for s, text in [("before", before), ("after", after)]}
    return dict(transitions=[dict(before=before, after=after, documents=docs, directives=[{(_NS,"HTTPAI"):1}]*2, component_identities=dict(before=_ID,after=_ID))])

def _fixture():
    root = directory()
    patches = [dict(key="/Select",name="Current",type="REG_DWORD",value=2)]
    for name, kind, value in [
        ("HTTP://+:80/STALE/", "REG_BINARY", b"old descriptor"),
        ("http://+:80/wrongtype/", "REG_NONE", _SD),
        ("http://+:80/correct/", "REG_BINARY", _SD),
        ("https://+:443/unrelated/", "REG_BINARY", b"retain exactly"),
    ]:
        patches.append(dict(key=_KEY,name=name,type=kind,value=value))
    patches.append(dict(key=_KEY.replace("002","001"),name="http://+:80/missing/",type="REG_SZ",value="inactive control set"))
    root.write(_PATH, windows.hive_from_patches("SYSTEM", patches, keys=[dict(key_parts=_KEY[1:].split("/"),security=_SECURITY)]))
    return root

def _apply(root, runtime):
    jobs, reservations = http_installer_jobs(runtime)
    # Independent publication fixture, not a substitute for the real-DLL smoke.
    effects = [dict(key=_KEY,name=row["url"],type=3,raw=_SD) for row in reservations.values()]
    patches = publish_http_effects(root,reservations,effects)
    return dict(components=len(jobs),reservations=len(reservations),values=len(patches))

def test_unchanged_declarations_repair_physical_state():
    root = _fixture()
    original = root.find(_PATH)
    report = _apply(root, _runtime())
    equal((report["components"], report["reservations"], report["values"]), (1,4,3))
    actual = windows.hive(root.find(_PATH))
    key = actual.find(_KEY)
    for name in ["http://+:80/missing/", "HTTP://+:80/STALE/", "http://+:80/wrongtype/", "http://+:80/correct/"]:
        equal(key.value_records[name].type, 3)
        equal(key.values[name], _SD)
    equal(key.security, _SECURITY)
    equal(key.values["https://+:443/unrelated/"], b"retain exactly")
    equal(actual.find(_KEY.replace("002","001")).values["http://+:80/missing/"], "inactive control set")
    equal(windows.hive(original).find(_KEY).values.get("http://+:80/missing/"), None)
    repaired = digest(root.find(_PATH))
    equal(_apply(root, _runtime())["values"], 0)
    equal(digest(root.find(_PATH)), repaired)

def test_unsupported_transition_is_atomic():
    root = _fixture()
    before = digest(root.find(_PATH))
    raises(_apply, args=[root,_runtime(changed=True)], message="ordering policy")
    equal(digest(root.find(_PATH)), before)

def test_missing_key_does_not_invent_security():
    root = directory()
    root.write(_PATH, windows.hive_from_patches("SYSTEM", [dict(key="/Select",name="Current",type="REG_DWORD",value=2)]))
    before = digest(root.find(_PATH))
    raises(_apply, args=[root,_runtime()], message="inherited security")
    equal(digest(root.find(_PATH)), before)

def test_unexpected_native_write_is_atomic():
    root = _fixture()
    jobs, reservations = http_installer_jobs(_runtime())
    effects = [dict(key=_KEY,name=row["url"],type=3,raw=_SD) for row in reservations.values()]
    before = digest(root.find(_PATH))
    extra = dict(effects[0],key="/ControlSet001/Services/HTTP/Parameters/UrlAclInfo")
    raises(publish_http_effects,args=[root,reservations,effects+[extra]],message="outside admitted authority")
    equal(digest(root.find(_PATH)),before)
    raises(publish_http_effects,args=[root,reservations,effects[:-1]],message="complete admitted table")
    equal(digest(root.find(_PATH)),before)


def test_qualified_installer_sources_fail_closed():
    adapter=testing.module("@stdlib//windows/servicing:installer.star")
    select=adapter["select_basic_installer"]
    for family in ["http","timezone"]:
        root=directory()
        raises(select,args=[root,family],message="one qualified source")
        paths=[record[0] for record in adapter["_QUALIFIED_SOURCES"][family]]
        root.write(paths[0],"not the qualified DLL")
        raises(select,args=[root,family],message="hash differs")
        root.write(paths[1],"another unqualified DLL")
        raises(select,args=[root,family],message="one qualified source")

TEST_SUITE = suite("nt6/update-http", [
    case("qualified_sources", test_qualified_installer_sources_fail_closed),
    case("unchanged_declarations_repair_physical_state", test_unchanged_declarations_repair_physical_state),
    case("unsupported_transition_is_atomic", test_unsupported_transition_is_atomic),
    case("missing_key_does_not_invent_security", test_missing_key_does_not_invent_security),
    case("unexpected_native_write_is_atomic", test_unexpected_native_write_is_atomic),
])
