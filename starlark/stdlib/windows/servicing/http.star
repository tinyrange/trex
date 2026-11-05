"""Execute the admitted HTTPAI queue through the native CSI harness.

The XML reader supplies CDF input, not predicted registry effects. The actual
DLL decides which writes to make; publication is bounded and atomic.
"""
load("@stdlib//windows/servicing:installer.star", "run_http_installer")

_NS = "urn:schemas-microsoft-com:asm.v3"
_SUFFIX = "/Services/HTTP/Parameters/UrlAclInfo"
_HTTP_PATH = "/Windows/WinSxS/amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35_10.0.26100.9703_none_875daae85585b1d5/httpai.dll"
_HTTP_SHA256 = "cf6e64fe29b3726acd814dd56e1de9416d3ed97d6da119f99c44e5da339dfaa8"

def http_reservations(document):
    """Parse the supported HTTPAI declaration shape into reservations; reject unsupported attributes or structure."""
    result = {}
    nodes = [n for n in document.children if n.namespace == _NS and n.name == "HTTPAI"]
    if len(nodes) != 1 or nodes[0].attributes or nodes[0].text.strip():
        fail("unsupported HTTPAI declaration")
    for node in nodes[0].children:
        attrs = {a["name"]: a["value"] for a in node.attributes}
        if node.namespace != _NS or node.name != "AddUrl" or node.children or node.text.strip() or len(attrs) != len(node.attributes) or sorted(attrs) != ["sddl", "url"] or any([a["namespace"] for a in node.attributes]):
            fail("unsupported HTTPAI URL operation")
        url = attrs["url"]
        if not url.startswith(("http://", "https://")) or not url.endswith("/") or any([ord(c) < 33 or ord(c) > 126 for c in url.elems()]) or "$(" in url or "$(" in attrs["sddl"] or chr(0) in attrs["sddl"]:
            fail("HTTPAI requires resolved ASCII URL and SDDL")
        if url.lower() in result:
            fail("duplicate HTTPAI reservation")
        result[url.lower()] = attrs
    return result

def http_installer_jobs(runtime):
    """Select bounded HTTP installer jobs and reservations from runtime transitions without mutating the image."""
    jobs, reservations = [], {}
    for transition in runtime["transitions"]:
        if not any([d.get((_NS, "HTTPAI"), 0) for d in transition["directives"]]):
            continue
        if transition["before"] == None or transition["after"] == None:
            fail("HTTPAI addition/removal needs a separate queue policy")
        for side in ["before", "after"]:
            if windows.csi_identity(transition["component_identities"][side]).processor_architecture != "amd64":
                fail("unsupported HTTPAI architecture")
        before = http_reservations(transition["documents"]["before"][1])
        after = http_reservations(transition["documents"]["after"][1])
        if before != after:
            fail("changed HTTPAI reservations need uninstall/install ordering policy")
        # This admits a bounded queue, not a manifest-equality no-op.
        for name, row in after.items():
            if name in reservations:
                fail("overlapping HTTPAI component reservations")
            reservations[name] = row
        jobs.append(dict(identity=transition["component_identities"]["after"],rows=list(after.values())))
    return jobs, reservations

def publish_http_effects(root, reservations, effects):
    """Validate native HTTP writes against reservation authority and the selected SYSTEM control set before publication."""
    path = "/Windows/System32/config/SYSTEM"
    source = root.find(path)
    system = windows.hive(source)
    select = system.find("/Select")
    current = None if select == None else select.values.get("Current")
    if type(current) != "int" or current < 1 or current > 999 or select.value_records["Current"].type != 4:
        fail("invalid HTTPAI control set")
    key_path = "/ControlSet" + ("00" + str(current))[-3:] + _SUFFIX
    prior = system.find(key_path)
    if prior == None:
        fail("HTTPAI key creation requires established inherited security")
    values = {n.lower(): (n, r.type, r.raw) for n, r in prior.value_records.items()}
    patches, seen = [], {}
    for effect in effects:
        name = effect["name"].lower()
        if effect["key"].lower() != key_path.lower() or name not in reservations or effect["type"] != 3 or not effect["raw"]:
            fail("native HTTPAI write outside admitted authority")
        if name in seen: fail("duplicate native HTTPAI write")
        seen[name] = True
        existing = values.get(name)
        if existing != None and existing[1:] == (effect["type"], effect["raw"]): continue
        patches.append(dict(key=key_path, name=effect["name"] if existing == None else existing[0], type=effect["type"], value=effect["raw"]))
    if sorted(seen) != sorted(reservations):
        fail("native HTTPAI did not write its complete admitted table")
    if patches:
        updated = windows.patch_hive(source, patches)
        actual = windows.hive(updated).find(key_path)
        if actual.security != prior.security:
            fail("HTTPAI changed registry key security")
        for patch in patches:
            record = actual.value_records[patch["name"]]
            if record.type != patch["type"] or record.raw != patch["value"]:
                fail("HTTPAI serialized reservation readback differs")
        for name, record in prior.value_records.items():
            if name.lower() not in reservations and (actual.value_records[name].raw != record.raw or actual.value_records[name].type != record.type):
                fail("HTTPAI changed unrelated reservation")
        if digest(root.find(path)) != digest(source):
            fail("HTTPAI source hive changed")
        root.write(path, updated)
    return patches

def apply_update_http(root, runtime):
    """Execute the qualified native HTTP installer and publish checked offline reservations; return phase evidence, not CBS completion."""
    jobs, reservations = http_installer_jobs(runtime)
    if not jobs:
        return dict(components=0, reservations=0, native_writes=0, values=0)
    file = root.find(_HTTP_PATH)
    if file == None or hex(digest(file, algorithm="sha256")) != _HTTP_SHA256:
        fail("native HTTPAI requires exact serviced source bytes")
    source = root.find("/Windows/System32/config/SYSTEM")
    system = windows.hive(source)
    effects, executions = [], []
    started = clock.monotonic()
    for job in jobs:
        result = run_http_installer(file, system, job["rows"])
        effects.extend(result["patches"])
        executions.append(dict(identity=str(job["identity"]),steps=result["result"].steps,writes=len(result["patches"])))
    seconds = clock.monotonic()-started
    if digest(root.find("/Windows/System32/config/SYSTEM")) != digest(source):
        fail("HTTPAI source changed during native execution")
    patches = publish_http_effects(root, reservations, effects)
    return dict(components=len(jobs), reservations=len(reservations), native_writes=len(effects), values=len(patches), changes=patches, executions=executions, seconds=seconds, installer_sha256=_HTTP_SHA256, policy="executed native offline HTTPAI; bounded paired queue, not complete CBS installation")
