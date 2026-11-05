"""Publish native phase-three service-category effects, never predicted merges.

XML limits which SvcHost values the admitted native jobs may touch. Native WCP
alone decides list contents, ordering, and deletions. Online service creation
and CBS transaction completion are not covered by this adapter.
"""
load("@stdlib//windows/servicing:native_midground.star", "service_category_jobs", "run_native_service_category")
load("@stdlib//windows/servicing:registry_effects.star", "plan_update_registry_effects", "apply_update_registry_effects")

_NS="urn:schemas-microsoft-com:asm.v3"
_PATH="/Windows/System32/config/SOFTWARE"
_KEY="/Microsoft/Windows NT/CurrentVersion/SvcHost"

def _children(node,name):
    return [n for n in node.children if n.namespace==_NS and n.name==name]

def _attributes(node):
    attrs={a["name"]:a["value"] for a in node.attributes if not a["namespace"]}
    if len(attrs)!=len(node.attributes): fail("ambiguous service category attributes")
    return attrs

def _name(name):
    if type(name)!="string" or not name or name=="(default)" or any([c in name for c in [chr(0),chr(92),"/","$("]]):
        fail("invalid service category name")
    return name.lower()

def service_category_authority(jobs):
    """Read declared group names only; this is not a replacement merger."""
    authority={}
    for row in jobs:
        for file in row:
            if file==None: continue
            if file.size>16<<20: fail("service category authority manifest exceeds bound")
            document=binary.xml(file,discard_whitespace=True).root
            identities=_children(document,"assemblyIdentity")
            if len(identities)!=1: fail("service category requires one manifest identity")
            architecture=_attributes(identities[0]).get("processorArchitecture")
            if architecture not in ["amd64","wow64"]: fail("unsupported service category architecture")
            key=("/Wow6432Node" if architecture=="wow64" else "")+_KEY
            for memberships in _children(document,"memberships"):
                for category in _children(memberships,"categoryMembership"):
                    ids=_children(category,"id")
                    if len(ids)!=1: fail("ambiguous service category identity")
                    identity=_attributes(ids[0])
                    if identity.get("typeName")!="SvcHost": continue
                    if any([identity.get(k)!=v for k,v in dict(name="Microsoft.Windows.Categories",version="1.0.0.0",publicKeyToken="365143bb27e7ac8b").items()]): fail("unrecognized SvcHost category identity")
                    for instance in _children(category,"categoryInstance"):
                        name=_attributes(instance).get("subcategory")
                        authority[(key.lower(),_name(name))]=True
    return authority

def plan_native_service_category(root,jobs,effects,source):
    """Require the execution's exact SOFTWARE epoch and validate before writes."""
    if sorted(effects)!=["key_deletions","keys","value_deletions","values"] or effects["keys"] or effects["key_deletions"]:
        fail("native service category emitted unsupported key effects")
    current=root.find(_PATH)
    if source==None or current==None or digest(current)!=digest(source): fail("native service category source changed before planning")
    authority=service_category_authority(jobs)
    hive=windows.hive(source)
    seen={}
    for field in ["values","value_deletions"]:
        for record in effects[field]:
            identity=(record["key"].lower(),_name(record["name"]))
            if record["hive"]!="SOFTWARE" or identity not in authority: fail("native service category effect outside queue authority")
            if identity in seen: fail("duplicate native service category final value")
            seen[identity]=True
            if hive.find(record["key"])==None: fail("native service category key creation is not established")
            if field=="values":
                raw=record["value"]
                if record["type"]!=7 or type(raw)!="bytes" or len(raw)<4 or len(raw)>1<<20 or len(raw)%2: fail("invalid service category MULTI_SZ")
                text=binary.text(raw,encoding="utf16le")
                if binary.encode(text,encoding="utf16le")!=raw or not text.endswith(chr(0)*2): fail("invalid service category MULTI_SZ termination")
                names=text[:-2].split(chr(0)) if text[:-2] else []
                for name in names: _name(name)
    return plan_update_registry_effects(root,effects,[dict(hive="SOFTWARE",prefix="/",target="SOFTWARE",path=_PATH,source=source)])

def apply_native_service_category(root,wcp_file,queue,changes,inspect_manifests,token_privileges,instruction_limit=500000000):
    """Run native service jobs with explicit privileges, validate their effects and publish only authorized hive changes."""
    jobs=service_category_jobs(queue,changes,inspect_manifests)
    if not jobs: return dict(jobs=0,publication=dict(hives=0,values=0,deleted_values=0,removed_keys=0))
    sources={k:root.find("/Windows/System32/config/"+k) for k in ["SOFTWARE","SYSTEM"]}
    if any([f==None for f in sources.values()]): fail("native service category target hives missing")
    result=run_native_service_category(wcp_file,{k:windows.hive(f) for k,f in sources.items()},jobs,instruction_limit=instruction_limit,token_privileges=token_privileges)
    for hive,source in sources.items():
        if digest(root.find("/Windows/System32/config/"+hive))!=digest(source): fail("native service category source changed during execution")
    plans=plan_native_service_category(root,jobs,result["effects"],sources["SOFTWARE"])
    result["publication"]=apply_update_registry_effects(root,plans)
    return result
