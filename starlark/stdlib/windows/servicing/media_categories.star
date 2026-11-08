"""Construct the MediaCategories subset of admitted KS registration.

This does not claim all Include/Needs or RunOnce work is complete. Existing
values survive unless the exact KS declaration replaces them. Newly created
keys use the explicit target administrator subject, never an oracle host SID.
"""
_SYSTEM='/Windows/System32/config/SYSTEM'
_PARENT='/ControlSet001/Control/MediaCategories'
_DACL='D:(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;;KA;;;BA)(A;CIIO;KA;;;CO)(A;CI;KR;;;S-1-15-2-1)(A;CI;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)'

# Server 26100.32230 MediaCategories, SYSTEM owner/group and inherited DACL.
# Native SeAssignSecurity produces 8c04 (not the parent's present-NULL SACL).
_SERVER_PARENT=binary.decode("0100148cc4000000d000000000000000140000000200b00006000000001218001900020001020000000000052000000021020000001218003f000f0001020000000000052000000020020000001214003f000f00010100000000000512000000001a14003f000f000101000000000003000000000012180019000200010200000000000f02000000010000000012380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000","hex")

def _child_security(parent, subject_group):
    selected=windows.security_descriptor_parts(parent)
    if selected==windows.security_descriptor_parts(_SERVER_PARENT):
        return windows.inherit_registry_security(windows.compile_sddl('O:BAG:'+subject_group),parent)
    expected=windows.compile_sddl('O:BAG:'+subject_group+_DACL)
    parts=windows.security_descriptor_parts(expected)
    if selected['control']!=0x8004 or selected['resource_manager_control'] or selected['sacl']!=None or selected['dacl']!=parts['dacl'] or selected['owner']!=parts['owner']:
        fail('unestablished MediaCategories creation parent')
    return expected

def plan_update_media_categories(root, jobs, ks_source, subject_group):
    """Plan supported amd64 MediaCategories updates from driver jobs, exact ks.inf bytes and an explicit subject group."""
    requested=[]
    for job in jobs:
        if job['architecture'].lower()!='amd64': continue
        inf=windows.inf(root.find(job['inf_source']))
        for section,values in inf.json.items():
            fields={k.lower():v for k,v in values.items()}
            if 'ks.registration' not in [v.lower() for v in fields.get('needs',[])]: continue
            if 'ks.inf' not in [v.lower() for v in fields.get('include',[])]:
                fail('KS registration lacks explicit ks.inf include')
            requested.append((job['inf_source'],section))
    if not requested: return None
    names=root.path_names(lower=True)
    ks_path=names.get('/windows/inf/ks.inf')
    if ks_path==None or digest(root.find(ks_path))!=digest(ks_source):
        fail('KS source differs from admitted baseline INF')
    ks=windows.inf(ks_source)
    fields={k.lower():v for k,v in ks.section('KS.Registration').items()}
    if sorted(fields)!=['addreg']: fail('unmodeled KS registration directives')
    source=root.find(_SYSTEM)
    hive=windows.hive(source)
    parent=hive.find(_PARENT)
    if parent==None: fail('MediaCategories parent is absent')
    descriptor=_child_security(parent.security,subject_group)
    patches=[]
    keys={}
    seen={}
    for section in fields['addreg']:
        for patch in ks.section_patches(section):
            if patch['hive']!='SYSTEM' or not patch['key'].lower().startswith(_PARENT.lower()+'/'): continue
            key=patch['key']
            leaf=key[len(_PARENT)+1:]
            if '/' in leaf or not leaf.startswith('{') or not leaf.endswith('}'):
                fail('unmodeled MediaCategories key depth')
            if patch['type'] not in ['REG_SZ','REG_BINARY']: fail('unsupported MediaCategories value type')
            identity=(key.lower(),patch['name'].lower())
            if identity in seen and seen[identity]!=patch: fail('conflicting MediaCategories declarations')
            if identity in seen: continue
            seen[identity]=patch
            patches.append({k:v for k,v in patch.items() if k!='hive'})
            if hive.find(key)==None: keys[key.lower()]=dict(key=key,security=descriptor)
    if not patches: fail('requested KS registration has no MediaCategories declarations')
    file=windows.hive_from_patches('SYSTEM',patches,keys=list(keys.values()),source=source)
    after=windows.hive(file)
    for key in keys.values():
        if windows.security_descriptor_parts(after.find(key['key']).security)!=windows.security_descriptor_parts(descriptor):
            fail('MediaCategories security readback differs')
    for patch in patches:
        if after.find(patch['key']).values.get(patch['name'])!=patch['value']:
            fail('MediaCategories value readback differs')
    proofs={p:digest(root.find(p)) for p,s in requested}
    proofs[ks_path]=digest(ks_source)
    return dict(path=_SYSTEM,source_hash=digest(source),file=file,proofs=proofs,requests=len(requested),keys=len(keys),values=len(patches))

def apply_update_media_categories(root, plan):
    """Recheck the source hive and INF proofs before publishing MediaCategories; None represents an empty plan."""
    if plan==None: return dict(requests=0,keys=0,values=0)
    if digest(root.find(plan['path']))!=plan['source_hash']: fail('MediaCategories hive changed before publication')
    for path,expected in plan['proofs'].items():
        if root.find(path)==None or digest(root.find(path))!=expected: fail('MediaCategories source changed before publication')
    root.write(plan['path'],plan['file'])
    return {k:plan[k] for k in ['requests','keys','values']}
