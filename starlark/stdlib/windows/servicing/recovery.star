"""Verified recovery publication; generated metadata policy remains explicit.

The production generator binds every record to an admitted forward edge.
WCP supplies a fixed reverse-target timestamp, independent of payload times.
File security uses component-staging policy, including driver ACLs.
"""
load('@stdlib//windows/servicing:runtime.star','build_servicing_created_security','build_servicing_staged_file_security_request','assign_servicing_staged_file_security')

# WCP 26100.9703, PDB 7CC21FAF1E625E052DD8ADB23E8B25F21:
# DeltaDecompressBuffer at 0x7bdb0 writes high/low FILETIME DWORDs at
# 0x7bf25/0x7bf2c, passes their address in R9 at 0x7bfe8 to
# ApplyDeltaGetReverseB. The codec copies this supplied FILETIME verbatim.
# This is a servicing constant, not a wall clock or reference-image value.
SERVICING_RECOVERY_FILETIME=0x019db1ded5d71680

def plan_inherited_recovery(root,payloads):
    """Plan inherited recovery records from explicit root/payload state without treating missing evidence as a recovery marker."""
    names=root.path_names(lower=True)
    result=[]
    seen={}
    for plan in payloads['stages'].values():
        entries=plan.files
        for i,entry in enumerate(entries):
            if entry.kind!='component-file' or entry.source_mode!='predecessor': continue
            if entry.store_path.lower() in payloads.get('preserved_staging_paths',{}): continue
            inherited=plan.inherited_recovery(i)
            if inherited==None: continue
            parts=entry.store_path.split('/',4)
            if len(parts)!=5 or parts[1:3]!=['Windows','WinSxS'] or not entry.file_key.startswith('f!'):
                fail('invalid inherited recovery destination')
            destination='/'.join(parts[:4])+'/r/'+parts[4]
            source=names.get(inherited.source_path.lower())
            installed=names.get(entry.store_path.lower())
            if source==None or installed==None: fail('inherited recovery source absent from constructed image')
            if destination.lower() in names or destination.lower() in seen: fail('inherited recovery destination already exists')
            record_hash=digest(inherited.file,algorithm='sha256')
            info=windows.delta_info(inherited.file,psf_record=True,maximum=128<<20)
            if digest(root.find(source),algorithm='sha256')!=record_hash: fail('inherited recovery record changed')
            if digest(root.find(installed),algorithm='sha256')!=info.extension_hash: fail('inherited recovery installed content changed')
            # The native carried object is a hardlink, not a new file with
            # inherited SYSTEM security. Keep the admitted base object's SD,
            # EAs, attributes and times; reference images never supply them.
            seen[destination.lower()]=True
            result.append(dict(source=source,installed=installed,path=destination,stem=parts[3].lower(),key=entry.file_key,
                record_hash=record_hash,source_hash=info.extension_hash,
                order=root.get_metadata(source).write_order,installed_order=root.get_metadata(installed).write_order))
    return result

def apply_inherited_recovery(root,plan):
    """Validate and publish planned inherited recovery records and metadata on root."""
    names=root.path_names(lower=True)
    for row in plan:
        if root.find(row['source'])==None or root.get_metadata(row['source']).write_order!=row['order']: fail('inherited recovery source changed')
        if root.find(row['installed'])==None or root.get_metadata(row['installed']).write_order!=row['installed_order']: fail('inherited recovery installed content changed')
        if row['path'].lower() in names: fail('inherited recovery destination changed')
    markers={}
    for row in plan:
        parts=row['path'].split('/')
        parent=names['/'.join(parts[:4]).lower()]
        for i in range(4,len(parts)-1):
            desired=parent+'/'+parts[i]
            current=names.get(desired.lower())
            if current==None:
                sd=root.get_security(parent) if i==4 else build_servicing_created_security(root.get_security(parent),directory=True)
                root.mkdir(desired)
                root.set_security(desired,sd)
                names[desired.lower()]=desired
                current=desired
            parent=current
        destination=parent+'/'+parts[-1]
        root.hardlink(row['source'],destination)
        names[destination.lower()]=destination
        markers.setdefault(row['stem'],{})[row['key']]=dict(path=destination,sha256=row['record_hash'])
    return markers

def retained_recovery_flags(root,payloads,stem,name,flags):
    """Read retained recovery flags from established image records; do not invent recovery state for absent records."""
    proof=payloads.get('retained_recovery',{}).get(stem.lower(),{}).get(name)
    if proof==None: return flags
    file=root.find(proof['path'])
    if file==None or digest(file,algorithm='sha256')!=proof['sha256']: fail('retained recovery record changed before CSI persistence')
    return flags|0x100


def plan_generated_recovery(root,payloads,target_filetime):
    """Plan generated recovery records with an explicit target FILETIME; do not infer timestamps from wall-clock or reference output."""
    # No implicit clock, metadata borrowed from an oracle, or inferred time.
    if target_filetime<0 or target_filetime>=1<<64: fail('invalid recovery target timestamp')
    names=root.path_names(lower=True)
    result=[]
    seen={}
    security_cache={}
    seed=windows.compile_sddl('O:SYG:SY')
    for plan in payloads['stages'].values():
        driver_kinds={c.stem.lower():windows.csi_identity(c.identity).type.lower() in ['driverupdate','dualmodedriver'] for c in plan.components}
        entries=plan.files
        for i in plan.read_order:
            entry=entries[i]
            if entry.store_path.lower() in payloads.get('preserved_staging_paths',{}): continue
            basis=entry.recovery_basis
            if basis==None: continue
            parts=entry.store_path.split('/',4)
            if entry.kind!='component-file' or entry.source_mode!='payload' or len(parts)!=5 or parts[1:3]!=['Windows','WinSxS'] or not entry.file_key.startswith('f!'):
                fail('invalid generated recovery destination')
            destination='/'.join(parts[:4])+'/r/'+parts[4]
            installed=names.get(entry.store_path.lower())
            if installed==None: fail('generated recovery installed content absent')
            if destination.lower() in names or destination.lower() in seen: fail('generated recovery destination already exists')
            record=plan.create_recovery(i,target_filetime=target_filetime,lazy=True)
            info=windows.delta_info(record,psf_record=True,maximum=128<<20)
            if info.target_hash!=basis.sha256 or info.target_size!=basis.size or info.target_filetime!=target_filetime:
                fail('generated recovery differs from admitted basis or timestamp')
            if digest(root.find(installed),algorithm='sha256')!=info.extension_hash:
                fail('generated recovery installed content changed')
            # Recovery uses staging security, not the installed file's final
            # runtime ACL (which activation can subsequently replace).
            parent_sd=_planned_recovery_parent_security(root,names,destination)
            security_key=(parent_sd,driver_kinds[parts[3].lower()])
            if security_key not in security_cache:
                request=build_servicing_staged_file_security_request(parent_sd,driver=security_key[1])
                security_cache[security_key]=assign_servicing_staged_file_security(seed,request)
            seen[destination.lower()]=True
            result.append(dict(file=record,installed=installed,path=destination,stem=parts[3].lower(),key=entry.file_key,
                record_hash=digest(record,algorithm='sha256'),installed_order=root.get_metadata(installed).write_order,
                security=security_cache[security_key],attributes=32))
    return result


def apply_generated_recovery(root,plan):
    """Check the complete generated-recovery batch before writing records or CSI markers; return emitted markers."""
    names=root.path_names(lower=True)
    seen={}
    # Check the whole batch before writing any record or setting CSI flags.
    # Regeneration errors after cache eviction must not publish bad bytes.
    for row in plan:
        if root.find(row['installed'])==None or root.get_metadata(row['installed']).write_order!=row['installed_order']:
            fail('generated recovery installed content changed')
        if row['path'].lower() in names or row['path'].lower() in seen: fail('generated recovery destination changed')
        if digest(row['file'],algorithm='sha256')!=row['record_hash']: fail('generated recovery record changed')
        seen[row['path'].lower()]=True
    markers={}
    for row in plan:
        parts=row['path'].split('/')
        parent=names['/'.join(parts[:4]).lower()]
        for i in range(4,len(parts)-1):
            desired=parent+'/'+parts[i]
            current=names.get(desired.lower())
            if current==None:
                sd=root.get_security(parent) if i==4 else build_servicing_created_security(root.get_security(parent),directory=True)
                root.mkdir(desired)
                root.set_security(desired,sd)
                names[desired.lower()]=desired
                current=desired
            parent=current
        destination=parent+'/'+parts[-1]
        root.write(destination,row['file'])
        root.set_security(destination,row['security'])
        root.set_file_attributes(destination,row['attributes'])
        names[destination.lower()]=destination
        markers.setdefault(row['stem'],{})[row['key']]=dict(path=destination,sha256=row['record_hash'])
    return markers


def _planned_recovery_parent_security(root,names,destination):
    parts=destination.split('/')
    parent='/'.join(parts[:4])
    sd=root.get_security(names[parent.lower()])
    for i in range(4,len(parts)-1):
        parent+='/'+parts[i]
        existing=names.get(parent.lower())
        if existing!=None:
            sd=root.get_security(existing)
        elif i!=4:
            sd=build_servicing_created_security(sd,directory=True)
    return sd
