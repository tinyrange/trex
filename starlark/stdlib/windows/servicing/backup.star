"""BootRecovery backups selected from admitted component transitions.

WCP 9703 ContainsBackup (113310) selects the exact category identity.
FormatBackupFileNameWithReallocate (26c05c) uses the low 32 bits of
RtlHashEncodedLBlob, lowercase, plus the sanitized component filename.
Backups are independent files, not aliases of the protected source object.
"""
load('@stdlib//windows/servicing:runtime.star', 'build_servicing_created_security', 'select_servicing_file_hash')
_NAMESPACES=['urn:schemas-microsoft-com:asm.v1','urn:schemas-microsoft-com:asm.v3']
_DIRECTORY='/Windows/WinSxS/Backup'

def _needed(document):
    tree=binary.xml(document,discard_whitespace=True).root
    for group in tree.children:
        if group.name!='memberships' or group.namespace not in _NAMESPACES: continue
        for membership in group.children:
            if membership.name!='categoryMembership' or membership.namespace not in _NAMESPACES: continue
            for node in membership.children:
                if node.name!='id' or node.namespace not in _NAMESPACES: continue
                attrs={a['name']:a['value'].lower() for a in node.attributes if not a['namespace']}
                if all([attrs.get(k)==v for k,v in [('name','microsoft.windows.categories'),('publicKeyToken','365143bb27e7ac8b'),('typeName','bootrecovery'),('version','1.0.0.0')]]): return True
    return False

def _filename(stem,name):
    # Keep the supported ASCII namespace explicit; never approximate Unicode
    # folding or allow a source path to escape its exact component directory.
    if not name or name in ['.','..'] or any([ord(c)<32 or ord(c)>126 or c in '/'+chr(92) for c in name.elems()]):
        fail('unsupported backup filename')
    folded=name.lower()
    safe=''.join([c for c in folded.elems() if c in 'abcdefghijklmnopqrstuvwxyz0123456789.-_'])
    if not safe: fail('empty sanitized backup filename')
    if len(safe)>60: safe=safe[:29]+'..'+safe[-29:]
    lanes=[0,0,0,0]
    for i,c in enumerate(folded.elems()): lanes[i%4]=(lanes[i%4]*65599+ord(c))&0xffffffff
    h=0
    for lane in lanes: h=(h*((1<<33)-9)+lane)&0xffffffffffffffff
    return stem+'_'+safe+'_'+('00000000'+hex(h&0xffffffff)[2:])[-8:]

def plan_update_backups(root,runtime,payloads):
    """Select BootRecovery copies and retirements from admitted manifests, checking exact staged hashes and retaining source/destination epochs."""
    sources={}
    for plan in payloads['stages'].values():
        entries={entry.store_path.lower():i for i,entry in enumerate(plan.files)}
        for component in plan.components:
            # Baseline/runtime and staged identities may differ only in casing.
            identity=str(component.identity).lower()
            if identity in sources: fail('ambiguous backup component identity')
            sources[identity]=dict(component=component,plan=plan,entries=entries)
    names=root.path_names(lower=True)
    parent=names.get(_DIRECTORY.lower())
    if parent==None: fail('backup directory is missing')
    parent_security=root.get_security(parent)
    security=build_servicing_created_security(parent_security)
    plans=[]
    destinations={}
    for transition in runtime['transitions']:
        doc=transition['after']
        if doc==None or not _needed(doc): continue
        source=sources.get(str(transition['component_identities']['after']).lower())
        if source==None: fail('backup component lacks admitted staged source')
        component=source['component']
        if digest(doc,algorithm='sha256')!=component.manifest_sha256: fail('backup declaration differs from admitted manifest')
        stem=component.stem
        files=[('/Windows/WinSxS/Manifests/'+stem+'.manifest',stem+'.manifest')]
        for file in windows.assembly_manifest(doc).files:
            files.append(('/Windows/WinSxS/'+stem+'/'+file.name,_filename(stem,file.name)))
        for source_path,filename in files:
            path=names.get(source_path.lower())
            index=source['entries'].get(source_path.lower())
            if path==None or index==None: fail('backup payload lacks exact staged file')
            data=root.find(path)
            if digest(data)!=digest(source['plan'].open(index)): fail('backup payload differs from admitted source')
            destination=parent+'/'+filename
            if destination.lower() in destinations: fail('duplicate backup destination')
            destinations[destination.lower()]=True
            old=names.get(destination.lower())
            if old!=None:
                destination=old
                if digest(root.find(old))!=digest(data): fail('conflicting existing backup')
            plans.append(dict(source=path,path=destination,order=root.get_metadata(path).write_order,
                destination_order=root.get_metadata(old).write_order if old!=None else None))
    retirements=_retirements(root,runtime,names,destinations)
    return dict(parent=parent,parent_security=parent_security,security=security,files=plans,retirements=retirements)

def _retirements(root,runtime,names,retained):
    stems={}
    for path in names.values():
        if path.lower().startswith('/windows/winsxs/manifests/') and path.lower().endswith('.manifest'):
            stem=path.rsplit('/',1)[1][:-9]
            stems.setdefault(int(stem.rsplit('_',1)[1],16),[]).append(stem)
    result=[]
    seen={}
    for transition in runtime['transitions']:
        document=transition['before']
        if document==None or not _needed(document): continue
        candidates=stems.get(windows.csi_identity_hash(transition['component_identities']['before']),[])
        if len(candidates)!=1: fail('ambiguous backup predecessor stem')
        # Native removal queues payload deletion, but retains old manifests.
        for file in windows.assembly_manifest(document).files:
            requested=_DIRECTORY+'/'+_filename(candidates[0],file.name)
            if requested.lower() in retained: continue
            path=names.get(requested.lower())
            if path==None: continue
            if path.lower() in seen: fail('duplicate backup retirement')
            seen[path.lower()]=True
            old=root.find(path)
            logical=archive.dcs(old) if old.size>=4 and old.slice(0,4).bytes()==b'DCS\x01' else old
            if digest(logical)!=select_servicing_file_hash(file)['digest']: fail('backup predecessor hash mismatch')
            result.append(dict(path=path,order=root.get_metadata(path).write_order))
    return result

def apply_update_backups(root,plan):
    """Preflight the complete backup plan, then publish independent copies and retirements on root; return selected/written/retired counts."""
    if root.get_security(plan['parent'])!=plan['parent_security']: fail('backup parent security changed')
    for p in plan['files']:
        if root.find(p['source'])==None or root.get_metadata(p['source']).write_order!=p['order']:
            fail('backup source changed before publication')
        present=root.find(p['path'])!=None
        if present!=(p['destination_order']!=None) or present and root.get_metadata(p['path']).write_order!=p['destination_order']:
            fail('backup destination changed before publication')
    for p in plan['retirements']:
        if root.find(p['path'])==None or root.get_metadata(p['path']).write_order!=p['order']:
            fail('backup retirement changed before publication')
    written=0
    for p in plan['files']:
        if p['destination_order']!=None: continue
        root.write(p['path'],root.find(p['source']))
        root.set_security(p['path'],plan['security'])
        root.set_file_attributes(p['path'],0x80)
        written+=1
    for p in plan['retirements']: root.remove(p['path'])
    return dict(selected=len(plan['files']),written=written,retired=len(plan['retirements']))
