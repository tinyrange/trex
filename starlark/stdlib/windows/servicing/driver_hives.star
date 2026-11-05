"""Bounded native offline-driver hive mount provider.

Models the observed successful-buffer/owned-reference SSU path, not a general
kernel hive lifecycle or authorization model. A successful ordinary unload first
constructs actual backing-hive effects, as does an owned native flush while
references remain open; pending/busy mounts never fake success.
Namespace teardown is kept outside the next captured native mutation epoch.
"""

load("@stdlib//windows/servicing:registry_effects.star", "plan_update_registry_effects", "apply_update_registry_effects")

def _query_mounted_object_name(event,registry,state):
    """ObjectNameInformation for live keys in this provider's owned HKLM mounts.

    The private registry display encoding is not a native path: decode each
    component separately, retaining literal slashes inside mount/key names.
    Other object classes and namespaces require an independently owned model.
    """
    m=event.machine
    handle,information,output,capacity,needed=event.args
    if information!=1: fail('unmodeled mounted-object information class')
    if handle in registry.state['deleted_handles']: return 0xc000017c
    key=registry.state['handles'].get(handle)
    if key==None: return 0xc0000008
    matches=[epoch for name,epoch in state['epochs'].items() if name in state['mounts'] and key[0]=='SOFTWARE' and (key[1].lower()==epoch['prefix'].lower() or key[1].lower().startswith(epoch['prefix'].lower()+'/'))]
    if len(matches)!=1: fail('object-name query requires a unique owned hive mount')
    if not needed: fail('mounted-object query requires ReturnLength storage')
    if not output and capacity: fail('mounted-object query has NULL output with nonzero capacity')
    parts=[p.replace('%2f','/').replace('%25','%') for p in key[1].split('/')[1:]]
    text=binary.encode(chr(92)+'REGISTRY'+chr(92)+'MACHINE'+chr(92)+chr(92).join(parts),encoding='utf16le')
    if len(text)>0xfffc: fail('mounted-object name exceeds UNICODE_STRING capacity')
    header=16 if m.pointer_size==8 else 8
    required=header+len(text)+2
    m.write_u32le(needed,required)
    if not output or (capacity&0xffffffff)<required: return 0xc0000004
    m.write(output,b'\x00'*header)
    m.write_u16le(output,len(text))
    m.write_u16le(output+2,len(text)+2)
    m.write_pointer(output+(8 if m.pointer_size==8 else 4),output+header)
    m.write(output+header,text)
    m.write_u16le(output+header+len(text),0)
    return 0

def _query_mounted_open_subkeys(event,registry,state):
    m=event.machine
    if m.pointer_size!=8: fail('owned open-reference report requires the measured Win64 layout')
    oa,length,output,needed=event.args
    if not needed: fail('open-reference report requires RequiredSize storage')
    if not output: fail('NULL open-reference report buffer is not modeled')
    desc=m.read_pointer(oa+16)
    key=binary.text(m.read(m.read_pointer(desc+8),m.read_u16le(desc)),encoding='utf16le')
    prefix=chr(92)+'REGISTRY'+chr(92)+'MACHINE'+chr(92)
    if m.read_u32le(oa)!=48 or m.read_pointer(oa+8) or not key.upper().startswith(prefix): fail('unexpected open-reference query')
    mount=key[len(prefix):]
    if mount.lower() not in state['mounts']: fail('open-reference query requires fixture mount')
    encoded='/'+mount.replace('%','%25').replace('/','%2f')
    refs=[(h,k) for h,k in registry.state['handles'].items() if k!=None and k[0]=='SOFTWARE' and (k[1].lower()==encoded.lower() or k[1].lower().startswith(encoded.lower()+'/'))]
    names=[]
    for h,k in refs:
        suffix=k[1][len(encoded):]
        suffix=chr(92).join([p.replace('%2f','/').replace('%25','%') for p in suffix.split('/')])
        names.append(binary.encode(key+suffix,encoding='utf16le'))
    required=8+24*len(names)
    for n in names:
        if len(n)>0xfffc: fail('owned open-reference name exceeds UNICODE_STRING')
        required+=len(n)+2
    if required>0xffffffff: fail('owned open-reference report exceeds ULONG size')
    m.write_u32le(needed,required)
    # Actual 9703 drvstore +0x5586d retries STATUS_BUFFER_OVERFLOW,
    # reallocating RequiredSize+1024. A short report never fabricates entries.
    if (length&0xffffffff)<required: return 0x80000005
    pid=m.invoke(m.resolve_export('kernel32.dll',name='GetCurrentProcessId'),args=[])
    if pid.reason!='return': fail('cannot obtain fixture process identity')
    m.write_u32le(output,len(names))
    cursor=output+8+24*len(names)
    for i,n in enumerate(names):
        entry=output+8+24*i
        m.write_pointer(entry,pid.value)
        m.write_u16le(entry+8,len(n))
        m.write_u16le(entry+10,len(n)+2)
        m.write_pointer(entry+16,cursor)
        m.write(cursor,n)
        m.write_u16le(cursor+len(n),0)
        cursor+=len(n)+2
    print('NATIVE_OPEN_REFERENCE_REPORT',pid.value,[(h,k[1]) for h,k in refs],required)
    state.setdefault('reports',[]).append({'key':key,'handles':[h for h,k in refs],'pid':pid.value,'required':required})
    return 0

def _mounted_hive_delta(registry, epoch):
    """Capture only mutations after the last successful backing-hive commit.

    Key metadata has no value-patch offset: compare its immutable final records
    separately. Recreated empty keys must still be emitted after a new ancestor
    deletion even when their final descriptor equals the earlier incarnation.
    """
    captured = registry.effects(patch_start=epoch['patch_start'], key_deletion_start=epoch['deletion_start'])
    encoded = epoch['prefix'].lower()
    effects = {field:[record for record in captured[field] if record['hive']=='SOFTWARE' and (record['key'].lower()==encoded or record['key'].lower().startswith(encoded+'/'))] for field in ['keys','values','key_deletions','value_deletions']}
    snapshot = {record['key'].lower():dict(record) for record in effects['keys']}
    previous = epoch.get('persisted_keys', {})
    removed = [record['key'].lower() for record in effects['key_deletions']]
    effects['keys'] = [record for record in effects['keys'] if previous.get(record['key'].lower())!=record or any([record['key'].lower()==key or record['key'].lower().startswith(key+'/') for key in removed])]
    return effects, snapshot, len(registry.state['patches']), len(registry.state['key_deletions'])


def update_driver_hive_mounts(registry,root,sources,host_namespace=None):
    """Create an emulator plugin for explicit offline hive mounts and flush epochs; host mount namespaces are not published target keys."""
    state={'mounts':{},'loads':[],'pending':{},'epochs':{},'commits':[]}
    def find(parts):
        # The host mount container is an explicitly supplied emulation input,
        # not the offline SOFTWARE root and never a published target key.
        if not parts: return host_namespace.root if host_namespace != None else None
        source=state['mounts'].get(parts[0].lower())
        return source.find(parts[1:]) if source!=None else None
    def commit_mount(name):
        epoch=state['epochs'][name.lower()]
        encoded=epoch['prefix']
        effects, snapshot, patch_end, deletion_end = _mounted_hive_delta(registry, epoch)
        if not any([effects[field] for field in effects]):
            epoch.update(persisted_keys=snapshot, patch_start=patch_end, deletion_start=deletion_end)
            return
        binding=dict(hive='SOFTWARE',prefix=encoded,target=epoch['target'],path=epoch['path'],source=epoch['source'])
        kernel=state.get('kernel')
        entry=kernel.state['paths'].get(epoch['physical']) if kernel!=None else None
        if entry==None or entry.get('directory',False):
            fail('mounted hive has no regular backing file object')
        plans=plan_update_registry_effects(root,effects,[binding])
        committed=apply_update_registry_effects(root,plans)
        backing=root.find(epoch['path'])
        entry.update(source=backing,size=backing.size,dirty=True)
        entry.pop('data',None)
        state['commits'].append(dict(target=epoch['target'],effects=committed,hash=digest(backing)))
        epoch.update(source=backing, persisted_keys=snapshot, patch_start=patch_end, deletion_start=deletion_end)
    def flush(event):
        m=event.machine
        handle=event.args[0]
        if handle in registry.state['deleted_handles']: return 0xc000017c
        key=registry.state['handles'].get(handle)
        if key==None: return 0xc0000008
        matches=[name for name,epoch in state['epochs'].items() if key[0]=='SOFTWARE' and (key[1].lower()==epoch['prefix'].lower() or key[1].lower().startswith(epoch['prefix'].lower()+'/'))]
        if len(matches)!=1: fail('native hive flush has no unique owned backing mount')
        result=m.invoke(m.resolve_export('advapi32.dll',name='RegFlushKey'),args=[handle])
        if result.reason!='return' or result.value: fail('native hive flush could not validate its registry handle')
        commit_mount(matches[0])
        state.setdefault('flushes',[]).append(matches[0])
        return 0
    def detach_mount(name):
        encoded=state['epochs'][name.lower()]['prefix']
        commit_mount(name)
        state['mounts'].pop(name.lower())
        state['pending'].pop(name.lower(),None)
        state['epochs'].pop(name.lower())
        for candidate in list(state.get('busy_unload',{})):
            if candidate.lower()==name.lower(): state['busy_unload'].pop(candidate)
        registry.delete_tree('SOFTWARE',encoded)
        registry.state['source_cache'].clear()
        return 0
    def unload_synchronous(event):
        m=event.machine
        oa,flags=event.args
        if flags&0xffffffff not in [0,1]: fail('unobserved synchronous hive-unload flags')
        if not oa or m.read_u32le(oa)!=48 or m.read_pointer(oa+8) or m.read_u32le(oa+24)!=0x40 or m.read_pointer(oa+32) or m.read_pointer(oa+40): fail('unobserved synchronous hive-unload attributes')
        desc=m.read_pointer(oa+16)
        if not desc or m.read_u16le(desc)>m.read_u16le(desc+2): fail('invalid synchronous hive-unload name')
        key=binary.text(m.read(m.read_pointer(desc+8),m.read_u16le(desc)),encoding='utf16le')
        prefix=chr(92)+'REGISTRY'+chr(92)+'MACHINE'+chr(92)
        if not key.upper().startswith(prefix): fail('unobserved synchronous hive-unload namespace')
        name=key[len(prefix):]
        if name.lower() not in state['mounts']: return 0xc0000034
        encoded=state['epochs'][name.lower()]['prefix']
        refs=[h for h,k in registry.state['handles'].items() if k!=None and k[0]=='SOFTWARE' and (k[1].lower()==encoded.lower() or k[1].lower().startswith(encoded.lower()+'/'))]
        if refs: fail('forced/synchronous hive unload with live references is not modeled')
        return detach_mount(name)
    def callback(event):
        name=event.machine.read_cstring(event.args[1],encoding='utf16le')
        path=event.machine.read_cstring(event.args[2],encoding='utf16le').lower()
        if event.args[0]&0xffffffff!=0x80000002: fail('fixture only mounts under HKLM')
        binding=sources.get(path)
        if binding==None: fail('unexpected hive input '+path)
        backing=root.find(binding['path'])
        if backing==None: fail('mounted hive backing is absent')
        source=windows.hive(backing)
        if name.lower() in state['mounts']: fail('duplicate hive mount')
        state['mounts'][name.lower()]=source
        registry.load_keys([{'hive':'SOFTWARE','key_parts':[name]}])
        registry.state['source_cache'].clear()
        encoded='/'+name.replace('%','%25').replace('/','%2f')
        state['epochs'][name.lower()]=dict(prefix=encoded,target=binding['target'],path=binding['path'],physical=path,source=backing,patch_start=len(registry.patches()),deletion_start=len(registry.key_deletions()))
        state['loads'].append({'mount':name,'path':path})
        print('MOUNTED_SOURCE_HIVE',name,path)
        return 0
    def unload(event):
        m=event.machine
        oa=event.args[0]
        if event.args[1]: fail('unload event signaling not modeled')
        root=m.read_pointer(oa+8)
        desc=m.read_pointer(oa+16)
        key=binary.text(m.read(m.read_pointer(desc+8),m.read_u16le(desc)),encoding='utf16le')
        prefix=chr(92)+'REGISTRY'+chr(92)+'MACHINE'+chr(92)
        if root or not key.upper().startswith(prefix): fail('unexpected unload object '+key)
        name=key[len(prefix):]
        if name.lower() not in state['mounts']: return 0xc0000034
        encoded='/'+name.replace('%','%25').replace('/','%2f')
        refs=[h for h,k in registry.state['handles'].items() if k!=None and k[0]=='SOFTWARE' and (k[1].lower()==encoded.lower() or k[1].lower().startswith(encoded.lower()+'/'))]
        if not refs: fail('probe expects native open reference before deferred unload')
        state['pending'][name.lower()]=encoded
        print('PENDING_SOURCE_UNLOAD',name,len(refs))
        return 0x103
    def reg_unload(event):
        m=event.machine
        if event.args[0]&0xffffffff!=0x80000002: fail('unexpected unload hive')
        name=m.read_cstring(event.args[1],encoding='utf16le')
        encoded='/'+name.replace('%','%25').replace('/','%2f')
        refs=[h for h,k in registry.state['handles'].items() if k!=None and k[0]=='SOFTWARE' and (k[1].lower()==encoded.lower() or k[1].lower().startswith(encoded.lower()+'/'))]
        if name not in state.setdefault('busy_unload',{}): print('REG_UNLOAD_REQUEST',name,len(refs))
        if refs:
            state['busy_unload'][name]=True
            return 5  # Original kernel STATUS_CANNOT_DELETE -> NTDLL Win32 5.
        state['busy_unload'].pop(name,None)
        if name.lower() not in state['mounts']: return 2
        # Namespace removal is not deletion of the target hive root.
        return detach_mount(name)
    def close(event):
        m=event.machine
        if event.args[0] in registry.state['handles']:
            result=m.invoke(m.resolve_export('advapi32.dll',name='RegCloseKey'),args=event.args)
        else:
            kernel=state.get('kernel')
            handle=event.args[0]
            if kernel==None or handle not in kernel.state['handles']: fail('unowned NtClose in narrow fixture '+str(event.args))
            result=m.invoke(m.resolve_export('kernel32.dll',name='CloseHandle'),args=event.args)
            if result.reason!='return' or result.value!=1 or handle in kernel.state['handles']: fail('kernel handle not actually closed')
            return 0
        if result.reason!='return': fail('close boundary '+result.reason)
        return result.value
    def query_open(event):
        return _query_mounted_open_subkeys(event,registry,state)
    def query_object(event):
        return _query_mounted_object_name(event,registry,state)
    def install(m):
        m.provide_export(query_object,module='ntdll.dll',name='NtQueryObject',argc=5)
        m.provide_export(unload_synchronous,module='ntdll.dll',name='NtUnloadKey2',argc=2)
        m.provide_export(flush,module='ntdll.dll',name='NtFlushKey',argc=1)
        m.provide_export(query_open,module='ntdll.dll',name='NtQueryOpenSubKeysEx',argc=4)
        m.provide_export(close,module='ntdll.dll',name='NtClose',argc=1)
        for provider in ['api-ms-win-core-registry-l1-1-0.dll','kernelbase.dll']:
            m.provide_export(reg_unload,module=provider,name='RegUnLoadKeyW',argc=2)
            m.provide_export(callback,module=provider,name='RegLoadKeyW',argc=3)
        m.provide_export(unload,module='ntdll.dll',name='NtUnloadKeyEx',argc=2)
    return emulator.plugin(install,name='windows.update.explicit-driver-hives',state=state,attrs={'find':find})
