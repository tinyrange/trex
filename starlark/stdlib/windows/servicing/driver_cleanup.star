"""Retire one completed native driver host; never complete a driver phase for it.

CloseContext and DLL detach do not close every process-owned registry handle.
The isolated host is no longer used after this boundary. Release those references
through RegCloseKey and unload its owned mounts through the existing provider,
which serializes actual final effects before removing the namespace. No pending
mount, live reference, hive edit or phase result is discarded or fabricated.
"""

def retire_update_driver_process(session):
    """Retire a completed native driver host once, only after all phases including Close; reject live or already-retired sessions."""
    if session.get('completed') != ['open','stage','install','uninstall','close']:
        fail('driver host retirement requires all native phases and Close')
    if session.get('resources_retired', False):
        fail('driver host resources already retired')
    machine = session['machine']
    registry = session['registry']
    mount = session['mount']
    borrowed = [0x80000000,0x80000001,0x80000002,0x80000003]
    detached = session.setdefault('process_detached', [])
    expected = ['drupdate.dll','drvstore.dll']
    if detached != expected[:len(detached)]:
        fail('driver DLL detach order is inconsistent')
    for name in expected[len(detached):]:
        modules = [m for m in machine.modules if m.name.lower() == name]
        if len(modules) != 1 or modules[0].tls_callbacks or modules[0].entry == modules[0].base:
            fail('unestablished driver module teardown')
        module = modules[0]
        result = machine.call(module.entry, args=[module.base,0,0])
        if result.reason != 'return' or result.value != 1:
            fail('native driver DLL detach did not complete: ' + name)
        detached.append(name)
    references = []
    for handle,key in registry.state['handles'].items():
        if key == None or handle in borrowed:
            continue
        owners = [name for name,epoch in mount.state['epochs'].items() if key[0] == 'SOFTWARE' and (key[1].lower() == epoch['prefix'].lower() or key[1].lower().startswith(epoch['prefix'].lower()+'/'))]
        if len(owners) != 1:
            fail('driver host retirement found an unowned registry reference')
        references.append(handle)
    close = machine.resolve_export('advapi32.dll', name='RegCloseKey')
    unload = machine.resolve_export('kernelbase.dll', name='RegUnLoadKeyW')
    if not close or not unload:
        fail('driver host teardown APIs are unavailable')
    for handle in references:
        result = machine.call(close, args=[handle])
        if result.reason != 'return' or result.value != 0 or registry.state['handles'].get(handle) != None:
            fail('driver process reference was not actually closed')
    names = list(mount.state['epochs'])
    for name in names:
        encoded = mount.state['epochs'][name]['prefix'][1:]
        native = encoded.replace('%2f','/').replace('%2F','/').replace('%25','%')
        argument = machine.allocate(value=binary.encode(native, encoding='utf16le', nul=True))
        result = machine.call(unload, args=[0x80000002,argument])
        if result.reason != 'return' or result.value != 0:
            fail('driver process backing hive was not actually unloaded')
    if any([mount.state[field] for field in ['mounts','pending','epochs']]):
        fail('driver process teardown left a mounted hive')
    if any([key != None and h not in borrowed for h,key in registry.state['handles'].items()]):
        fail('driver process teardown left an owned registry reference')
    # Retire closed-handle tombstones only; these are not live references.
    # The isolated native host is never resumed after publication.
    for handle,key in list(registry.state['handles'].items()):
        if key == None:
            registry.state['handles'].pop(handle)
    kernel = mount.state['kernel']
    temporary = 'c:' + chr(92) + 'windows' + chr(92) + 'temp'
    if temporary in kernel.state['paths']:
        entry = kernel.state['paths'][temporary]
        if not entry.get('directory', False) or any([p.startswith(temporary+chr(92)) for p in kernel.state['paths']]):
            fail('driver host temporary directory is not empty')
        argument = machine.allocate(value=binary.encode(temporary, encoding='utf16le', nul=True))
        result = machine.call(machine.resolve_export('kernel32.dll', name='RemoveDirectoryW'), args=[argument])
        if result.reason != 'return' or result.value != 1 or temporary in kernel.state['paths']:
            fail('driver host temporary directory was not removed')
    session['resources_retired'] = True
    session['retirement'] = dict(registry_references=len(references),hives=len(names),detached=list(detached))
    return session['retirement']
