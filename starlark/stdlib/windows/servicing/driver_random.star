"""Execute the source NTDLL's self-initializing RtlRandomEx for offline drivers.

The process cookie is an explicit virtual-process input, not an observed target
OS cookie, trust verdict, privilege or servicing state. No initialization flag or
random table is patched. The source routine initializes its own state. Its only
admitted process query is ProcessCookie for the current virtual process. This
bounded AMD64 path does not implement arbitrary NTDLL syscalls or initialization.
"""


def update_driver_native_random(ntdll, process_cookie):
    """Create a qualified native random/process-cookie plugin; require an explicit ULONG cookie and the expected native exports."""
    if type(process_cookie) != 'int' or process_cookie < 0 or process_cookie > 0xffffffff:
        fail('driver random process_cookie must be an explicit ULONG')
    targets = {e['name']: e['rva'] for e in ntdll.exports if e.get('name') in ['RtlRandomEx', 'NtQueryInformationProcess']}
    if len(targets) != 2:
        fail('driver random requires actual NTDLL exports')
    state = {'cookie': process_cookie, 'calls': 0, 'queries': []}
    def query(event):
        process, kind, out, size, needed = event.args
        if process != 0xffffffffffffffff or kind != 36 or not out or size != 4 or needed:
            fail('native random requires an unmodeled process query')
        event.machine.write_u32le(out, state['cookie'])
        state['queries'].append((kind, size))
        return 0
    def callback(event):
        if not event.args[0]:
            fail('native random requires owned Seed storage')
        result = event.machine.invoke(state['module'].base + targets['RtlRandomEx'], args=event.args)
        if result.reason != 'return':
            fail('actual native random stopped: ' + result.reason + ' ' + result.detail)
        state['calls'] += 1
        return result.value
    def install(m):
        if m.pointer_size != 8:
            fail('driver native random control only admits AMD64')
        native = m.load_module(image=ntdll.data, name='driver-random-ntdll.dll')
        state['module'] = native
        m.hook(query, address=native.base + targets['NtQueryInformationProcess'], argc=5)
        m.provide_export(callback, module='ntdll.dll', name='RtlRandomEx', argc=1)
    return emulator.plugin(install, name='windows.update.driver-native-random', state=state)
