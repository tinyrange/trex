"""Persist the measured offline DriverStore catalog-hint EA operation.

This is not a general protected-EA, catalog-trust or access-check implementation.
Only an actual owned FILE_WRITE_EA handle to the explicit offline repository and
one structurally valid v1 $CI.CatalogHint update are admitted. Other policy stops
before returning to native code. Existing unrelated EAs and hardlinks survive.
"""


def update_driver_eas(kernel):
    """Create an emulator EA plugin that validates and records native writes against the supplied kernel file objects."""
    state = {'writes': []}
    check = directory()
    check.write('/check', b'')
    def callback(event):
        m = event.machine
        handle, iosb, buffer, length = event.args
        def complete(status):
            if iosb:
                m.write_u32le(iosb, status)
                m.write_pointer(iosb + m.pointer_size, 0)
            return status
        if not iosb or not buffer or not length or length > 65536:
            return complete(0xc000000d)
        owned = kernel.state['handles'].get(handle)
        if type(owned) != 'dict' or owned.get('kind') != 'file':
            return complete(0xc0000008)
        opened = owned['value']
        if 'desired_access' not in opened:
            fail('driver EA handle has no captured access provenance')
        if not opened['desired_access'] & 0x10:
            return complete(0xc0000022)
        entry = opened.get('file')
        if entry == None or entry.get('directory', False):
            fail('driver EA requires an owned regular-file object')
        if not entry.get('writable', True):
            return complete(0xc0000022)
        path = opened['path']
        prefix = 'd:' + chr(92) + 'windows' + chr(92) + 'system32' + chr(92) + 'driverstore' + chr(92) + 'filerepository' + chr(92)
        if not path.startswith(prefix) or any([p in ['', '.', '..'] for p in path[len(prefix):].split(chr(92))]):
            fail('driver EA is outside the explicit offline FileRepository')
        parsed = testing.attempt(windows.decode_file_eas, args=[m.read(buffer, length)])
        if not parsed.ok:
            return complete(0x80000014)  # STATUS_EA_LIST_INCONSISTENT
        eas = parsed.value
        if len(eas) != 1 or eas[0]['name'] != '$CI.CatalogHint' or eas[0]['flags']:
            fail('unmodeled driver EA policy')
        value = eas[0]['value']
        if len(value) < 5:
            fail('unmodeled driver catalog hint encoding')
        if binary.read_u16le(value) != 1 or binary.read_u16le(value,2) != len(value) - 4:
            fail('unmodeled driver catalog hint version or length')
        name = binary.text(value[4:], encoding='ascii')
        if not name.lower().endswith('.cat') or any([c in name for c in [chr(0), chr(92), '/', ':']]) or name in ['.', '..']:
            fail('unmodeled driver catalog hint name')
        # Replace a name case-insensitively, never discard other file EAs.
        merged = [dict(ea) for ea in entry.get('extended_attributes', []) if ea['name'].lower() != '$ci.cataloghint']
        merged.append(dict(eas[0]))
        check.set_extended_attributes('/check', merged)
        entry['extended_attributes'] = merged
        entry['dirty'] = True
        state['writes'].append(dict(path=path, name=eas[0]['name'], value=value))
        return complete(0)
    def install(m):
        m.provide_exports(callback, module='ntdll.dll', signatures={'NtSetEaFile': 4})
    return emulator.plugin(install, name='windows.update.driver-eas', state=state)
