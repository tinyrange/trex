"""Bounded readonly catalog metadata for the observed offline-driver path.

Does not implement WinVerifyTrust, catalog installation or publisher policy.
Unknown APIs stop at their native call boundary without returning success.
"""


def update_driver_catalogs(kernel,cryptoapi):
    """Create an emulator plugin for catalog enumeration and metadata, with explicit kernel and CryptoAPI state."""
    state={'catalogs':{},'actions':[]}
    def error(code):
        kernel.state['last_error']=code
        return 0
    def callback(event):
        m=event.machine
        name=event.name.lower()
        if name=='cryptcatopen':
            path,flags,provider,version,encoding=event.args
            invalid=0xffffffffffffffff if m.pointer_size==8 else 0xffffffff
            if flags or version or encoding: fail('unmodeled driver catalog open policy')
            if provider not in cryptoapi.state['providers']:
                error(6)
                return invalid
            if not path: fail('driver catalog metadata requires an existing file')
            physical=m.read_cstring(path,encoding='utf16le').replace('/',chr(92)).lower()
            if not physical.startswith('d:'+chr(92)+'windows'+chr(92)+'winsxs'+chr(92)) or any([p in ['.','..',''] for p in physical.split(chr(92))[1:]]):
                fail('driver catalog metadata is outside its explicit offline source')
            entry=kernel.state['paths'].get(physical)
            if entry==None or entry.get('directory',False):
                error(2)
                return invalid
            attributes=windows.catalog_attributes(kernel.state['file_data'](entry))
            if any([not a['name_value'] for a in attributes]): fail('unmodeled catalog-level extension')
            # Parse before allocating any owned target buffers or handles.
            pointers=[]
            allocations=[]
            for attr in attributes:
                tag=m.allocate(value=binary.encode(attr['name'],encoding='utf16le',nul=True))
                value=m.allocate(value=attr['value']) if attr['value'] else 0
                size=40 if m.pointer_size==8 else 24
                record=m.allocate(size=size)
                m.write_u32le(record,size)
                m.write_pointer(record+(8 if m.pointer_size==8 else 4),tag)
                m.write_u32le(record+(16 if m.pointer_size==8 else 8),attr['flags'])
                m.write_u32le(record+(20 if m.pointer_size==8 else 12),len(attr['value']))
                m.write_pointer(record+(24 if m.pointer_size==8 else 16),value)
                pointers.append(record)
                allocations.extend([record,tag]+([value] if value else []))
            handle=cryptoapi.state['next_handle']
            cryptoapi.state['next_handle']=handle+1
            state['catalogs'][handle]=dict(path=physical,pointers=pointers,allocations=allocations)
            state['actions'].append(dict(operation='open',path=physical,handle=handle,attributes=len(attributes)))
            return handle
        opened=state['catalogs'].get(event.args[0])
        if opened==None: return error(6)
        if name=='cryptcatclose':
            state['catalogs'].pop(event.args[0])
            for pointer in opened['allocations']: m.free(pointer)
            state['actions'].append(dict(operation='close',handle=event.args[0]))
            return 1
        if name=='cryptcatenumeratecatattr':
            previous=event.args[1]
            pointers=opened['pointers']
            if previous and previous not in pointers: return error(87)
            index=pointers.index(previous)+1 if previous else 0
            return pointers[index] if index<len(pointers) else 0
        fail('unmodeled driver catalog callback '+event.name)
    def unsupported(event):
        fail('unmodeled driver catalog API '+event.name)
    def install(m):
        m.provide_exports(callback,module='wintrust.dll',signatures={'CryptCATOpen':5,'CryptCATClose':1,'CryptCATEnumerateCatAttr':2})
        # These are declared imports of this target DLL, not invented exports.
        # Stop BEFORE a semantic return, rather than letting the delay loader
        # raise a misleading missing-symbol exception. No trust is fabricated.
        m.provide_exports(unsupported,module='wintrust.dll',signatures={'CryptCATAdminAcquireContext':3,'CryptCATAdminReleaseContext':2,'CryptCATGetMemberInfo':2,'WinVerifyTrust':3})
    return emulator.plugin(install,name='windows.update.driver-catalog-metadata',state=state)
