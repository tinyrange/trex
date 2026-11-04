"""Reconstruct the exact immutable file inputs of the pinned driver host."""
load('@stdlib//windows/selfreg:win32.star','virtual_file_entries')
load('@stdlib//windows/servicing:drivers.star','select_update_driver_source_paths')
load('@stdlib//windows/servicing:file_commit.star','image_path_names')

def build_update_driver_input_entries(root, jobs):
    """Build native virtual-file inputs from explicit driver jobs and the actual INF/DriverStore namespace, retaining file metadata."""
    names = image_path_names(root, mutable=False)
    prefixes = {job['path'].rsplit('/',1)[0].lower()+'/':True for job in jobs}
    selected = {p:True for p in select_update_driver_source_paths(root,list(prefixes))}
    paths = [p for p in root.files if p.lower().startswith('/windows/inf/') or p.lower().startswith('/windows/system32/driverstore/') or p in selected]
    paths.extend(['/Windows/System32/config/'+n for n in ['SYSTEM','SOFTWARE','DRIVERS']])
    paths.extend([names[('/Windows/System32/'+n).lower()] for n in ['ntoskrnl.exe','hal.dll','ntdll.dll','kernel32.dll','ssshim.dll']])
    entries = virtual_file_entries({'D:'+p:root.find(p) for p in paths})
    entries.update({'c:':dict(directory=True,initial=True,dirty=False),'c:'+chr(92)+'windows':dict(directory=True,initial=True,dirty=False)})
    objects = {}
    for path,entry in entries.items():
        actual = names.get(path[2:].replace(chr(92),'/') or '/') if path.startswith('d:') else None
        if actual == None:
            continue
        metadata = root.get_metadata(actual)
        entry.update(security=root.get_security(actual),creation_time=metadata.creation_time,access_time=metadata.last_access_time,write_time=metadata.last_write_time,extended_attributes=metadata.extended_attributes)
        if metadata.has_file_attributes:
            entry['attributes'] = metadata.file_attributes
        if not entry['directory'] and metadata.hard_link_id:
            if metadata.hard_link_id in objects:
                entries[path] = objects[metadata.hard_link_id]
            else:
                objects[metadata.hard_link_id] = entry
    print('NATIVE_DRIVER_INPUT_PATHS',len(paths),len(entries),'REAL_DRIVER_OBJECTS',len(objects))
    return entries
