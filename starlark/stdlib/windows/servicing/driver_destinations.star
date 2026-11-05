"""Independently qualify native driver projections outside its source inventory.

The host input inventory includes selected source objects, not every runtime
alias. Authorize replacement only by the admitted manifest's exact after hash,
an entirely unchanged resident dependency, or an exact staged driver catalog.
These checks authorize content construction, not CBS package completion.
"""

load('@stdlib//windows/servicing:files.star','prepare_update_file_hierarchy')

def prepare_update_driver_destination_authority(runtime, hives, generated):
    """Keep only actual native output leaves, releasing the large full hierarchy."""
    # The ordinary file installer does not project dual-mode drivers. These
    # candidate destinations authorize only actual native outputs; they must
    # never be published through its generic file/FileMap pass.
    prepared = prepare_update_file_hierarchy(runtime,hives,driver_projection_candidates=True)
    selected = {}
    sources = {}
    for native,entry in generated.items():
        if entry['directory']:
            continue
        path = native.replace(chr(92),'/').lower()[2:]
        node = prepared['hierarchy'].get(path)
        if node == None or node['kind'] != 'file':
            continue
        selected[path] = node
        key = node['after'].get('source_key')
        if key in prepared['sources']:
            sources[key] = prepared['sources'][key]
    return dict(hierarchy=selected,sources=sources)

def qualify_update_driver_destinations(root, prepared, payloads, generated):
    """Bind generated driver destinations to admitted payload and prepared path authority; return qualified paths and counts."""
    names = {p.lower():p for p in root.files}
    catalogs = {}
    for stage in payloads['stages'].values():
        for entry in stage.files:
            if entry.kind == 'component-file' and entry.store_path.lower().endswith('.cat'):
                path = names.get(entry.store_path.lower())
                if path == None:
                    fail('staged driver catalog source is absent')
                catalogs.setdefault(path.rsplit('/',1)[1].lower(),[]).append(root.find(path))
    authorized = {}
    counts = dict(runtime=0,unchanged=0,catalogs=0)
    for native,entry in generated.items():
        path = native.replace(chr(92),'/').lower()
        if not path.startswith('d:/windows/') or entry['directory']:
            continue
        path = path[2:]
        if any([path.startswith(p) for p in ['/windows/inf/','/windows/winsxs/','/windows/system32/driverstore/filerepository/','/windows/system32/config/']]):
            continue
        if any([p in ['', '.', '..'] for p in path.split('/')[1:]]):
            fail('invalid extra native driver destination')
        actual = names.get(path)
        prior = root.find(actual) if actual != None else None
        content_hash = digest(entry['data'],algorithm='sha256')
        node = prepared['hierarchy'].get(path)
        if path.startswith('/windows/system32/catroot/{f750e6c3-38ee-11d1-85e5-00c04fc295ee}/'):
            candidates = catalogs.get(path.rsplit('/',1)[1],[])
            if not any([digest(file,algorithm='sha256') == content_hash for file in candidates]):
                fail('native driver catalog differs from its staged source: ' + path)
            windows.catalog_index(entry['data'])
            counts['catalogs'] += 1
        elif node != None and node['kind'] == 'file' and node['after']['state'] in [2,7]:
            source = prepared['sources'].get(node['after']['source_key'],{}).get('after')
            if source == None or source['hash']['digest_method'] != 2 or source['hash']['transform'] != 1 or source['hash']['digest'] != content_hash:
                fail('native driver projection differs from the admitted manifest: ' + path)
            counts['runtime'] += 1
        elif path.startswith('/windows/system32/drivers/') and prior != None and digest(prior,algorithm='sha256') == content_hash:
            metadata = root.get_metadata(actual)
            expected = (root.get_security(actual),metadata.file_attributes,metadata.creation_time,metadata.last_write_time,metadata.last_access_time,metadata.extended_attributes)
            observed = (entry.get('security'),entry.get('attributes',0x80)&~0x80,entry.get('creation_time',0),entry.get('write_time',0),entry.get('access_time',0),entry.get('extended_attributes',[]))
            if expected != observed:
                fail('unchanged native driver dependency metadata differs: ' + path)
            counts['unchanged'] += 1
        else:
            fail('native driver destination has no independent construction authority: ' + path)
        authorized[path] = dict(directory=False,sha256=content_hash,prior_sha256=digest(prior,algorithm='sha256') if prior != None else None)
    # Only ancestors of independently qualified files may cross the original
    # destination boundary; arbitrary unrelated directories remain rejected.
    for path in list(authorized):
        parts = path.split('/')
        for depth in range(2,len(parts)):
            parent = '/'.join(parts[:depth])
            authorized.setdefault(parent,dict(directory=True))
    return dict(paths=authorized,counts=counts)
