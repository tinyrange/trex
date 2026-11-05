"""Construct paired, equivalent-INF DriverDatabase replacements without x86.

Preserve installed configuration and physical hive placement. The caller supplies
complete new repositories, not templates' INF-only FileSize values. Nothing is
published until all hives have been built and read back successfully.
"""
load('@stdlib//windows/servicing:registry_effects.star','build_update_driver_key_security')

_DB = ['DriverDatabase','DriverPackages']

def _walk(node, parts):
    queue = [(node,parts)]
    for position in range(262144):
        if position == len(queue): return queue
        current, path = queue[position]
        queue.extend([(child,path+[child.name]) for child in current.children])
    fail('driver registry traversal exceeds bound')

def _path_references(text, replacements):
    # Replace complete path components, never similarly named packages.
    return chr(92).join([replacements.get(part.lower(),part) for part in text.split(chr(92))])

def _raw_references(record, replacements):
    if record.type not in [1,2,7]: return record.raw
    text = binary.text(record.raw,encoding='utf16le')
    return binary.encode(chr(0).join([_path_references(part,replacements) for part in text.split(chr(0))]),encoding='utf16le')

def plan_version_only_driver_hives(root, replacements):
    """replacements carry exact before/after names, version, size and INF name.

    Each replacement must already have passed the ordered-INF equality guard.
    This routine requires an actual old package; absent or multiple bindings
    are not silently repaired from a manifest template.
    """
    states = {}
    for name in ['SYSTEM','DRIVERS','SOFTWARE']:
        path = '/Windows/System32/config/'+name
        source = root.find(path)
        states[name] = dict(path=path,source=source,hive=windows.hive(source, snapshot=True),keys=[],patches=[],removals=[])
    mappings = {}
    targets = {}
    jobs = []
    for row in replacements:
        before, after = row.get('source',row['before']),row['after']
        if before.lower() == after.lower(): continue
        for name in [before,after]:
            if not name or name in ['.','..'] or any([c in name for c in [chr(92),'/',':',chr(0)]]):
                fail('invalid driver replacement package name')
        if before.lower() in mappings or after.lower() in targets:
            fail('driver replacement package is not unique')
        if type(row['size']) != 'int' or row['size'] < 0 or row['size'] > 0xffffffffffffffff or type(row['version']) != 'bytes' or len(row['version']) != 48:
            fail('invalid driver replacement package metadata')
        bindings = [(name,state['hive'].find(_DB+[before])) for name,state in states.items() if name != 'SOFTWARE' and state['hive'].find(_DB+[before]) != None]
        if len(bindings) != 1: fail('driver replacement requires one actual old package binding: '+before)
        name, old = bindings[0]
        version_record = old.value_records.get('Version')
        size_record = old.value_records.get('FileSize')
        if version_record == None or version_record.type != 3 or len(version_record.raw) != 48 or size_record == None or size_record.type != 11 or len(size_record.raw) != 8:
            fail('unsupported installed driver package metadata')
        if old.values.get('(default)','').lower() != row['inf'].lower():
            fail('driver replacement binding has another INF')
        if any([state['hive'].find(_DB+[after]) != None for name,state in states.items() if name != 'SOFTWARE']):
            fail('driver replacement would overwrite an existing package')
        mappings[before.lower()] = after
        targets[after.lower()] = True
        jobs.append((states[name],old,row))
    if set(mappings) & set(targets): fail('driver replacement chains require explicit ordering')
    for state, old, row in jobs:
        new_root = _DB+[row['after']]
        security = {}
        for node, path in _walk(old,[]):
            parts = new_root+path
            parent = security[tuple(path[:-1])] if path else state['hive'].find(_DB).security
            descriptor = build_update_driver_key_security(parent)
            security[tuple(path)] = descriptor
            state['keys'].append(dict(key_parts=parts,security=descriptor))
            for name, record in node.value_records.items():
                raw = _raw_references(record,mappings)
                if not path and name.lower() == 'version': raw = row['version']
                if not path and name.lower() == 'filesize': raw = binary.u64le(row['size'])
                state['patches'].append(dict(key_parts=parts,name=name,type=record.type,value=raw))
        if old.values.get('Version') == None or old.values.get('FileSize') == None:
            fail('driver replacement source lacks package version or size')
        if not row.get('retain_source',False):
            state['removals'].append(dict(key_parts=_DB+[row['before']]))
    retained = {r.get('source',r['before']).lower():r['after'] for unused,unused2,r in jobs if r.get('retain_source',False)}
    for state in states.values():
        for patch in state['hive'].path_component_patches(mappings,exclude_keys=[_DB]):
            parts = patch['key_parts']
            if len(parts) == 3 and [p.lower() for p in parts[:2]] == ['driverdatabase','driverinffiles'] and patch['name'] == '':
                if patch['type'] != 7: fail('driver package aliases require MULTI_SZ')
                entries = binary.text(patch['before'],encoding='utf16le').rstrip(chr(0)).split(chr(0))
                final = []
                for entry in entries:
                    if entry.lower() in retained: final.append(entry)
                    replacement = mappings.get(entry.lower(),entry)
                    if replacement not in final: final.append(replacement)
                patch['value'] = binary.encode(chr(0).join(final)+chr(0)+chr(0),encoding='utf16le')
            state['patches'].append({key:value for key,value in patch.items() if key != 'before'})
    plans = []
    for name,state in states.items():
        if not state['patches'] and not state['removals']: continue
        updated = windows.patch_hive(state['source'],state['patches'],keys=state['keys'],delete_keys=state['removals'])
        check = windows.hive(updated, snapshot=True)
        for patch in state['patches']:
            actual = check.find(patch['key_parts']).value_records[patch['name'] or '(default)']
            if actual.type != patch['type'] or actual.raw != patch['value']:
                fail('driver replacement value readback disagrees')
        for key in state['keys']:
            if check.find(key['key_parts']).security != key['security']:
                fail('driver replacement key security readback disagrees')
        for key in state['removals']:
            if check.find(key['key_parts']) != None: fail('retired driver package survived replacement')
        plans.append(dict(path=state['path'],source=state['source'],file=updated))
    return plans

def apply_version_only_driver_hives(root, plans):
    """Preflight every source hive before publishing version-only driver replacements; return the number of written hives."""
    for plan in plans:
        if root.find(plan['path']).bytes() != plan['source'].bytes():
            fail('driver hive changed before replacement publication')
    for plan in plans: root.write(plan['path'],plan['file'])
    return len(plans)
