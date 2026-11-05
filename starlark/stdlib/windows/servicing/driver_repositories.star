"""Complete native DriverStore layouts for admitted version-only replacements.

CSI runtime projections are not repository inventory (including WOW64 drivers).
Authorize every relative name against both the installed layout and the new
manifest, verify all logical source bytes before writing, then link exact store
objects. No native installer execution or architecture-wide path rewriting.
"""
load('@stdlib//windows/servicing:file_commit.star','image_path_names')
load('@stdlib//windows/servicing:runtime.star','select_servicing_file_hash')

_REPOSITORY='/Windows/System32/DriverStore/FileRepository/'

def plan_direct_driver_repositories(root, jobs, replacements, manifests):
    """Plan repository files/directories from explicit replacement jobs and manifests, retaining source epochs for publication."""
    names=image_path_names(root, mutable=False)
    inventories={}
    for path in root.files:
        if path.lower().startswith(_REPOSITORY.lower()):
            parts=path[len(_REPOSITORY):].split('/',1)
            if len(parts)==2: inventories.setdefault(parts[0].lower(),{})[parts[1].lower()]=path
    by_after={r['after']['declaration']['repository'].lower():r['after'] for r in replacements if not r['unchanged']}
    files=[]
    directories={}
    for job in jobs:
        after=by_after[job['after'].lower()]
        old=job.get('source',job['before'])
        inventory=inventories.get(old.lower(),{})
        declared={}
        for record in windows.assembly_manifest(manifests[after['row']['identity'].lower()]).files:
            relative=record.name.replace(chr(92),'/')
            if any([p in ['', '.', '..'] or ':' in p or chr(0) in p for p in relative.split('/')]):
                fail('invalid driver repository relative file')
            if relative.lower() in declared: fail('duplicate driver repository manifest file')
            expected=select_servicing_file_hash(record)
            if expected == None or expected['digest_method'] != 2 or expected['transform'] != 1:
                fail('driver repository requires an exact logical SHA256')
            source=names.get((after['path'].rsplit('/',1)[0]+'/'+relative).lower())
            if source == None or root.find(source) == None: fail('driver repository source is absent')
            declared[relative.lower()]=dict(relative=relative,source=source,sha256=expected['digest'])
        if set(declared) != set(inventory):
            fail('version-only driver repository layout changed')
        for relative,item in declared.items():
            target=_REPOSITORY+job['after']+'/'+item['relative']
            files.append(dict(path=target,source=item['source'],sha256=item['sha256']))
            # Exact corresponding installed directories supply the unchanged
            # repository layout's ACL, not a generic nearby WRP descriptor.
            parts=item['relative'].split('/')[:-1]
            for i in range(len(parts)+1):
                suffix=('/'+'/'.join(parts[:i])) if i else ''
                destination=_REPOSITORY+job['after']+suffix
                original=names.get((_REPOSITORY+old+suffix).lower())
                if original == None: fail('installed driver directory is absent')
                descriptor=root.get_security(original)
                if descriptor == None: fail('installed driver directory lacks security')
                if destination in directories and directories[destination] != descriptor:
                    fail('conflicting driver repository directory security')
                directories[destination]=descriptor
    return dict(files=files,directories=directories,source_versions={f['source']:root.get_metadata(f['source']).write_order for f in files})

def apply_direct_driver_repositories(root, plan, audit_payloads=False):
    """Re-resolve and verify repository source epochs before publication; optionally audit payload bytes and return file/directory counts."""
    # Re-resolve the path, not a saved file handle: staging/source replacement
    # between planning and commit must fail without partially publishing.
    sources={item['source']:item['sha256'] for item in plan['files']}
    paths=list(sources)
    for path in paths:
        if root.find(path) == None or root.get_metadata(path).write_order != plan['source_versions'][path]:
            fail('driver repository source changed before publication')
    if audit_payloads:
        for path,actual in zip(paths,digest_many([root.find(p) for p in paths],workers=4)):
            if actual != sources[path]: fail('driver repository source changed or hash mismatch')
    names=image_path_names(root)
    for path in sorted(plan['directories'],key=lambda p:(p.count('/'),p)):
        parent=names[path.rsplit('/',1)[0].lower()]
        actual=names.get(path.lower(),parent+'/'+path.rsplit('/',1)[1])
        if root.find(actual) != None: fail('driver repository directory collides with a file')
        if not testing.attempt(root.get_security,args=[actual]).ok: root.mkdir(actual)
        root.set_security(actual,plan['directories'][path])
        names[path.lower()]=actual
    for item in plan['files']:
        path=item['path']
        parent=names[path.rsplit('/',1)[0].lower()]
        actual=names.get(path.lower(),parent+'/'+path.rsplit('/',1)[1])
        if root.find(actual) != None: root.remove(actual)
        root.hardlink(item['source'],actual)
        # Never carry the old package catalog hint onto changed bytes. Catalog
        # publication/indexing is a later transaction phase; absent hints allow
        # that index to choose the new catalog rather than naming stale proof.
        eas=root.get_metadata(actual).extended_attributes
        filtered=[dict(ea) for ea in eas if ea['name'].lower() != '$ci.cataloghint']
        if len(filtered) != len(eas): root.set_extended_attributes(actual,filtered)
        identity=root.get_metadata(actual).hard_link_id
        if not identity or identity != root.get_metadata(item['source']).hard_link_id:
            fail('driver repository is not linked to its exact store object')
        names[path.lower()]=actual
    return dict(files=len(plan['files']),directories=len(plan['directories']))
