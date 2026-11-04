"""Publish catalog lookup hints, never cached signing levels or trust verdicts.

The admitted DriverStore path writes v1 hints for each non-catalog member of
an explicitly cataloged INF repository. Verify the exact source bytes, nested
catalog signature, timestamp chains and each member before any EA mutation.
"""

def _catalog_name(name):
    if not name.lower().endswith('.cat') or len(name) > 255 or any([ord(c) < 33 or ord(c) > 126 or c in '/\\:' for c in name.elems()]):
        fail('invalid catalog hint leaf name')
    return name

def _hint(name):
    name = _catalog_name(name)
    raw = binary.encode(name, encoding='ascii')
    return dict(name='$CI.CATALOGHINT', flags=0, value=binary.concat([binary.u16le(1),binary.u16le(len(raw)),raw]).bytes())

def _roots(file):
    anchors=windows.hive(file).find('/Microsoft/SystemCertificates/ROOT/Certificates')
    if anchors == None or not anchors.children or len(anchors.children)>64:
        fail('catalog hints require bounded ROOT anchors')
    roots=[]
    for key in anchors.children:
        cert=windows.serialized_certificate(key.values['Blob']).certificate
        if cert.sha1 != key.name.lower(): fail('catalog ROOT fingerprint mismatch')
        roots.append(cert.der)
    return roots

def plan_driver_catalog_hints(root, jobs, repositories, host_architecture):
    """Plan signed driver catalog hints for explicit amd64 host jobs and repository bindings; do not modify root."""
    if host_architecture != 'amd64': fail('unestablished driver hint host architecture')
    roots=_roots(root.find('/Windows/System32/config/SOFTWARE'))
    by_repo={j['after'].lower():[] for j in jobs}
    prefix='/Windows/System32/DriverStore/FileRepository/'
    for item in repositories['files']:
        parts=item['path'][len(prefix):].split('/',1)
        by_repo[parts[0].lower()].append(item)
    plans=[]
    catalogs={}
    for job in jobs:
        # Cross-architecture repositories are retained payload, not an executed
        # host DriverStore install. Their files may receive package hints later.
        if job['architecture'].lower() != host_architecture: continue
        version={k.lower():v for k,v in windows.inf(root.find(job['inf_source'])).section('Version').items()}
        catalog_fields={k:v for k,v in version.items() if k.startswith('catalogfile')}
        if not catalog_fields: continue
        # No guessed fallback among decorated architecture/OS selectors.
        if sorted(catalog_fields)!=['catalogfile'] or len(catalog_fields['catalogfile'])!=1:
            fail('unsupported decorated driver catalog selection')
        name=_catalog_name(catalog_fields['catalogfile'][0])
        files=by_repo[job['after'].lower()]
        cat=[f for f in files if f['path'].lower()==(prefix+job['after']+'/'+name).lower()]
        # Inbox INFs may name a separate-distribution catalog absent from both
        # installed and replacement layouts. They use package catalogs instead;
        # no private DriverStore catalog hint is authorized by that name alone.
        if not cat: continue
        if len(cat)!=1: fail('ambiguous admitted driver catalog')
        catfile=root.find(cat[0]['source'])
        if catfile==None or digest(catfile)!=cat[0]['sha256']:
            fail('driver catalog differs from admitted source')
        key=digest(catfile)
        if key not in catalogs:
            signature=windows.catalog_signature(catfile)
            timestamp=signature.timestamp
            if timestamp==None: fail('driver catalog lacks authenticated timestamp')
            windows.certificate_chain(timestamp.signer,roots,timestamp.certificates,timestamp.unix,'timestamping')
            windows.certificate_chain(signature.signer,roots,signature.certificates,timestamp.unix,'code_signing')
            catalogs[key]=windows.catalog_index(catfile)
        index=catalogs[key]
        hint=_hint(name)
        for item in files:
            if item==cat[0]: continue
            file=root.find(item['source'])
            if file==None or digest(file)!=item['sha256']:
                fail('driver hint member differs from admitted source')
            if not any([index[a] and windows.catalog_hash(file,algorithm=a) in index[a] for a in ['sha256','sha1']]):
                fail('driver hint member is outside its declared signed catalog')
            meta=root.get_metadata(item['source'])
            plans.append(dict(path=item['source'],hash=item['sha256'],order=meta.write_order,eas=[dict(e) for e in meta.extended_attributes],hint=hint,catalog=cat[0]['source'],catalog_hash=key))
    return plans

def apply_catalog_hints(root, plans):
    """Validate catalog bytes and file bindings for the batch, then publish hint EAs on the selected objects."""
    destinations={}
    catalog_hashes={}
    for plan in plans:
        file=root.find(plan['path'])
        if file==None or digest(file)!=plan['hash'] or root.get_metadata(plan['path']).write_order!=plan['order'] or root.get_metadata(plan['path']).extended_attributes!=plan['eas']:
            fail('catalog hint member changed before publication')
        if plan['catalog'] not in catalog_hashes:
            cat=root.find(plan['catalog'])
            catalog_hashes[plan['catalog']]=digest(cat) if cat!=None else None
        if catalog_hashes[plan['catalog']]!=plan['catalog_hash']:
            fail('catalog hint proof changed before publication')
        identity=root.get_metadata(plan['path']).hard_link_id or plan['path'].lower()
        if identity in destinations and destinations[identity]!=plan['hint']:
            fail('conflicting catalog hints for one file object')
        destinations[identity]=plan['hint']
    for plan in plans:
        eas=[e for e in plan['eas'] if e['name'].lower()!='$ci.cataloghint']
        root.set_extended_attributes(plan['path'],eas+[plan['hint']])
    return dict(files=len(plans),objects=len(destinations))


def package_hint_paths(parsed):
    """Read exact signed SPC Hint attributes, never infer eligibility from PE type.

    CBS9703 CipSetEasForEachHint (6b90c) skips short v2 subject IDs,
    selects OID 1.3.6.1.4.1.311.12.2.1, flags&10001==10001 and Hint.
    Its offline path is Windows/WinSxS/<NUL-terminated UTF16 value>.
    """
    if parsed['version'] not in [1,2]: fail('unsupported package hint catalog version')
    result=[]
    for entry in parsed['entries']:
        if parsed['version']==2 and len(entry['subject'])<32: continue
        for attr in entry['attributes']:
            if attr['oid']!='1.3.6.1.4.1.311.12.2.1' or not attr['name_value'] or attr['flags']&0x10001!=0x10001 or attr['name'].lower()!='hint': continue
            raw=attr['value']
            if len(raw)<2 or len(raw)%2 or raw[-2:]!=b'\x00\x00': fail('invalid terminated package Hint')
            name=binary.text(raw[:-2],encoding='utf16le').replace(chr(92),'/')
            if not name or len(name)>1024 or any([ord(c)<32 or ord(c)>126 or c in ':*?' for c in name.elems()]) or any([p in ['', '.', '..'] for p in name.split('/')]):
                fail('unsafe package Hint path')
            if len(entry['digest']) not in [20,32]: fail('unsupported package Hint digest')
            result.append(dict(path='/Windows/WinSxS/'+name,digest=entry['digest']))
    return result


def plan_package_catalog_hints(root, packages):
    """Verify actual catalogs and members in execution order, retaining last writer.

    Absent signed paths are not installed by this operation. Native tries the
    open and reports failure; we record absent paths without creating files.
    Present files must still match their own catalog entry, including retained
    compressed base content. No cached signing level is fabricated.
    """
    names=root.path_names(lower=True)
    roots=_roots(root.find('/Windows/System32/config/SOFTWARE'))
    chains={}
    final={}
    proofs={}
    missing={}
    seen={}
    mismatch_count=0
    mismatches=[]
    for package in packages:
        name=_catalog_name(package+'.cat')
        if package.lower() in seen: fail('duplicate package hint execution')
        seen[package.lower()]=True
        path=names.get(('/Windows/servicing/Packages/'+name).lower())
        if path==None: fail('package hint catalog is missing')
        cat=windows.catalog(root.find(path))
        signature=windows.catalog_signature(cat)
        timestamp=signature.timestamp
        if timestamp==None: fail('package hint catalog lacks authenticated timestamp')
        chain=(signature.signer,tuple(signature.certificates),timestamp.signer,tuple(timestamp.certificates),timestamp.unix)
        if chain not in chains:
            windows.certificate_chain(timestamp.signer,roots,timestamp.certificates,timestamp.unix,'timestamping')
            windows.certificate_chain(signature.signer,roots,signature.certificates,timestamp.unix,'code_signing')
            chains[chain]=True
        cat_hash=digest(cat)
        for member in package_hint_paths(windows.catalog_entries(cat)):
            actual=names.get(member['path'].lower())
            if actual==None:
                missing[member['path'].lower()]=True
                continue
            if actual not in proofs:
                file=root.find(actual)
                meta=root.get_metadata(actual)
                logical=archive.dcs(file) if file.size>=4 and file.bytes(0,4)==b'DCS\x01' else file
                proofs[actual]=dict(hash=digest(file),order=meta.write_order,eas=[dict(e) for e in meta.extended_attributes],logical=logical,hashes={},object=('link',meta.hard_link_id) if meta.hard_link_id else ('path',actual.lower()))
            proof=proofs[actual]
            algorithm='sha256' if len(member['digest'])==32 else 'sha1'
            if algorithm not in proof['hashes']:
                proof['hashes'][algorithm]=windows.catalog_hash(proof['logical'],algorithm=algorithm)
            if proof['hashes'][algorithm]!=member['digest']:
                mismatch_count+=1
                if len(mismatches)<16:
                    mismatches.append(actual+'; catalog='+name+'; '+algorithm+' expected='+binary.hex(member['digest'])+' actual='+binary.hex(proof['hashes'][algorithm]))
                continue
            final[proof['object']]=dict(path=actual,hash=proof['hash'],order=proof['order'],eas=proof['eas'],hint=_hint(name),catalog=path,catalog_hash=cat_hash)
    # Complete the read-only verification pass to diagnose independent legacy
    # layouts together. Never return a partial publication plan after a failure.
    if mismatch_count:
        fail('package Hint member hash mismatches ('+str(mismatch_count)+', first 16): '+str(mismatches))
    return dict(plans=list(final.values()),catalogs=len(seen),present_paths=len(proofs),absent_paths=len(missing))


def catalog_hint_name(ea):
    """Decode a v1 lookup hint without treating it as a trust decision."""
    if ea['name'].lower() != '$ci.cataloghint' or ea['flags'] != 0:
        fail('unsupported catalog hint EA')
    raw = ea['value']
    if len(raw) < 4 or binary.read_u16le(raw, 0) != 1 or binary.read_u16le(raw, 2) != len(raw)-4:
        fail('invalid catalog hint header')
    return _catalog_name(binary.text(raw[4:], encoding='ascii'))


def audit_catalog_hints(root, paths=None):
    """Verify emitted hints against the actual registered catalog tree.

    This is read-only and independent of the publication planner. A different
    catalog leaf is not automatically equivalent: it must exist in CatRoot,
    have an authenticated signing timestamp and chains, and cover the member's
    logical bytes. Duplicate catalog leaves must contain identical bytes.
    No reference-image catalogs or filesystem objects participate.
    """
    names = root.path_names(lower=True)
    catalogs = {}
    for lower, path in names.items():
        if lower.startswith('/windows/system32/catroot/') and lower.endswith('.cat'):
            catalogs.setdefault(lower.rsplit('/', 1)[1], []).append(path)
    selected = list(root.files) if paths == None else paths
    if len(selected) > 1048576:
        fail('catalog hint audit path bound exceeded')
    members = []
    objects = {}
    for path in selected:
        actual = names.get(path.lower())
        if actual == None:
            fail('catalog hint audit member is missing: ' + path)
        meta = root.get_metadata(actual)
        hints = [e for e in meta.extended_attributes if e['name'].lower() == '$ci.cataloghint']
        if not hints:
            continue
        if len(hints) != 1:
            fail('duplicate catalog hint EA: ' + actual)
        name = catalog_hint_name(hints[0])
        key = ('link', meta.hard_link_id) if meta.hard_link_id else ('path', actual.lower())
        if key in objects:
            if objects[key] != name.lower():
                fail('inconsistent catalog hints on aliases')
            continue
        objects[key] = name.lower()
        members.append((actual, name.lower()))
    roots = None
    verified = {}
    chains = {}
    failures = []
    failure_count = 0
    matched = 0
    for path, name in members:
        if name not in catalogs:
            failure_count += 1
            if len(failures) < 16:
                failures.append(path + '; missing registered catalog=' + name)
            continue
        if name not in verified:
            sources = catalogs[name]
            hashes = {digest(root.find(p)): True for p in sources}
            if len(hashes) != 1:
                fail('ambiguous registered catalog leaf: ' + name)
            cat = windows.catalog(root.find(sources[0]))
            signature = windows.catalog_signature(cat)
            timestamp = signature.timestamp
            if timestamp == None:
                fail('hinted registered catalog lacks authenticated timestamp: ' + name)
            if roots == None:
                roots = _roots(root.find(names['/windows/system32/config/software']))
            chain = (signature.signer, tuple(signature.certificates), timestamp.signer, tuple(timestamp.certificates), timestamp.unix)
            if chain not in chains:
                windows.certificate_chain(timestamp.signer, roots, timestamp.certificates, timestamp.unix, 'timestamping')
                windows.certificate_chain(signature.signer, roots, signature.certificates, timestamp.unix, 'code_signing')
                chains[chain] = True
            verified[name] = windows.catalog_index(cat)
        file = root.find(path)
        logical = archive.dcs(file) if file.size >= 4 and file.bytes(0,4) == b'DCS\x01' else file
        index = verified[name]
        if not any([index[a] and windows.catalog_hash(logical, algorithm=a) in index[a] for a in ['sha256', 'sha1']]):
            failure_count += 1
            if len(failures) < 16:
                failures.append(path + '; not covered by registered catalog=' + name)
            continue
        matched += 1
    if failure_count:
        fail('catalog hint audit failures (' + str(failure_count) + ', first 16): ' + str(failures))
    return dict(objects=len(members), matched=matched, catalogs=len(verified), chains=len(chains))
