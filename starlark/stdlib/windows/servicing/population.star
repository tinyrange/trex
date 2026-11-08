"""Offline servicing construction policy. No guest or host servicing tools.

Metadata availability, package admission, and image mutation are distinct phases.
This module must not turn an incomplete analysis into bootable update media.
"""

_NS = "urn:schemas-microsoft-com:asm.v3"
_PACKAGES = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages"

def _package_name(identity):
    language = identity.attribute("language", "neutral")
    return "~".join([
        identity.attribute("name"), identity.attribute("publicKeyToken"),
        identity.attribute("processorArchitecture"),
        "" if language.lower() in ["neutral", "none", ""] else language,
        identity.attribute("version"),
    ])

def collect_servicing_metadata(base, image, source, features, roots, package_limit = 65536, hives = None):
    """Close exact package references over raw/express MUMs and the base store.

    Optional hives are the exact recipe baseline, before update writes. Use the
    same baseline for population, composition, source and winner analysis.
    Roots and features are explicit caller policy, not inferred from preliminary
    payload selection. All registered store packages seed the closure, including
    staged and absent registrations. Parent applicability and XML contained flags
    NEVER prune metadata. Missing references are returned, not authorized to skip.
    """
    # Server cumulative updates can contain more than 80,000 exact MUMs.
    # Keep the conservative default; callers may explicitly budget a larger
    # bounded closure without pruning package metadata before applicability.
    if package_limit < 1 or package_limit > 131072 or not features or not roots:
        fail("servicing metadata needs bounded packages and explicit features/roots")
    software = windows.hive(hives["SOFTWARE"] if hives != None else base[image + "/Windows/System32/config/SOFTWARE"])
    registered = software.find(_PACKAGES).children
    directory = image + "/Windows/servicing/Packages"
    available = {}
    for path in base[directory].files:
        name = path.split("/")[-1]
        if name.lower().endswith(".mum"):
            available.setdefault(name[:-4].lower(), []).append((name[:-4], None, path))
    catalogs = [source.servicing_metadata(feature) for feature in features]
    for catalog in catalogs:
        for name in catalog.packages:
            available.setdefault(name.lower(), []).append((name, catalog, None))
    def open_entry(name, catalog, path):
        return base[path] if catalog == None else catalog.open_package(name)
    def open_entries(entries):
        # Only native immutable readers run on workers. Provenance selection and
        # dependency traversal remain on this thread, in their original order.
        result = [None for unused in entries]
        for i, (name, catalog, path) in enumerate(entries):
            if catalog == None: result[i] = base[path]
        for catalog in catalogs:
            positions = [i for i, entry in enumerate(entries) if entry[1] == catalog]
            opened = catalog.open_packages([entries[i][0] for i in positions], workers=4)
            for i, file in zip(positions, opened): result[i] = file
        return result
    result = _close_servicing_metadata([k.name for k in registered], roots, available, open_entry, package_limit, open_entries=open_entries)
    result["software"] = software
    return result

def _close_servicing_metadata(registered, roots, available, open_entry, package_limit, open_entries=None):
    queue = []
    queued = {}
    for name in registered + roots:
        key = name.lower()
        if key not in available:
            fail("required servicing package metadata unavailable: " + name)
        if key not in queued:
            queued[key] = True
            queue.append(key)
    files = {}
    xmls = {}
    origins = {}
    missing = {}
    batch_start, batch_end = 0, 0
    batch_files, batch_xmls = [], []
    for position in range(package_limit):
        if position == len(queue):
            return dict(files = files, xmls = xmls, origins = origins, missing = missing, roots = list(roots))
        key = queue[position]
        entries = available[key]
        if open_entries != None:
            if position == batch_end:
                # Prefetch only already-enqueued packages. Newly discovered
                # dependencies append after them, preserving breadth-first order.
                batch_start, batch_end = position, min(len(queue), position + 256)
                batch_entries = [entry for key in queue[batch_start:batch_end] for entry in available[key]]
                opened = open_entries(batch_entries)
                if len(opened) != len(batch_entries): fail("metadata batch result length mismatch")
                batch_files = []
                offset = 0
                for batch_key in queue[batch_start:batch_end]:
                    selected = None
                    for entry in available[batch_key]:
                        file = opened[offset]
                        offset += 1
                        if selected != None and selected.bytes() != file.bytes():
                            fail("conflicting metadata for exact package " + entry[0])
                        selected = file
                    batch_files.append(selected)
                batch_xmls = binary.xml_many(batch_files, discard_whitespace=True, workers=4)
            selected = batch_files[position-batch_start]
            root = batch_xmls[position-batch_start].root
        else:
            selected = None
            for name, catalog, path in entries:
                file = open_entry(name, catalog, path)
                if selected != None and selected.bytes() != file.bytes():
                    fail("conflicting metadata for exact package " + name)
                selected = file
            root = binary.xml(selected, discard_whitespace=True).root
        name = entries[-1][0]
        identity = root.child("assemblyIdentity", namespace = _NS)
        if identity == None or _package_name(identity).lower() != key:
            fail("servicing package identity mismatch: " + name)
        # Cabinet member casing is not the CBS identity spelling. Native
        # population callbacks use the signed manifest identity, so retain that
        # spelling after the case-insensitive member/identity check above.
        name = _package_name(identity)
        package = root.child("package", namespace = _NS)
        if package == None:
            fail("servicing package declaration missing: " + name)
        files[name] = selected
        xmls[name] = root
        origins[name] = "base" if entries[-1][1] == None else "update"
        for update in package.children_named("update", namespace = _NS):
            for child in update.children_named("package", namespace = _NS):
                for identity in child.children_named("assemblyIdentity", namespace = _NS):
                    target = _package_name(identity)
                    target_key = target.lower()
                    if target_key not in available:
                        missing.setdefault(target, []).append((name, update.attribute("name")))
                    elif target_key not in queued:
                        if len(queue) >= package_limit:
                            fail("servicing metadata closure exceeds package limit")
                        queued[target_key] = True
                        queue.append(target_key)
    if len(files) != len(queue):
        fail("servicing metadata closure exceeds package limit")
    return dict(files = files, xmls = xmls, origins = origins, missing = missing, roots = list(roots))


def _capability_version_filter(identity):
    # ProcessCapabilityUpdateType supplies a two-component version parser.
    # An omitted or zero version is the native wildcard, not exact empty.
    if "name" not in identity or any([k not in ["name", "version"] for k in identity]):
        fail("initial capability identity requires resolved arch/language policy " + str(identity))
    if "version" not in identity:
        return 0
    parts = identity["version"].split(".")
    if len(parts) != 2 or any([not p.isdigit() or int(p) > 65535 for p in parts]):
        fail("unsupported capability reference version " + identity["version"])
    return (int(parts[0]) << 16) | int(parts[1])

def _capability_version_matches(version_filter, version):
    if version_filter == 0:
        return True
    parts = version.split(".")
    if len(parts) != 4 or any([not p.isdigit() or int(p) > 65535 for p in parts]):
        fail("invalid capability index version " + version)
    # CheckCapabilityMatch compares FileVersionFromString's low DWORD.
    return version_filter == ((int(parts[2]) << 16) | int(parts[3]))

def _initial_servicing_component_state(records, primary):
    # CSI pins retain resolved manifests independently of payload staging.
    # In particular the recipe's completed staged Recall removal retains p!
    # but removes s!, and the package itself is Resolved (0x20), not Absent.
    for prefix, state in [("i!", 0x70), ("s!", 0x40), ("p!", 0x20)]:
        if any([name.startswith(prefix) and value.primary == primary for name,value in records.items()]):
            return state
    return 0

def plan_servicing_population(base, image, closure, work_limit=2097152, hives=None, phase="install", editions=["Microsoft-Windows-ProfessionalEdition"]):
    """Plan ordinary package admission; reject unsupported or unresolved policy.

    This does not apply a CSI transaction or authorize boot. Unknown nonzero
    references fail: the metadata closure is not an omission allowlist.
    """
    if phase not in ["stage", "prestage", "install"]:
        fail("unsupported servicing population phase")
    stage_only = phase == "prestage"
    files = closure['files']

    xmls = closure['xmls']

    sw = closure['software']

    pk = sw.find(_PACKAGES)

    package_keys = pk.children
    pkeys = {k.name.lower(): k for k in package_keys}

    ns = _NS

    pkgname = _package_name

    def parent_blocks(p):
        out=[]
        pending=list(reversed(p.children_named('parent',namespace=ns)))
        for unused in range(4096):
            if not pending: return out
            node=pending.pop()
            out.append(node)
            pending.extend(reversed(node.children_named('parent',namespace=ns)))
        fail('parent block bound')

    def populated_descriptor(name,p,b):
        build=b.attribute('buildCompare','EQ').upper()
        revision=b.attribute('revisionCompare','EQ').upper()
        if p.attribute('releaseType')=='OnDemand Pack' and b.attribute('buildCompare')==None and build=='EQ' and revision=='EQ': build='GE'
        ignore=not (b.attribute('revisionCompare')!=None and (name.lower().startswith('package_for_rollupfix~') or [i for i in b.children_named('assemblyIdentity',namespace=ns) if i.attribute('name').lower()=='package_for_rollupfix']))
        return dict(major_minor='EQ',build=build,revision='GE' if ignore else revision,ignore_revision=ignore)

    names=sorted(files)

    parsed={n:windows.cbs_manifest(files[n]) for n in names}

    packages={n:xmls[n].child('package',namespace=ns) for n in names}

    descriptors=[dict(manifest=parsed[n],comparisons=[populated_descriptor(n,packages[n],b) for b in parent_blocks(packages[n])]) for n in names]

    scopes=windows.cbs_parent_update_scopes(descriptors,names)

    relationships=windows.cbs_parent_relationships(descriptors,names)

    package_values = {n: pkeys[n.lower()].values for n in names if n.lower() in pkeys}
    states={n:package_values[n]['CurrentState'] if n in package_values else 0 for n in names}

    name_by_lower={n.lower():n for n in names}

    familykeys={n:'~'.join(n.lower().split('~')[:-1]) for n in names}

    package_detect={k.name.lower():list(k.values.items()) for k in sw.find('/Microsoft/Windows/CurrentVersion/Component Based Servicing/PackageDetect').children}

    update_detect={k.name.lower():list(k.values) for k in sw.find('/Microsoft/Windows/CurrentVersion/Component Based Servicing/UpdateDetect').children}

    relationshipmap={n:{p:True for p in relationships[i]} for i,n in enumerate(names)}

    ch = windows.hive(hives["COMPONENTS"] if hives != None else base[image + "/Windows/System32/config/COMPONENTS"])

    def ci_elevation(value):
        secondary = value.secondary
        return int(str(secondary)) if secondary else 128

    deployments={k.name:k.values for k in ch.find('/CanonicalData/Deployments').children}

    source_records={key:{name:windows.cbs_deployment_source(value) for name,value in values.items() if name[:2] in ['p!','s!','i!']} for key,values in deployments.items()}
    component_entries = []
    for key in ch.find('/DerivedData/Components').children:
        values = key.values
        component_entries.append(dict(identity=values['identity'], owners=[ci_elevation(v) for link in values if link.startswith('c!') for name,v in source_records[link[2:]].items() if name.startswith('i!')]))

    contexts=[dict(manifest=parsed[n],intended_state=states[n],parents=scopes[i]) for i,n in enumerate(names)]

    index=windows.cbs_update_index(contexts,editions=editions).with_components(component_entries)

    baselines={n:package_values[n].get('Baseline',0) if n in package_values else 0 for n in names}

    descs={n:descriptors[i] for i,n in enumerate(names)}

    versions={n:tuple([int(x) for x in n.split('~')[-1].split('.')]) for n in names}

    families={}

    for n in names:
        families.setdefault(familykeys[n],[]).append(n)

    storeowners=[dict(package=name_by_lower[k.name.lower()],owner=o,state=v&65535,integration=v>>16) for k in package_keys for child in k.children if child.name.lower()=='owners' for o,v in child.values.items()]

    resident_index={k.name.lower():list(k.values) for k in sw.find('/Microsoft/Windows/CurrentVersion/Component Based Servicing/PackageIndex').children}

    def related(n):
        resident=[name_by_lower[x.lower()] for x in resident_index.get(familykeys[n],[]) if x.lower() in name_by_lower]
        allnames=resident+[x for x in families[familykeys[n]] if x not in resident]
        return [x for x in allnames if versions[x]<versions[n]]

    roots = closure['roots']

    # Explicit stage tasks still run ordinary Plan/watch processing. Only the
    # multiphase prestage pass uses PlanStaging flag 0x40 and omits watches.
    # PlanStaging limits the requested owner state, not the aggregate ceiling.
    # Native flag 0x40 preserves resident owners and caps only new update state;
    # package children inherit it. Final ordinary Plan remains independent.
    root_requests=[dict(package=n,owner=n,state=112 if phase == "install" else 64,integration=2,ceiling=4096,stage_only=stage_only) for n in roots]

    parent_candidates = {n: sorted({candidate: True for block in parent_blocks(packages[n]) for identity in block.children_named('assemblyIdentity', namespace=ns) for candidate in families.get('~'.join(pkgname(identity).lower().split('~')[:-1]), [])}) for n in names}

    # This native query depends only on the fixed descriptor/candidate identities
    # and their current states. Keep just its last input vector per package;
    # changed snapshots must be observed, never memoized by package name alone.
    parent_state_cache = {}
    def population_applicability(n,snapshot):
        candidates = parent_candidates[n]
        inputs = snapshot.package_state_vector(candidates)
        previous = parent_state_cache.get(n)
        if previous != None and previous[0] == inputs:
            value = previous[1]
        else:
            value = windows.cbs_parent_states([descs[n]],[dict(package=x,intended_state=inputs[i],baseline=bool(baselines[x])) for i,x in enumerate(candidates)])[0]
            parent_state_cache[n] = (inputs, value)
        if value==4096: value=112
        if value>=112 and any([versions[x]>versions[n] and snapshot.package_state(x)>80 for x in families[familykeys[n]]]): value=80
        return value

    def population_mum(n,snapshot,action):
        # SupersedeLowerVersion examines lower identities while staging, but
        # actions 1/2 bypass their recursive AddPackage admission (CBS9703
        # 9b6cc..9b6de, 9bc2c..9bc30). Install action 3 may supersede them.
        # Selection migration is a separate effect, not an owner request.
        if action==2: return dict(before_updates=[],deferred=[])
        if action>=4:
            candidates=[x for x in related(n) if snapshot.package_state(x)==80]
            if not candidates: return dict(before_updates=[],deferred=[])
            # ReInstallSupersededLowerVersion (CBS32131 110059..110098,
            # 110308..110321) selects the greatest superseded version, not
            # every lower package. Ordinary sessions request installed with
            # no named owner and skip recursive MUM (110422..110469).
            previous=max(candidates,key=lambda x: versions[x])
            if n.lower().startswith('package_for_rollupfix~'):
                fail('LCU reinstall needs capability/container validation '+n)
            if any([c.name=='selectable' for u in update_nodes[previous].values() for c in u.children]):
                fail('reinstall needs adjusted update-selection migration '+previous)
            return dict(before_updates=[dict(package=previous,owner='',state=112,integration=2,ceiling=4096,skip_mum=True)],deferred=[])
        immediate=[]
        later=[]
        for previous in related(n):
            if snapshot.package_state(previous)>80:
                request=dict(package=previous,owner='',state=80,integration=2,ceiling=4096,skip_mum=True)
                if previous.lower().startswith('package_for_rollupfix~'): later.append(request)
                else: immediate.append(request)
        return dict(before_updates=immediate,deferred=later)

    def attrs(node):
        return node.attribute_map()

    update_nodes={n:{attrs(u)['name'].lower():u for u in packages[n].children_named('update',namespace=ns)} for n in names}


    def id_key(a):
        culture=a.get('language','neutral').lower()
        if culture in ['', 'none']: culture='neutral'
        return tuple([a.get(k,'').lower() for k in ['name','version','publicKeyToken','processorArchitecture']])+tuple([culture,a.get('versionScope','').lower(),a.get('type','').lower()])

    deployment_ids={key:windows.csi_identity(values['appid']) for key,values in deployments.items()}

    deployment_by_identity={id_key(dict(name=a.name,version=a.version,language=a.language,publicKeyToken=a.public_key_token,processorArchitecture=a.processor_architecture,versionScope=a.version_scope,type=a.type)):key for key,a in deployment_ids.items()}

    def initial_component(identity,primary):
        key=deployment_by_identity.get(identity)
        if not key: return 0
        records=source_records[key]
        return _initial_servicing_component_state(records, primary)

    component_initial_states={n:{un:[initial_component(id_key(attrs(a)),n+'.'+attrs(u)['name']) for c in u.children if c.name in ['component','driver'] for a in c.children if a.name=='assemblyIdentity'] for un,u in us.items()} for n,us in update_nodes.items()}

    selection_values={n:{un.lower():value for child in pkeys[n.lower()].children if child.name.lower()=='updates' for un,value in child.values.items()} if n.lower() in pkeys else {} for n in names}

    owner_values={} 

    for o in storeowners:
        owner_values.setdefault(o['package'].lower(),{})[o['owner'].lower()]=o['state']

    cap_registry={k.name.lower():k.values for k in sw.find('/Microsoft/Windows/CurrentVersion/Component Based Servicing/CapabilityIndex').children}

    session_editions = {edition.lower(): True for edition in editions}
    def selectable_enabled(node):
        custom=[c for c in node.children if c.name=='customInformation']
        if not custom: return True
        editions=[attrs(e)['name'].lower() for c in custom for group in c.children if group.name=='EnableSelectabilityForEditions' for e in group.children if e.name=='EnableSelectabilityForEdition']
        if not editions: fail('unsupported edition selection')
        return any([edition in session_editions for edition in editions])

    def cap_meta(n):
        nodes=[c for c in packages[n].children if c.name=='declareCapability']
        if not nodes: return dict(kind=0,identity={},languages=[],arches=[])
        if len(nodes)!=1: fail('multiple capability declarations '+n)
        identities=[attrs(a) for c in nodes[0].children if c.name=='capability' for a in c.children if a.name=='capabilityIdentity']
        if len(identities)!=1: fail('unsupported capability identity '+n)
        rules=[a for c in nodes[0].children if c.name=='satelliteInfo' for a in c.children]
        kinds={a.name.lower():True for a in rules}
        if len(kinds)>1: fail('mixed satellite types '+n)
        kind=({'declare':1,'require':2,'applyto':3}[list(kinds)[0]] if kinds else 0)
        return dict(kind=kind,identity=identities[0],languages=[attrs(a)['value'].lower() for a in rules if attrs(a)['type']=='language'],arches=[attrs(a)['value'].lower() for a in rules if attrs(a)['type']=='arch'])

    cap_metadata={n:cap_meta(n) for n in names}

    def capability_start(a,snapshot):
        version_filter = _capability_version_filter(a)
        records=cap_registry.get(a['name'].lower(),{})
        strict=[]
        relaxed=[]
        for p,v in records.items():
            parts=v.split('~')
            if len(parts)!=5: fail('invalid capability index value '+v)
            if parts[0].lower()!=a['name'].lower() or parts[2] or parts[3]: continue
            if not _capability_version_matches(version_filter, parts[4]): continue
            n=name_by_lower[p.lower()]
            if cap_metadata[n]['kind']==3: continue
            value=max([states[x] for x in families[familykeys[n]]])
            if value not in [0,64,112]: fail('unsupported partial capability current state')
            if snapshot.package_state(n)>=64:
                relaxed.append(value)
                if snapshot.package_state(n)!=80: strict.append(value)
        lo=max([0]+strict)
        hi=max([0]+relaxed)
        if lo!=hi: fail('capability current depends on CBSCDS flag '+a['name'])
        return lo

    def initial_update(n,un,target,snapshot):
        un=un.lower()
        u=update_nodes[n][un]
        ds=list(component_initial_states[n][un])
        for p in u.children:
            if p.name=='package':
                for a in p.children:
                    if a.name!='assemblyIdentity': continue
                    child=pkgname(a)
                    actual=name_by_lower.get(child.lower())
                    owner=n
                    if attrs(p).get('integrate')=='liberate' and actual and attrs(packages[actual]).get('releaseType')=='Product': owner=actual
                    value=owner_values.get(child.lower(),{}).get(owner.lower(),0)
                    ds.append(min(value,snapshot.package_state(actual)) if actual else 0)
            if p.name=='capability':
                for a in p.children:
                    if a.name=='capabilityIdentity': ds.append(capability_start(attrs(a),snapshot))
        selectable=[c for c in u.children if c.name=='selectable']
        enabled=bool(selectable) and selectable_enabled(selectable[0])
        cap=any([c.name=='capability' for c in u.children])
        detachable=cap and enabled and attrs(selectable[0]).get('absentIfCapabilityAbsent')=='true'
        if ds and not (detachable and ds[0]>0):
            low=min(ds)
            high=max(ds)
            start=high if high>target else low
        else:
            start=snapshot.applicable(n,un).raw_state
            if enabled:
                stored=selection_values[n].get(un,-1)
                if stored not in [-1,255]: fail('initial selection needs explicit override policy '+str(stored))
                if stored==-1: start=min(start,{'staged':64,'absent':0,'installed':112}[attrs(selectable[0]).get('disposition', 'staged')])
            start=min(start,ds[0] if ds else snapshot.package_state(n))
        return dict(state=start,has_deployments=bool(ds))

    cached_children={n:[name_by_lower[p.lower()] for p,integration in package_detect.get(familykeys[n]+'~0.0.0.0',[]) if p.lower() in name_by_lower and states[name_by_lower[p.lower()]]>0] for n in names}

    def watch_request(n,state=4096):
        return dict(package=n,owner='',state=state,integration=2,ceiling=4096)

    def dependents(e,snapshot):
        n=e.package
        result=[]
        children=cached_children[n]
        if e.dirty:
            for child in children:
                if n in relationshipmap[child] and child not in result: result.append(child)
        for un in update_nodes[n]:
            if un not in e.dirty_updates: continue
            for p in update_detect.get(un,[]):
                child=name_by_lower.get(p.lower())
                if not child: fail('unresolved update-watch package '+p)
                if child==n or child in result or snapshot.package_state(child)<64: continue
                if not child.split('~')[2]: fail('neutral-architecture watch shortcut needs integration policy')
                if child in children and n in relationshipmap[child]: result.append(child)
        return [watch_request(child) for child in result]

    satellite_store_order=[name_by_lower[p.lower()] for values in cap_registry.values() for p in values if cap_metadata[name_by_lower[p.lower()]]['kind']==3]

    def satellites(e,n,snapshot):
        parent=cap_metadata[n]
        if parent['kind']!=2 or not (parent['languages'] or parent['arches']): return []
        a=parent['identity']
        result=[]
        for candidate in satellite_store_order:
            b=cap_metadata[candidate]['identity']
            if a['name'].lower()==b['name'].lower() and a.get('version','').lower()==b.get('version','').lower(): result.append(watch_request(candidate,e.intended_state))
        return result

    # ResolvePackageFromStore uses source kind -1 for non-absent resident
    # packages. Exact roots were explicitly prepared from update sources.
    store_loaded = [n for n in names if states[n] > 0 and n not in roots]
    # Native AddPackageTask marks an LCU install session by the exact identity
    # name, before package admission. This is not inferred from missing files.
    lcu_session = any([n.split('~')[0].lower() == 'package_for_rollupfix' for n in roots])
    return index.ordinary_population(lcu_session=lcu_session, store_loaded_packages=store_loaded, roots=root_requests, store_owners=storeowners, applicability=population_applicability, populate_mum=population_mum, work_limit=work_limit, allow_absent_references=True, watch=dict(initial_update=initial_update, dependents=(lambda e,snapshot: []) if stage_only else dependents, satellites=(lambda e,n,snapshot: []) if stage_only else satellites))
