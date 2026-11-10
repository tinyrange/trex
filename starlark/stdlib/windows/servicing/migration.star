"""Maintain migration manifest membership from admitted component transitions.

Retain unaffected entries in order, then append new declarations in transition
order. This is a membership index; reference transaction enumeration order is
not an input to construction.
"""
load("@stdlib//windows/servicing:runtime.star", "servicing_runtime_manifest_root")
_PATH = '/Windows/WinSxS/migration.xml'
_NS = 'urn:schemas-microsoft-com:asm.v3'

def _filename(name):
    if not name.endswith('.manifest') or not name[:-9] or any([c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for c in name.elems()]):
        fail('invalid migration manifest filename')
    return name

def _entries(file):
    tree = binary.xml(file, discard_whitespace=True).root
    if tree.name != 'migrationManifests' or tree.namespace:
        fail('unsupported migration index root')
    result = []
    seen = {}
    for child in tree.children:
        if child.name != 'file' or child.namespace or child.children:
            fail('unsupported migration index entry')
        name = _filename(child.text)
        if name.lower() in seen:
            fail('duplicate migration index entry')
        seen[name.lower()] = True
        result.append(name)
    return result

def _rewrite(entries, removed, added):
    removed = {n.lower(): True for n in removed}
    result = [n for n in entries if n.lower() not in removed]
    seen = {n.lower(): True for n in result}
    for name in added:
        _filename(name)
        if name.lower() not in seen:
            result.append(name)
            seen[name.lower()] = True
    return '<migrationManifests>' + ''.join(['<file>' + n + '</file>' for n in result]) + '</migrationManifests>'

def plan_update_migration(root, runtime, payloads, baseline_components):
    """Plan migration-index membership from admitted payloads and baseline components, preserving source and manifest proofs."""
    names = root.path_index(lower=True)
    path = names.get(_PATH.lower())
    if path == None:
        fail('baseline migration index is missing')
    original = root.find(path)
    entries = _entries(original)
    components = windows.hive(baseline_components).find('/DerivedData/Components')
    if components == None:
        fail('baseline component identities are missing')
    old = {}
    for node in components.children:
        identity = str(node.values['identity']).lower()
        if identity in old:
            fail('ambiguous baseline migration identity')
        old[identity] = node.name
    admitted = {}
    for stage in payloads['stages'].values():
        files = {f.store_path.lower(): i for i, f in enumerate(stage.files) if f.kind == 'component-manifest'}
        for component in stage.components:
            source = '/Windows/WinSxS/Manifests/' + component.stem + '.manifest'
            key = str(component.identity).lower()
            if key in admitted or source.lower() not in files:
                fail('ambiguous or missing admitted migration manifest')
            admitted[key] = dict(component=component, stage=stage, index=files[source.lower()], path=source)
    removed = []
    added = []
    proofs = []
    for transition in runtime['transitions']:
        before = transition['component_identities'].get('before')
        if before != None:
            stem = old.get(str(before).lower())
            if stem == None:
                fail('migration transition lacks baseline identity')
            removed.append(_filename(stem + '.manifest'))
        document = transition['after']
        if document == None:
            continue
        if 'migration' not in windows.assembly_manifest(document).top_level: continue
        if not any([n.namespace == _NS and n.name == 'migration' for n in servicing_runtime_manifest_root(transition, "after").children]):
            continue
        source = admitted.get(str(transition['component_identities']['after']).lower())
        if source == None or digest(document, algorithm='sha256') != source['component'].manifest_sha256:
            fail('migration declaration differs from admitted manifest')
        source_path = names.get(source['path'].lower())
        if source_path == None or digest(root.find(source_path)) != digest(source['stage'].open(source['index'])):
            fail('migration encoded manifest differs from admitted source')
        proofs.append(dict(path=source_path, hash=digest(root.find(source_path))))
        added.append(_filename(source['component'].stem + '.manifest'))
    removed_names = {r.lower(): True for r in removed}
    content = _rewrite(entries, removed, added)
    return dict(path=path, source_hash=digest(original), order=root.get_metadata(path).write_order, security=root.get_security(path), proofs=proofs, content=content, before=len(entries), after=len(_entries(content)), removed=len([n for n in entries if n.lower() in removed_names]), added=len(added))

def apply_update_migration(root, plan):
    """Validate the migration plan source/epoch and proofs before writing its replacement index; return membership counts."""
    current = root.find(plan['path'])
    if current == None or digest(current) != plan['source_hash'] or root.get_metadata(plan['path']).write_order != plan['order'] or root.get_security(plan['path']) != plan['security']:
        fail('migration index changed before publication')
    for proof in plan['proofs']:
        file = root.find(proof['path'])
        if file == None or digest(file) != proof['hash']:
            fail('migration source changed before publication')
    root.write(plan['path'], plan['content'])
    if root.get_security(plan['path']) != plan['security']:
        fail('migration publication changed security')
    return {key: plan[key] for key in ['before', 'after', 'removed', 'added']}
