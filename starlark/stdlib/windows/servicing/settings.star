"""Publish settings manifests from exact admitted component declarations.

WCP 9703 ShouldManifestBeSettingsManifestLinked (11be48) tests configuration
or RegistryKey.overridable count, not the presence of migration rules. The
original encoded manifest is hardlinked; existing older versions are retained.
"""
_NS='urn:schemas-microsoft-com:asm.v3'
_DIRECTORY='/Windows/WinSxS/SettingsManifests'

def _needed(document):
    tree=binary.xml(document,discard_whitespace=True).root
    for node in tree.children:
        if node.namespace!=_NS: continue
        if node.name=='configuration': return True
        if node.name!='registryKeys': continue
        for key in node.children:
            if key.namespace!=_NS or key.name!='registryKey': continue
            if any([c.namespace==_NS and c.name=='overridable' for c in key.children]): return True
    return False

def plan_update_settings_manifests(root,runtime,payloads):
    """Select admitted settings manifests and bind exact source objects, security and destination epochs."""
    sources={}
    for plan in payloads['stages'].values():
        files={entry.store_path.lower():i for i,entry in enumerate(plan.files) if entry.kind=='component-manifest'}
        for component in plan.components:
            path='/Windows/WinSxS/Manifests/'+component.stem+'.manifest'
            if path.lower() not in files: fail('settings manifest lacks exact encoded source')
            # Runtime identities can preserve baseline casing (NonSxS), while
            # the staged manifest uses nonSxS. CSI source joins are case-insensitive.
            identity=str(component.identity).lower()
            if identity in sources: fail('ambiguous settings manifest identity')
            sources[identity]=dict(path=path,stem=component.stem,sha256=component.manifest_sha256,plan=plan,index=files[path.lower()])
    names=root.path_names(lower=True)
    parent=names.get(_DIRECTORY.lower())
    if parent==None: fail('settings manifest directory is missing')
    result=[]
    destinations={}
    for transition in runtime['transitions']:
        document=transition['after']
        if document==None or not _needed(document): continue
        source=sources.get(str(transition['component_identities']['after']).lower())
        if source==None: fail('settings manifest has no admitted staged identity')
        if digest(document,algorithm='sha256')!=source['sha256']: fail('settings declaration differs from admitted manifest')
        path=names.get(source['path'].lower())
        if path==None: fail('settings source manifest is missing')
        current=root.find(path)
        if digest(current)!=digest(source['plan'].open(source['index'])): fail('settings encoded manifest differs from admitted source')
        destination=parent+'/'+source['stem']+'.manifest'
        if destination.lower() in destinations: fail('duplicate settings manifest destination')
        destinations[destination.lower()]=True
        old=names.get(destination.lower())
        if old!=None:
            if digest(root.find(old))!=digest(current): fail('existing settings manifest differs from admitted source')
            destination=old
        metadata=root.get_metadata(path)
        security=root.get_security(path)
        if security==None: fail('settings source lacks security')
        result.append(dict(source=path,path=destination,order=metadata.write_order,security=security,destination_order=root.get_metadata(old).write_order if old!=None else None))
    return result

def apply_update_settings_manifests(root,plans):
    """Preflight settings source/destination objects before publishing manifest hardlinks; return selection/link counts."""
    for p in plans:
        if root.find(p['source'])==None or root.get_metadata(p['source']).write_order!=p['order'] or root.get_security(p['source'])!=p['security']:
            fail('settings manifest source changed before publication')
        present=root.find(p['path'])!=None
        if present!=(p['destination_order']!=None) or present and root.get_metadata(p['path']).write_order!=p['destination_order']:
            fail('settings manifest destination changed before publication')
    linked=0
    for p in plans:
        source_meta=root.get_metadata(p['source'])
        if p['destination_order']!=None:
            if source_meta.hard_link_id and source_meta.hard_link_id==root.get_metadata(p['path']).hard_link_id: continue
            root.remove(p['path'])
        root.hardlink(p['source'],p['path'])
        if not root.get_metadata(p['path']).hard_link_id or root.get_metadata(p['path']).hard_link_id!=root.get_metadata(p['source']).hard_link_id:
            fail('settings manifest did not retain exact source object')
        linked+=1
    return dict(selected=len(plans),linked=linked)
