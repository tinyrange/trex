"""Settings publication selects native settings declarations and exact objects."""
load('//tests:testing.star','case','equal','raises','suite')
m=testing.module('@stdlib//windows/servicing:settings.star')

def _xml(body):
    return '<a:assembly xmlns:a="urn:schemas-microsoft-com:asm.v3" xmlns:foreign="urn:other">'+body+'</a:assembly>'

def test_selection_is_namespace_aware_and_not_migration():
    for body,needed in [
        ('<a:configuration/>',True),
        ('<a:registryKeys><a:registryKey><a:overridable/></a:registryKey></a:registryKeys>',True),
        ('<a:registryKeys><a:registryKey><a:registryValue/></a:registryKey></a:registryKeys>',False),
        ('<a:migration settingsVersion="1"/>',False),
        ('<foreign:configuration/>',False),
        ('<a:registryKeys><a:registryKey><foreign:overridable/></a:registryKey></a:registryKeys>',False),
    ]:
        equal(m['_needed'](_xml(body)),needed)

def _fixture():
    root=directory()
    security=windows.compile_sddl('O:SYG:SYD:(A;;FA;;;SY)')
    plans=[]
    for name in ['one','two']:
        source='/Windows/WinSxS/Manifests/'+name+'.manifest'
        path='/Windows/WinSxS/SettingsManifests/'+name+'.manifest'
        root.write(source,'encoded '+name)
        root.set_security(source,security)
        plans.append(dict(source=source,path=path,order=root.get_metadata(source).write_order,security=security,destination_order=None))
    root.write('/Windows/WinSxS/SettingsManifests/old.manifest','keep')
    return root,plans

def test_exact_links_and_atomic_preflight():
    root,plans=_fixture()
    root.write(plans[1]['source'],'changed')
    raises(m['apply_update_settings_manifests'],args=[root,plans],message='source changed')
    equal(root.find(plans[0]['path']),None)
    root,plans=_fixture()
    root.write(plans[1]['path'],'concurrent')
    raises(m['apply_update_settings_manifests'],args=[root,plans],message='destination changed')
    equal(root.find(plans[0]['path']),None)
    root,plans=_fixture()
    equal(m['apply_update_settings_manifests'](root,plans),dict(selected=2,linked=2))
    for p in plans:
        equal(root.get_metadata(p['path']).hard_link_id,root.get_metadata(p['source']).hard_link_id)
        equal(root.get_security(p['path']),p['security'])
        p['destination_order']=root.get_metadata(p['path']).write_order
    equal(m['apply_update_settings_manifests'](root,plans),dict(selected=2,linked=0))
    equal(root.find('/Windows/WinSxS/SettingsManifests/old.manifest').read(),'keep')

TEST_SUITE=suite('nt6_update_settings',[
    case('native_predicate',test_selection_is_namespace_aware_and_not_migration),
    case('object_links_and_atomicity',test_exact_links_and_atomic_preflight),
])
