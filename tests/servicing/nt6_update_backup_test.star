"""Native BootRecovery selection, names, and independent guarded copies."""
load('//tests:testing.star','case','equal','raises','suite')
m=testing.module('@stdlib//windows/servicing:backup.star')

def test_categories_and_native_names():
    body='<memberships><categoryMembership><id name="Microsoft.Windows.Categories" version="1.0.0.0" publicKeyToken="365143bb27e7ac8b" typeName="BootRecovery"/></categoryMembership></memberships>'
    for namespace in ['urn:schemas-microsoft-com:asm.v1','urn:schemas-microsoft-com:asm.v3']:
        doc='<assembly xmlns="'+namespace+'">'+body+'</assembly>'
        equal(m['_needed'](doc),True)
        equal(m['_needed'](doc.replace('BootRecovery','Services')),False)
        equal(m['_needed'](doc.replace('365143bb27e7ac8b','31bf3856ad364e35')),False)
        equal(m['_needed'](doc.replace('1.0.0.0','2.0.0.0')),False)
        equal(m['_needed'](doc.replace(namespace,'urn:foreign')),False)
    for name,expected in [('ClipSVC.dll','clipsvc.dll_0a2c978a'),('drvinst.exe','drvinst.exe_6593e92a'),('umpnpmgr.dll','umpnpmgr.dll_112f9bb4'),('wtd.sys','wtd.sys_ce04a0e0')]:
        equal(m['_filename']('stem',name),'stem_'+expected)
    for name in ['../file.dll',chr(92)+'file.dll','é.dll','..']:
        raises(m['_filename'],args=['stem',name],message='unsupported backup filename')

def _fixture():
    root=directory()
    parent='/Windows/WinSxS/Backup'
    root.mkdir(parent)
    security=windows.compile_sddl('O:SYG:SYD:(A;;FA;;;SY)')
    root.set_security(parent,security)
    files=[]
    for name in ['first','second']:
        source='/Windows/WinSxS/component/'+name
        root.write(source,name)
        files.append(dict(source=source,path=parent+'/'+name,order=root.get_metadata(source).write_order,destination_order=None))
    return root,dict(parent=parent,parent_security=security,security=security,files=files,retirements=[])

def test_copy_preflight_and_independence():
    root,p=_fixture()
    root.write(p['files'][1]['source'],'changed')
    raises(m['apply_update_backups'],args=[root,p],message='source changed')
    equal(root.find(p['files'][0]['path']),None)
    root,p=_fixture()
    root.write(p['files'][1]['path'],'concurrent')
    raises(m['apply_update_backups'],args=[root,p],message='destination changed')
    equal(root.find(p['files'][0]['path']),None)
    root,p=_fixture()
    equal(m['apply_update_backups'](root,p),dict(selected=2,written=2,retired=0))
    for f in p['files']:
        equal(root.find(f['path']).read(),root.find(f['source']).read())
        equal(root.get_metadata(f['path']).hard_link_id,0)
        equal(root.get_metadata(f['path']).file_attributes,0) # NORMAL is canonicalized to zero.
        equal(root.get_metadata(f['path']).has_file_attributes,True)
        equal(root.get_security(f['path']),p['security'])
        root.write(f['source'],'replacement')
        equal(root.find(f['path']).read(),f['path'].split('/')[-1])

def test_predecessor_retirement_requires_exact_hash():
    root,p=_fixture()
    identity=b'Test, Culture=neutral, Version=10.0.1.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64'
    stem='test_'+hex(windows.csi_identity_hash(identity))[2:]
    manifest='/Windows/WinSxS/Manifests/'+stem+'.manifest'
    old_manifest='/Windows/WinSxS/Backup/'+stem+'.manifest'
    root.write(manifest,'encoded manifest')
    root.write(old_manifest,'retained old manifest')
    old='/Windows/WinSxS/Backup/'+m['_filename'](stem,'test.dll')
    root.write(old,'abc')
    doc='<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Test" version="10.0.1.0" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"/><memberships><categoryMembership><id name="Microsoft.Windows.Categories" version="1.0.0.0" publicKeyToken="365143bb27e7ac8b" typeName="BootRecovery"/></categoryMembership></memberships><file name="test.dll"><hash xmlns="urn:schemas-microsoft-com:asm.v2"><Transforms xmlns="http://www.w3.org/2000/09/xmldsig#"><Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity"/></Transforms><DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><DigestValue xmlns="http://www.w3.org/2000/09/xmldsig#">ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=</DigestValue></hash></file></assembly>'
    runtime=dict(transitions=[dict(before=doc,component_identities=dict(before=identity))])
    retired=m['_retirements'](root,runtime,root.path_names(lower=True),{})
    equal([f['path'] for f in retired],[old])
    equal(m['_retirements'](root,runtime,root.path_names(lower=True),{old.lower():True}),[])
    p['retirements']=retired
    root.write(old,'modified')
    raises(m['_retirements'],args=[root,runtime,root.path_names(lower=True),{}],message='predecessor hash mismatch')
    raises(m['apply_update_backups'],args=[root,p],message='retirement changed')
    equal(root.find(p['files'][0]['path']),None)
    root.write(old,'abc')
    p['retirements']=m['_retirements'](root,runtime,root.path_names(lower=True),{})
    equal(m['apply_update_backups'](root,p)['retired'],1)
    equal(root.find(old),None)
    equal(root.find(old_manifest).read(),'retained old manifest')

TEST_SUITE=suite('nt6_update_backup',[
    case('native_categories_and_names',test_categories_and_native_names),
    case('independent_copies_and_atomicity',test_copy_preflight_and_independence),
    case('hash_qualified_retirement',test_predecessor_retirement_requires_exact_hash),
])
