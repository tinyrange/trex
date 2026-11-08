"""Target subject security, Include/Needs scope and atomic media publication."""
load('//tests:testing.star','case','equal','raises','suite')
m=testing.module('@stdlib//windows/servicing:media_categories.star')

def _fixture():
    root=directory()
    parent=m['_PARENT']
    sd=windows.compile_sddl('O:BAG:S-1-5-21-1-2-3-513'+m['_DACL'])
    system=windows.hive_from_patches('SYSTEM',[],keys=[dict(key=parent,security=sd)])
    root.write(m['_SYSTEM'],system)
    ks='[KS.Registration]\nAddReg=Names\n[Names]\nHKLM,"SYSTEM\\CurrentControlSet\\Control\\MediaCategories\\{00000000-0000-0000-0000-000000000001}",Name,0,"Audio"\n'
    root.write('/Windows/INF/ks.inf',ks)
    root.write('/driver.inf','[Install]\nInclude=ks.inf\nNeeds=KS.Registration\n')
    job=dict(architecture='amd64',inf_source='/driver.inf')
    return root,[job],root.find('/Windows/INF/ks.inf')

def test_subject_and_scope():
    root,jobs,ks=_fixture()
    plan=m['plan_update_media_categories'](root,jobs,ks,'S-1-5-21-4-5-6-513')
    equal((plan['requests'],plan['keys'],plan['values']),(1,1,1))
    after=windows.hive(plan['file']).find(m['_PARENT']).children[0]
    equal(windows.sid_string(windows.security_descriptor_parts(after.security)['group']),'S-1-5-21-4-5-6-513')
    equal(after.values['Name'],'Audio')
    jobs[0]['architecture']='x86'
    equal(m['plan_update_media_categories'](root,jobs,ks,'S-1-5-21-4-5-6-513'),None)
    jobs[0]['architecture']='amd64'
    root.write('/driver.inf','[Install]\nNeeds=KS.Registration\n')
    raises(m['plan_update_media_categories'],args=[root,jobs,ks,'S-1-5-21-4-5-6-513'],message='explicit')

def test_stale_sources():
    root,jobs,ks=_fixture()
    plan=m['plan_update_media_categories'](root,jobs,ks,'S-1-5-21-4-5-6-513')
    root.write('/driver.inf','changed')
    raises(m['apply_update_media_categories'],args=[root,plan],message='source changed')
    equal(digest(root.find(m['_SYSTEM'])),plan['source_hash'])
    root,jobs,ks=_fixture()
    plan=m['plan_update_media_categories'](root,jobs,ks,'S-1-5-21-4-5-6-513')
    equal(m['apply_update_media_categories'](root,plan),dict(requests=1,keys=1,values=1))


def test_server_native_creation():
    # Source kernel B65A1E5D9D57D828E82F8C75F19E98571 SeAssignSecurity,
    # NULL creator, container=1, registry mapping, BA owner and explicit group.
    parent=binary.decode("0100148cc4000000d000000000000000140000000200b00006000000001218001900020001020000000000052000000021020000001218003f000f0001020000000000052000000020020000001214003f000f00010100000000000512000000001a14003f000f000101000000000003000000000012180019000200010200000000000f02000000010000000012380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce010100000000000512000000010100000000000512000000","hex")
    expected=binary.decode("0100048cc4000000d400000000000000140000000200b00006000000001218001900020001020000000000052000000021020000001218003f000f0001020000000000052000000020020000001214003f000f00010100000000000512000000001a14003f000f000101000000000003000000000012180019000200010200000000000f02000000010000000012380019000200010a00000000000f0300000000040000b031803f6cbc634c3ce050d1970ca1620f01cb197e7aa6c0fae697f119a30cce0102000000000005200000002002000001050000000000051500000007000000080000000900000001020000","hex")
    root,jobs,ks=_fixture()
    path=m['_SYSTEM']
    root.write(path,windows.hive_from_patches('SYSTEM',[],keys=[dict(key=m['_PARENT'],security=parent)],source=root.find(path)))
    plan=m['plan_update_media_categories'](root,jobs,ks,'S-1-5-21-7-8-9-513')
    after=windows.hive(plan['file']).find(m['_PARENT'])
    equal(after.security,parent)
    equal(windows.security_descriptor_parts(after.children[0].security),windows.security_descriptor_parts(expected))
    equal(m['apply_update_media_categories'](root,plan),dict(requests=1,keys=1,values=1))
    # A changed parent SACL/control is not silently admitted by its DACL alone.
    altered=binary.concat([parent[:2],binary.u16le(0x8404),parent[4:]])
    raises(m['_child_security'],args=[altered,'S-1-5-21-7-8-9-513'],message='unestablished')

TEST_SUITE=suite('nt6_update_media_categories',[case('server_native_creation',test_server_native_creation),case('subject_scope',test_subject_and_scope),case('stale_sources',test_stale_sources)])
