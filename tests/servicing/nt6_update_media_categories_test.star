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

TEST_SUITE=suite('nt6_update_media_categories',[case('subject_scope',test_subject_and_scope),case('stale_sources',test_stale_sources)])
