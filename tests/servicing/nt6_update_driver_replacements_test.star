"""Conservative replacement guards must not lose ordered INF instructions."""
load('//tests:testing.star','case','equal','raises','suite')
replacement=testing.module('@stdlib//windows/servicing:driver_replacements.star')

def _file(text):
    root=directory()
    root.write('/inf',text)
    return root.find('/inf')

_INF='[Version]\nSignature="$Windows NT$"\nDriverVer=06/21/2006,10.0.26100.1\n[Install]\nAddReg=A\nDelReg=B\nAddReg=C\n[Copy]\none.sys\ntwo.sys\n[Strings]\nLabel="Old label"\n'

def test_version_and_date_only():
    changed=_INF.replace('06/21/2006,10.0.26100.1','09/17/2026,10.0.26100.9711')
    result=replacement['require_version_only_driver_inf'](_file(_INF),_file(changed))
    equal(result['after'],['09/17/2026','10.0.26100.9711'])
    equal(result['identical'],False)
    equal(replacement['require_version_only_driver_inf'](_file(_INF),_file(_INF))['identical'],True)

def test_interleaved_duplicates_are_not_equal():
    changed=_INF.replace('AddReg=A\nDelReg=B\nAddReg=C','AddReg=A\nAddReg=C\nDelReg=B')
    # The grouped dictionary loses cross-directive ordering; do not use it as
    # authority to keep existing installed configuration.
    equal(windows.inf(_INF).json,windows.inf(changed).json)
    raises(replacement['require_version_only_driver_inf'],args=[_file(_INF),_file(changed)],message='changes INF instructions')

def test_semantic_changes_and_copy_order_rejected():
    for changed in [_INF.replace('one.sys\ntwo.sys','two.sys\none.sys'),_INF.replace('Old label','New label'),_INF.replace('DelReg=B','DelReg=C')]:
        raises(replacement['require_version_only_driver_inf'],args=[_file(_INF),_file(changed)],message='changes INF instructions')

def test_missing_duplicate_and_wrong_section_versions_rejected():
    for changed in [_INF.replace('DriverVer=06/21/2006,10.0.26100.1\n',''),_INF.replace('[Install]','DriverVer=06/21/2006,10.0.26100.2\n[Install]'),_INF.replace('[Version]','[Other]')]:
        raises(replacement['require_version_only_driver_inf'],args=[_file(_INF),_file(changed)],message='DriverVer')

hive_replacement=testing.module('@stdlib//windows/servicing:driver_replace_hives.star')

def _hive_fixture():
    root=directory()
    descriptor=windows.compile_sddl('O:BAG:BUD:(A;CI;KA;;;SY)(A;CI;RC;;;OW)(A;CI;KR;;;WD)')
    for hive in ['SYSTEM','DRIVERS','SOFTWARE']:
        keys=[dict(key_parts=['DriverDatabase','DriverPackages'],security=descriptor)]
        patches=[]
        if hive != 'SOFTWARE':
            package='sample.inf_'+('amd64_old' if hive=='SYSTEM' else 'x86_old')
            parts=['DriverDatabase','DriverPackages',package]
            keys.append(dict(key_parts=parts,security=descriptor))
            patches=[dict(key_parts=parts,name='',type='REG_SZ',value='sample.inf'),dict(key_parts=parts,name='Version',type='REG_BINARY',value=b'A'*48),dict(key_parts=parts,name='FileSize',type='REG_QWORD',value=123),dict(key_parts=parts+['Configuration'],name='Keep',type='REG_DWORD',value=9)]
            aliases=['DriverDatabase','DriverInfFiles','sample.inf']
            patches += [dict(key_parts=aliases,name='',type='REG_MULTI_SZ',value=[package,'retained.inf_other']),dict(key_parts=aliases,name='Active',type='REG_SZ',value=package)]
        if hive == 'SYSTEM':
            patches += [dict(key='/ControlSet001/Services/Sample',name='ImagePath',type='REG_EXPAND_SZ',value=chr(92).join(['','SystemRoot','System32','DriverStore','FileRepository','sample.inf_amd64_old','sample.sys'])),dict(key='/ControlSet001/Services/Sample',name='Start',type='REG_DWORD',value=4)]
        patches += [dict(key='/Untouched',name='Similar',type='REG_SZ',value='sample.inf_amd64_old_suffix'),dict(key='/Untouched',name='Bytes',type='REG_BINARY',value=b'keep')]
        root.write('/Windows/System32/config/'+hive,windows.hive_from_patches(hive,patches,keys=keys))
    return root

def test_atomic_registry_replacement_preserves_configuration_and_aliases():
    root=_hive_fixture()
    originals={name:root.find('/Windows/System32/config/'+name).bytes() for name in ['SYSTEM','DRIVERS','SOFTWARE']}
    rows=[dict(before='sample.inf_'+arch+'_old',after='sample.inf_'+arch+'_new',inf='sample.inf',version=b'B'*48,size=65537) for arch in ['amd64','x86']]
    plans=hive_replacement['plan_version_only_driver_hives'](root,rows)
    equal({name:root.find('/Windows/System32/config/'+name).bytes() for name in originals},originals)
    hive_replacement['apply_version_only_driver_hives'](root,plans)
    for name,arch in [('SYSTEM','amd64'),('DRIVERS','x86')]:
        hive=windows.hive(root.find('/Windows/System32/config/'+name))
        prefix='/DriverDatabase/DriverPackages/sample.inf_'+arch
        equal(hive.find(prefix+'_old'),None)
        equal(hive.find(prefix+'_new').values['Version'],b'B'*48)
        equal(hive.find(prefix+'_new').values['FileSize'],65537)
        equal(hive.find(prefix+'_new/Configuration').values['Keep'],9)
        equal(hive.find('/DriverDatabase/DriverInfFiles/sample.inf').values['(default)'],['sample.inf_'+arch+'_new','retained.inf_other'])
        equal(hive.find('/DriverDatabase/DriverInfFiles/sample.inf').values['Active'],'sample.inf_'+arch+'_new')
        equal(hive.find('/Untouched').values['Similar'],'sample.inf_amd64_old_suffix')
    system=windows.hive(root.find('/Windows/System32/config/SYSTEM'))
    equal(system.find('/ControlSet001/Services/Sample').values['Start'],4)
    equal('sample.inf_amd64_new' in system.find('/ControlSet001/Services/Sample').values['ImagePath'],True)
    equal(root.find('/Windows/System32/config/SOFTWARE').bytes(),originals['SOFTWARE'])
    raises(hive_replacement['apply_version_only_driver_hives'],args=[root,plans],message='changed before')

def test_missing_binding_does_not_publish_partial_hives():
    root=_hive_fixture()
    source=root.find('/Windows/System32/config/SYSTEM').bytes()
    rows=[dict(before='sample.inf_amd64_old',after='sample.inf_amd64_new',inf='sample.inf',version=b'B'*48,size=64),dict(before='missing',after='missing_new',inf='missing.inf',version=b'B'*48,size=64)]
    raises(hive_replacement['plan_version_only_driver_hives'],args=[root,rows],message='one actual old package binding')
    equal(root.find('/Windows/System32/config/SYSTEM').bytes(),source)

def test_still_owned_active_source_is_retained():
    root=_hive_fixture()
    source=windows.hive(root.find('/Windows/System32/config/SYSTEM')).find('/DriverDatabase/DriverPackages/sample.inf_amd64_old').values
    row=dict(before='already_absent',source='sample.inf_amd64_old',retain_source=True,after='sample.inf_amd64_new',inf='sample.inf',version=b'B'*48,size=64)
    plans=hive_replacement['plan_version_only_driver_hives'](root,[row])
    hive_replacement['apply_version_only_driver_hives'](root,plans)
    hive=windows.hive(root.find('/Windows/System32/config/SYSTEM'))
    equal(hive.find('/DriverDatabase/DriverPackages/sample.inf_amd64_old').values,source)
    equal(hive.find('/DriverDatabase/DriverInfFiles/sample.inf').values['(default)'],['sample.inf_amd64_old','sample.inf_amd64_new','retained.inf_other'])
    equal(hive.find('/DriverDatabase/DriverInfFiles/sample.inf').values['Active'],'sample.inf_amd64_new')

def test_driver_rank_downgrade_rejected():
    changed=_INF.replace('06/21/2006,10.0.26100.1','06/20/2006,10.0.26100.9711')
    raises(replacement['require_version_only_driver_inf'],args=[_file(_INF),_file(changed)],message='downgrade')


repositories=testing.module('@stdlib//windows/servicing:driver_repositories.star')

def _repository_fixture():
    root=directory()
    prefix='/Windows/System32/DriverStore/FileRepository/'
    descriptor=windows.compile_sddl('O:SYG:SYD:P(A;;FA;;;SY)(A;;GRGX;;;BU)')
    contents={'sample.inf':b'new INF','I386/driver.dll':b'new DLL'}
    body=''
    for relative,data in contents.items():
        old=prefix+'sample.inf_x86_old/'+relative
        source='/Windows/WinSxS/x86_new/'+relative
        root.write(old,b'old')
        root.write(source,data)
        root.set_security(source,descriptor)
        root.set_file_attributes(source,32)
        root.set_times(source,11,12,13)
        root.set_extended_attributes(source,[dict(name='Keep',flags=0,value=b'EA')])
        body += '<file name="%s"><hash xmlns="urn:schemas-microsoft-com:asm.v2" xmlns:d="http://www.w3.org/2000/09/xmldsig#"><d:Transforms><d:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity"/></d:Transforms><d:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><d:DigestValue>%s</d:DigestValue></hash></file>' % (relative.replace('/',chr(92)),binary.base64(digest(data)))
    for path in [prefix.rstrip('/'),prefix+'sample.inf_x86_old',prefix+'sample.inf_x86_old/I386']:
        root.set_security(path,descriptor)
    root.write('/manifest','<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"><assemblyIdentity name="sample" version="1.0.0.0" processorArchitecture="x86" type="dualModeDriver"/>'+body+'</assembly>')
    jobs=[dict(before='sample.inf_x86_old',after='sample.inf_x86_new',architecture='x86')]
    replacements=[dict(unchanged=False,after=dict(path='/Windows/WinSxS/x86_new/sample.inf',row=dict(identity='sample'),declaration=dict(repository='sample.inf_x86_new')))]
    return root,jobs,replacements,{'sample':root.find('/manifest')}

def test_complete_native_x86_repository_objects():
    root,jobs,replacements,manifests=_repository_fixture()
    plan=repositories['plan_direct_driver_repositories'](root,jobs,replacements,manifests)
    target='/Windows/System32/DriverStore/FileRepository/sample.inf_x86_new/'
    equal(root.find(target+'sample.inf'),None)
    counts=repositories['apply_direct_driver_repositories'](root,plan)
    equal(counts,dict(files=2,directories=2))
    for relative in ['sample.inf','I386/driver.dll']:
        source='/Windows/WinSxS/x86_new/'+relative
        equal(root.find(target+relative).bytes(),root.find(source).bytes())
        actual=root.get_metadata(target+relative)
        equal(actual.hard_link_id,root.get_metadata(source).hard_link_id)
        equal(actual.file_attributes,32)
        equal(actual.last_write_time,12)
        equal(actual.extended_attributes,[dict(name='Keep',flags=0,value=b'EA')])
        equal(root.get_security(target+relative),root.get_security(source))
    equal(root.get_security(target+'I386'),root.get_security('/Windows/System32/DriverStore/FileRepository/sample.inf_x86_old/I386'))
    equal(root.find('/Windows/SysWOW64/DriverStore/FileRepository/sample.inf_x86_new/sample.inf'),None)

def test_repository_stale_source_rejected_before_publication():
    root,jobs,replacements,manifests=_repository_fixture()
    plan=repositories['plan_direct_driver_repositories'](root,jobs,replacements,manifests)
    root.write('/Windows/WinSxS/x86_new/I386/driver.dll',b'tampered')
    raises(repositories['apply_direct_driver_repositories'],args=[root,plan],message='source changed before publication')
    equal(root.find('/Windows/System32/DriverStore/FileRepository/sample.inf_x86_new/sample.inf'),None)

def test_repository_layout_drift_rejected():
    root,jobs,replacements,manifests=_repository_fixture()
    root.write('/Windows/System32/DriverStore/FileRepository/sample.inf_x86_old/extra.pnf',b'unmodeled')
    raises(repositories['plan_direct_driver_repositories'],args=[root,jobs,replacements,manifests],message='layout changed')

def test_repository_lazy_default_and_explicit_audit():
    root,jobs,replacements,manifests=_repository_fixture()
    profiler=clock.read_profiler(min_seconds=0.0)
    for path in ['/Windows/WinSxS/x86_new/sample.inf','/Windows/WinSxS/x86_new/I386/driver.dll']:
        root.write(path,profiler.file(root.find(path),path))
    plan=repositories['plan_direct_driver_repositories'](root,jobs,replacements,manifests)
    repositories['apply_direct_driver_repositories'](root,plan)
    equal(profiler.snapshot()['total']['calls'],0)
    repositories['apply_direct_driver_repositories'](root,plan,audit_payloads=True)
    equal(profiler.snapshot()['total']['calls'] > 0,True)
    root,jobs,replacements,manifests=_repository_fixture()
    # Corrupt input present BEFORE planning: generation alone is not a digest
    # proof. Explicit audit must still reconstruct and reject the bad source.
    root.write('/Windows/WinSxS/x86_new/I386/driver.dll',b'corrupt')
    plan=repositories['plan_direct_driver_repositories'](root,jobs,replacements,manifests)
    raises(repositories['apply_direct_driver_repositories'],args=[root,plan],kwargs=dict(audit_payloads=True),message='hash mismatch')
    equal(root.find('/Windows/System32/DriverStore/FileRepository/sample.inf_x86_new/sample.inf'),None)

runtime_aliases=testing.module('@stdlib//windows/servicing:driver_runtime.star')

def _runtime_fixture():
    root,jobs,replacements,manifests=_repository_fixture()
    old='/Windows/System32/DriverStore/FileRepository/sample.inf_x86_old/I386/driver.dll'
    root.hardlink(old,'/Windows/SysWOW64/Driver.dll')
    root.hardlink(old,'/Windows/SysWOW64/Other.dll')
    root.write('/Windows/SysWOW64/SameBytes.dll',root.find(old))
    repositories_plan=repositories['plan_direct_driver_repositories'](root,jobs,replacements,manifests)
    plan=runtime_aliases['plan_direct_driver_runtime'](root,jobs,repositories_plan)
    return root,repositories_plan,plan

def test_runtime_existing_object_not_equal_bytes():
    root,repositories_plan,plan=_runtime_fixture()
    equal(sorted([p['path'] for p in plan]),['/Windows/SysWOW64/Driver.dll','/Windows/SysWOW64/Other.dll'])
    repositories['apply_direct_driver_repositories'](root,repositories_plan)
    equal(runtime_aliases['apply_direct_driver_runtime'](root,plan),dict(installed_aliases=2,replaced=2))
    source='/Windows/WinSxS/x86_new/I386/driver.dll'
    for path in ['/Windows/SysWOW64/Driver.dll','/Windows/SysWOW64/Other.dll']:
        equal(root.find(path).bytes(),b'new DLL')
        equal(root.get_metadata(path).hard_link_id,root.get_metadata(source).hard_link_id)
        equal(root.get_security(path),root.get_security(source))
    equal(root.find('/Windows/SysWOW64/SameBytes.dll').bytes(),b'old')
    equal(root.find('/Windows/System32/Driver.dll'),None)
    equal(runtime_aliases['apply_direct_driver_runtime'](root,plan),dict(installed_aliases=2,replaced=0))

def test_runtime_stale_batch_has_no_partial_publication():
    for target in ['destination','source','binding']:
        root,repositories_plan,plan=_runtime_fixture()
        affected={'destination':plan[-1]['path'],'source':plan[-1]['source'],'binding':plan[-1]['original']}[target]
        root.write(affected,b'changed')
        raises(runtime_aliases['apply_direct_driver_runtime'],args=[root,plan],message='changed before publication')
        equal(root.find(plan[0]['path']).bytes(),b'old')

def test_runtime_external_alias_is_not_authorized():
    root,repositories_plan,plan=_runtime_fixture()
    root.hardlink(plan[0]['original'],'/Users/Test/driver.dll')
    jobs=[dict(before='sample.inf_x86_old',after='sample.inf_x86_new')]
    raises(runtime_aliases['plan_direct_driver_runtime'],args=[root,jobs,repositories_plan],message='explicit destination policy')

retire=testing.module('@stdlib//windows/servicing:driver_retire.star')

def test_retirement_keeps_store_alias_and_retained_package():
    root,jobs,replacements,manifests=_repository_fixture()
    old='/Windows/System32/DriverStore/FileRepository/sample.inf_x86_old/I386/driver.dll'
    root.hardlink(old,'/Windows/WinSxS/x86_old/driver.dll')
    root.write('/Windows/System32/DriverStore/FileRepository/retained/file.sys',b'keep')
    jobs.append(dict(before='absent',source='retained',after='new',retain_source=True))
    plan=retire['plan_direct_driver_retirement'](root,jobs)
    result=retire['apply_direct_driver_retirement'](root,plan)
    equal(result,dict(packages=1,files=2,directories=2))
    equal(root.find(old),None)
    equal(root.find('/Windows/WinSxS/x86_old/driver.dll').bytes(),b'old')
    equal(root.find('/Windows/System32/DriverStore/FileRepository/retained/file.sys').bytes(),b'keep')

def test_retirement_rejects_late_changes_before_deleting():
    for change in ['extra','replacement']:
        root,jobs,replacements,manifests=_repository_fixture()
        plan=retire['plan_direct_driver_retirement'](root,jobs)
        path='/Windows/System32/DriverStore/FileRepository/sample.inf_x86_old/'+('extra.sys' if change=='extra' else 'I386/driver.dll')
        root.write(path,b'late')
        raises(retire['apply_direct_driver_retirement'],args=[root,plan],message='changed before publication')
        equal(root.find('/Windows/System32/DriverStore/FileRepository/sample.inf_x86_old/sample.inf').bytes(),b'old')

TEST_SUITE=suite('nt6_update_driver_replacements',[
    case('retirement_retained_sources',test_retirement_keeps_store_alias_and_retained_package),
    case('retirement_stale_batch',test_retirement_rejects_late_changes_before_deleting),
    case('runtime_installed_aliases',test_runtime_existing_object_not_equal_bytes),
    case('runtime_stale_batch',test_runtime_stale_batch_has_no_partial_publication),
    case('runtime_external_alias',test_runtime_external_alias_is_not_authorized),
    case('repository_lazy_and_audit',test_repository_lazy_default_and_explicit_audit),
    case('native_x86_repository',test_complete_native_x86_repository_objects),
    case('repository_source_guard',test_repository_stale_source_rejected_before_publication),
    case('repository_layout_guard',test_repository_layout_drift_rejected),
    case('version_only',test_version_and_date_only),
    case('ordered_duplicates',test_interleaved_duplicates_are_not_equal),
    case('semantic_changes',test_semantic_changes_and_copy_order_rejected),
    case('required_version',test_missing_duplicate_and_wrong_section_versions_rejected),
    case('physical_hives',test_atomic_registry_replacement_preserves_configuration_and_aliases),
    case('missing_binding',test_missing_binding_does_not_publish_partial_hives),
    case('retained_source',test_still_owned_active_source_is_retained),
    case('driver_rank',test_driver_rank_downgrade_rejected),
])
