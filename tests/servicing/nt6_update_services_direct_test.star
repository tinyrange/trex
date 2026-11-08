"""Service deltas preserve policy, unrelated owners and atomic hive publication."""
load('//tests:testing.star','case','equal','raises','suite')
load('@stdlib//windows/servicing:services_direct.star','plan_direct_services','apply_direct_services')
load('@stdlib//windows/servicing:registry_effects.star','apply_update_registry_effects')
_NS='urn:schemas-microsoft-com:asm.v3'
_SYS='/Windows/System32/config/SYSTEM'
_SOFT='/Windows/System32/config/SOFTWARE'
_KEY='/ControlSet001/Services/'
_GROUP='/Microsoft/Windows NT/CurrentVersion/SvcHost'
_SD=windows.compile_sddl('O:SYG:SYD:AI(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)')

def _manifest(name,image='old.exe',group='Old',sddl='D:(A;;RP;;;SY)',extra='',start='demand',launch_protected=None):
    text='<assembly xmlns="'+_NS+'"><assemblyIdentity name="test" processorArchitecture="amd64" version="1.0.0.0"/><memberships><categoryMembership><id typeName="Service"/><categoryInstance><serviceData name="'+name+'" imagePath="'+image+'" start="'+start+'" type="win32OwnProcess" errorControl="normal"><securityDescriptor name="S"/>'+extra+'</serviceData></categoryInstance></categoryMembership><categoryMembership><id name="Microsoft.Windows.Categories" publicKeyToken="365143bb27e7ac8b" typeName="SvcHost"/><categoryInstance subcategory="'+group+'"><serviceGroup position="last" serviceName="'+name+'"/></categoryInstance></categoryMembership></memberships><trustInfo><securityDescriptorDefinition name="S" sddl="'+sddl+'"/></trustInfo></assembly>'
    if launch_protected!=None: text=text.replace('<serviceData ', '<serviceData launchProtected="'+launch_protected+'" ')
    file=binary.concat([text])
    return (file,binary.xml(file).root)

def _runtime(rows):
    transitions=[]
    for before,after in rows:
        documents={side:doc for side,doc in [('before',before),('after',after)] if doc!=None}
        transitions.append(dict(documents=documents,component_identities={s:b'test, Culture=neutral, Version=1.0.0.0, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64' for s in documents}))
    return dict(transitions=transitions)

def _root():
    root=directory()
    root.write(_SYS,windows.hive_from_patches('SYSTEM',[
        dict(key='/Select',name='Current',type='REG_DWORD',value=1),
        dict(key=_KEY+'Test',name='ImagePath',type='REG_EXPAND_SZ',value='old.exe'),
        dict(key=_KEY+'Test',name='Start',type='REG_DWORD',value=4),
        dict(key=_KEY+'Test',name='Custom',type='REG_SZ',value='preserve'),
        dict(key=_KEY+'Gone',name='ImagePath',type='REG_EXPAND_SZ',value='old.exe'),
    ],keys=[dict(key='/ControlSet001/Services',security=_SD),dict(key=_KEY+'Test',security=_SD),dict(key=_KEY+'Gone',security=_SD)]))
    root.write(_SOFT,windows.hive_from_patches('SOFTWARE',[
        dict(key=_GROUP,name='Old',type='REG_MULTI_SZ',value=['Unrelated','Test','Gone']),
        dict(key=_GROUP,name='Other',type='REG_SZ',value='keep'),
    ],keys=[dict(key=_GROUP,security=_SD)]))
    return root

def test_configuration_deltas_preserve_policy_and_group_members():
    root=_root()
    repeated='<serviceTrigger type="fixture"/><serviceTrigger type="another"/>'
    runtime=_runtime([(_manifest('Test',extra=repeated),_manifest('Test',image='new.exe',group='New',extra=repeated)),(_manifest('Gone'),None),(None,_manifest('Added',image='added.exe',group='New'))])
    result=apply_direct_services(root,runtime)
    hive=windows.hive(root.find(_SYS))
    equal(hive.find(_KEY+'Test').values,{'ImagePath':'new.exe','Start':4,'Custom':'preserve'})
    equal(hive.find(_KEY+'Gone'),None)
    equal(hive.find(_KEY+'Added').values['Start'],3)
    equal(hive.find(_KEY+'Added').values['Type'],16)
    software=windows.hive(root.find(_SOFT))
    equal(software.find(_GROUP).values['Old'],['Unrelated'])
    equal(set(software.find(_GROUP).values['New']),set(['Added','Test']))
    equal(software.find(_GROUP).values['Other'],'keep')
    equal(hive.find(_KEY+'Test').security,_SD)
    equal(result['publication']['removed_keys'],1)

def test_definition_change_and_failure_action_bytes():
    root=_root()
    failure='<failureActions resetPeriod="900"><actions><action delay="1000" type="restartService"/><action delay="5000" type="restartService"/><action delay="60000" type="restartService"/></actions></failureActions>'
    runtime=_runtime([(_manifest('Test'),_manifest('Test',sddl='D:(A;;RPWP;;;SY)',extra=failure))])
    apply_direct_services(root,runtime)
    hive=windows.hive(root.find(_SYS))
    equal(hex(hive.find(_KEY+'Test').values['FailureActions']),'840300000000000000000000030000001400000001000000e803000001000000881300000100000060ea0000')
    expected=windows.security_descriptor_parts(windows.compile_sddl('O:SYG:SYD:(A;;RPWP;;;SY)'))
    equal(windows.security_descriptor_parts(hive.find(_KEY+'Test/Security').values['Security']),expected)
    equal(hive.find(_KEY+'Test').values['Start'],4)

def test_unsupported_change_and_stale_source_are_atomic():
    root=_root()
    original={p:digest(root.find(p)) for p in [_SYS,_SOFT]}
    runtime=_runtime([(_manifest('Test'),_manifest('Test',extra='<serviceTrigger type="new"/>'))])
    raises(plan_direct_services,args=[root,runtime],message='unsupported changed service child')
    equal({p:digest(root.find(p)) for p in original},original)
    runtime=_runtime([(_manifest('Test'),_manifest('Test',image='new.exe'))])
    plan=plan_direct_services(root,runtime)
    root.write(_SOFT,windows.patch_hive(root.find(_SOFT),[dict(key=_GROUP,name='Other',type='REG_SZ',value='late')]))
    raises(apply_update_registry_effects,args=[root,plan['plans']],message='changed before commit')
    equal(digest(root.find(_SYS)),original[_SYS])

def test_unchanged_competing_declarations_and_service_rights():
    root=_root()
    a,b=_manifest('Test'),_manifest('Test',image='other.exe')
    apply_direct_services(root,_runtime([(a,a),(b,b)]))
    equal(windows.hive(root.find(_SYS)).find(_KEY+'Test').values['ImagePath'],'old.exe')
    raises(plan_direct_services,args=[root,_runtime([(a,b),(b,b)])],message='competing declarations')
    mod=testing.module('@stdlib//windows/servicing:services_direct.star')
    result=mod['_service_security']('D:(A;;GRGX;;;SY)(A;;GA;;;BA)((A;;GR;;;IU)S:(AU;FA;GA;;;WD)',None)
    parts=windows.security_descriptor_parts(result)
    equal([a['mask'] for a in windows.acl_entries(parts['dacl'])['entries']],[0x201fd,0xf01ff,0x2008d])
    equal(windows.acl_entries(parts['sacl'])['entries'][0]['mask'],0xf01ff)
    raises(mod['_service_security'],args=['D:(A;;RP;;;SY',None])


def test_unchanged_x86_contribution_is_not_a_view_mapping():
    root=_root()
    original={p:digest(root.find(p)) for p in [_SYS,_SOFT]}
    a,b=_manifest('Test'),_manifest('Test',image='new.exe')
    runtime=_runtime([(a,a),(a,a)])
    x86=runtime['transitions'][1]
    x86['component_identities']={s:binary.encode(binary.text(v).replace('Architecture=amd64','Architecture=x86')) for s,v in x86['component_identities'].items()}
    result=apply_direct_services(root,runtime)
    equal(result['services'],[])
    equal(result['groups'],0)
    equal({p:digest(root.find(p)) for p in original},original)
    # Do not discard x86 ownership before detecting an amd64-side change.
    runtime['transitions'][0]=_runtime([(a,b)])['transitions'][0]
    raises(plan_direct_services,args=[root,runtime],message='unestablished x86 contribution')
    x86['documents']['after']=_manifest('Test',group='New')
    raises(plan_direct_services,args=[root,dict(transitions=[x86])],message='changed x86 SvcHost')
    equal({p:digest(root.find(p)) for p in original},original)


def test_launch_protection_matches_installed_native_controls():
    # Independent source Server controls: sppsvc=1, ClipSVC=2, WinDefend=3.
    for name,value in [('windows',1),('windowsLight',2),('antimalwareLight',3)]:
        root=_root()
        runtime=_runtime([(_manifest('Test'),_manifest('Test',launch_protected=name))])
        apply_direct_services(root,runtime)
        values=windows.hive(root.find(_SYS)).find(_KEY+'Test').values
        equal(values['LaunchProtected'],value)
        equal(values['Start'],4)
    root=_root()
    original=digest(root.find(_SYS))
    raises(plan_direct_services,args=[root,_runtime([(_manifest('Test'),_manifest('Test',launch_protected='unknown'))])],message='unsupported service launchProtected')
    equal(digest(root.find(_SYS)),original)

TEST_SUITE=suite('nt6_update_services_direct',[
    case('launch_protection',test_launch_protection_matches_installed_native_controls),
    case('unchanged_x86',test_unchanged_x86_contribution_is_not_a_view_mapping),
    case('unchanged_owners_and_service_rights',test_unchanged_competing_declarations_and_service_rights),
    case('configuration_and_policy',test_configuration_deltas_preserve_policy_and_group_members),
    case('security_and_failure_actions',test_definition_change_and_failure_action_bytes),
    case('atomic_guards',test_unsupported_change_and_stale_source_are_atomic),
])
