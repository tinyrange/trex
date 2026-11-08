"""Deferred NGEN work preserves transaction ordering and source epochs."""
load('//tests:testing.star','case','equal','raises','suite')
load('@stdlib//windows/servicing:ngen.star','collect_update_ngen','plan_update_ngen','apply_update_ngen')
_PATH='/Windows/System32/config/SOFTWARE'
_QUEUE='/Microsoft/.NETFramework/NGenQueue'

def _manifest(arch='msil',parameter='/NoDependencies /queue:3'):
    return ('<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Sample" version="10.0.0.0" processorArchitecture="'+arch+'" publicKeyToken="31bf3856ad364e35"/><file name="SAMPLE.dll"><ngen managedversion="4.0.0.0" parameter="'+parameter+'"/></file></assembly>')

def _fixture():
    root=directory()
    sd=windows.compile_sddl('O:SYG:SYD:AI(A;CI;KA;;;SY)(A;CI;KR;;;BU)')
    root.write(_PATH,windows.hive_from_patches('SOFTWARE',[
        dict(key=_QUEUE+'/'+p+'/'+suffix,name=name,type='REG_SZ',value=value) for p in ['Win32','Win64'] for suffix,name,value in [('Default/9','','existing command'),('PersistedPriorities','19','persisted command')]
    ],keys=[dict(key=_QUEUE+'/'+p+'/Default',security=sd) for p in ['Win32','Win64']]))
    root.write('/Windows/System32/config/COMPONENTS',windows.hive_from_patches('COMPONENTS',[dict(key='/',name='StoreArchitecture',type='REG_BINARY',value=binary.u32le(9))],keys=[dict(key='/',security=sd)]))
    return root,dict(transitions=[dict(before=_manifest(),after=_manifest())])

def test_pending_order_architecture_and_preservation():
    root,runtime=_fixture()
    plan=plan_update_ngen(root,runtime)
    equal(len(plan['records']),8)
    result=apply_update_ngen(root,plan)
    equal(result['queued'],len(plan['records']))
    equal(windows.hive(root.find('/Windows/System32/config/COMPONENTS')).find('/Installers/Ngen').values,{'TicklerArchWow':1,'TicklerArchNative':1})
    hive=windows.hive(root.find(_PATH))
    for p in ['Win32','Win64']:
        parent=_QUEUE+'/'+p+'/Default/'
        equal(hive.find(parent+'9').values,{'(default)':'existing command'})
        equal(hive.find(parent+'10').values,{'(default)':'uninstall "Sample, Version=4.0.0.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=msil" /NoDependencies '})
        equal(hive.find(parent+'11').values,{'(default)':'install "Sample, Version=4.0.0.0, Culture=Neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=msil" /NoDependencies /queue:3'})
        equal(hive.find(parent+'12').values,{'(default)':'update /queue'})
        equal(hive.find(parent+'13').values,{'(default)':'persisted command'})
        equal(hive.find(_QUEUE+'/'+p+'/PersistedPriorities').values,{'19':'persisted command'})
    for arch,counts in [('amd64',(0,2)),('x86',(2,0)),('wow64',(0,0))]:
        manifest=_manifest(arch)
        commands=collect_update_ngen(dict(transitions=[dict(before=manifest,after=manifest)]))
        equal((len(commands['Win32']),len(commands['Win64'])),counts)
    # A previous identical command is not deduplicated across transactions.
    equal(len(plan_update_ngen(root,runtime)['records']),8)

def test_server_target_annotation_preserves_native_default_dispatch():
    plain=_manifest(parameter='/NoDependencies /queue:2')
    expected=collect_update_ngen(dict(transitions=[dict(before=plain,after=plain)]))
    for mode in ['64bitonly','64bitOnly']:
        marked=plain.replace('<ngen ', '<ngen win64targetarch="'+mode+'" ')
        commands=collect_update_ngen(dict(transitions=[dict(before=marked,after=marked)]))
        equal(commands,expected)
        equal((len(commands['Win32']),len(commands['Win64'])),(2,2))
    for arch,mode in [('msil','unknown'),('msil',''),('msil','32bitonly'),('amd64','64bitonly')]:
        marked=_manifest(arch).replace('<ngen ', '<ngen win64targetarch="'+mode+'" ')
        raises(collect_update_ngen,args=[dict(transitions=[dict(before=None,after=marked)])],message='unsupported NGEN win64targetarch')

def test_atomic_epoch_and_bad_declarations():
    root,runtime=_fixture()
    plan=plan_update_ngen(root,runtime)
    root.write(_PATH,windows.patch_hive(root.find(_PATH),[dict(key='/Unrelated',name='Keep',type='REG_SZ',value='yes')]))
    before=digest(root.find(_PATH))
    raises(apply_update_ngen,args=[root,plan],message='changed before commit')
    equal(digest(root.find(_PATH)),before)
    for parameter in ['/queue:1 /queue:2','/unknown','/NoDependencies /NoDependencies']:
        raises(collect_update_ngen,args=[dict(transitions=[dict(before=None,after=_manifest(parameter=parameter))])],message='unsupported NGEN parameters')
    raises(collect_update_ngen,args=[dict(transitions=[dict(before=None,after=_manifest('arm64'))])],message='unsupported NGEN target')


def test_explicit_gac_architecture_controls_ngen():
    for component, managed, counts in [('amd64','msil',(2,2)),('wow64','x86',(2,0)),('amd64','amd64',(0,2))]:
        manifest=_manifest(component).replace('SAMPLE.dll','SAMPLE.exe').replace('<ngen ', '<ngen xmlns="urn:schemas-microsoft-com:asm.v3" ').replace('</file>','<gac clrarch="'+managed+'"/></file>')
        commands=collect_update_ngen(dict(transitions=[dict(before=manifest,after=manifest)]))
        equal((len(commands['Win32']),len(commands['Win64'])),counts)
        for values in commands.values():
            for command in values:
                equal('processorArchitecture='+managed+'"' in command, True)
    bad=_manifest().replace('</file>','<gac clrarch="unknown"/></file>')
    raises(collect_update_ngen,args=[dict(transitions=[dict(before=None,after=bad)])],message='NGEN CLR architecture')


def test_global_update_directive_is_not_an_assembly_command():
    root,runtime=_fixture()
    directive=_manifest('amd64','IssueNgenUpdate').replace('SAMPLE.dll','clr.dll')
    runtime['transitions'].extend([dict(before=directive,after=directive),dict(before=None,after=directive)])
    plan=plan_update_ngen(root,runtime)
    for platform in ['Win32','Win64']:
        commands=[command for target,command in plan['records'] if target==platform]
        equal(len([c for c in commands if c=='update /queue']),1)
        equal(len(commands),4)
        equal(any(['IssueNgenUpdate' in c or 'clr.dll' in c for c in commands]),False)
        equal(commands[-2:],["update /queue","persisted command"])
    commands=collect_update_ngen(dict(transitions=[dict(before=directive,after=None)]))
    equal(commands,{'Win32':['update /queue'],'Win64':['update /queue']})

TEST_SUITE=suite('nt6_update_ngen',[
    case('global_update_directive',test_global_update_directive_is_not_an_assembly_command),
    case('explicit_gac_architecture',test_explicit_gac_architecture_controls_ngen),
    case('server_target_annotation',test_server_target_annotation_preserves_native_default_dispatch),
    case('pending_order_and_architecture',test_pending_order_architecture_and_preservation),
    case('atomic_epoch_and_validation',test_atomic_epoch_and_bad_declarations),
])
