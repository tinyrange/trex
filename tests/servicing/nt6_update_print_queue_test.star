"""Deferred printer records bind exact inputs and target paths, not random IDs."""
load('//tests:testing.star','case','equal','raises','suite')
load('@stdlib//windows/servicing:print_queue.star','plan_direct_print_queue','apply_direct_print_queue')
_PATH='/Windows/System32/config/SOFTWARE'
_KEY='/Microsoft/Windows NT/CurrentVersion/Print/PackagesToAdd'

def _fixture():
    root=directory()
    sd=windows.compile_sddl('O:SYG:SYD:AI(A;CI;KA;;;SY)(A;CI;KR;;;BU)')
    root.write(_PATH,windows.hive_from_patches('SOFTWARE',[
        dict(key='/Microsoft/Windows NT/CurrentVersion',name='SystemRoot',type='REG_SZ',value='C:'+chr(92)+'Windows'),
        dict(key=_KEY+'/unrelated',name='Keep',type='REG_SZ',value='yes'),
    ],keys=[dict(key=_KEY,security=sd)]))
    path='/Windows/WinSxS/amd64_printer/sample.inf'
    root.write(path,'[Version]\nClass=Printer\nClassGUID={4D36E979-E325-11CE-BFC1-08002BE10318}\nDriverVer=06/21/2006,10.0.26100.9711\n')
    row=dict(unchanged=False,after=dict(path=path,row=dict(architecture='amd64',inf='sample.inf',hash=binary.base64(digest(root.find(path))))),comparison=dict(after=['06/21/2006','10.0.26100.9711']))
    return root,row

def test_target_binding_idempotency_and_architecture():
    root,row=_fixture()
    x86=dict(row,after=dict(row['after'],row=dict(row['after']['row'],architecture='x86')))
    plan=plan_direct_print_queue(root,[row,x86])
    equal(plan['records'],[{'Architecture':9,'Inf Path':chr(92).join(['C:','Windows','WinSxS','amd64_printer','sample.inf']),'KB Name':'sample.inf_6-21-2006_10.0.26100.9711','Published Name':'sample.inf'}])
    result=apply_direct_print_queue(root,plan)
    equal(result['queued'],1)
    equal(result['installation'],'pending-first-boot')
    equal(plan_direct_print_queue(root,[row,x86])['records'],[])
    equal(windows.hive(root.find(_PATH)).find(_KEY+'/unrelated').values,{'Keep':'yes'})
    # Existing records are matched by their semantics, not our chosen UUID.
    hive=windows.hive(root.find(_PATH))
    queued=[c for c in hive.find(_KEY).children if c.name!='unrelated'][0]
    root.write(_PATH,windows.patch_hive(root.find(_PATH),[
        dict(key=_KEY+'/{11111111-2222-4333-8444-555555555555}',name=n.lower(),type=v.type,value=v.raw) for n,v in queued.value_records.items()
    ],delete_keys=[_KEY+'/'+queued.name]))
    equal(plan_direct_print_queue(root,[row])['records'],[])

def test_stale_or_mismatched_source_cannot_publish():
    root,row=_fixture()
    original=digest(root.find(_PATH))
    plan=plan_direct_print_queue(root,[row])
    root.write(row['after']['path'],'tampered')
    raises(apply_direct_print_queue,args=[root,plan],message='source changed')
    raises(plan_direct_print_queue,args=[root,[row]],message='differs from admitted')
    equal(digest(root.find(_PATH)),original)

TEST_SUITE=suite('nt6_update_print_queue',[
    case('target_and_pending_semantics',test_target_binding_idempotency_and_architecture),
    case('input_epoch',test_stale_or_mismatched_source_cannot_publish),
])
