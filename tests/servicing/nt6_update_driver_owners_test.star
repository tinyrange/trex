"""Owner persistence: physical leaves, shared owners, recreation and stale inputs."""
load('//tests:testing.star','case','equal','raises','suite')
owners=testing.module('@stdlib//windows/servicing:driver_owners.star')

def _fixture():
    root=directory()
    parent=windows.compile_sddl('O:BAG:BUD:(A;CI;KA;;;SY)(A;CI;RC;;;OW)(A;CI;KR;;;WD)')
    original=windows.compile_sddl('O:BAG:BUD:P(A;;KA;;;BA)')
    keys=[dict(key_parts=p,security=parent) for p in [['Drivers'],['Drivers','amd64'],['Drivers','amd64','test.inf']]]
    patches=[]
    for hash,names in [('Old/Hash=',[('First',7),('Second',9)]),('Untouched=',[('Keep',3)])]:
        parts=['Drivers','amd64','test.inf',hash]
        keys.append(dict(key_parts=parts,security=original))
        for name,value in names: patches.append(dict(key_parts=parts,name=name,type='REG_DWORD',value=value))
    patches.append(dict(key='/Unrelated',name='Keep',type='REG_SZ',value='untouched'))
    source=windows.hive_from_patches('COMPONENTS',patches,keys=keys)
    root.write('/Windows/System32/config/COMPONENTS',source)
    return root,source,original

def _op(kind,hash,owner):
    return dict(kind=kind,architecture='amd64',inf='test.inf',hash=hash,owner=owner)

def test_owner_effects_preserve_shared_leaves_and_literal_hashes():
    root,source,original=_fixture()
    plan=owners['plan_update_driver_owners'](source,[_op(0,'Old/Hash=','FIRST'),_op(1,'Old/Hash=','First'),_op(0,'New/Hash=','New'),_op(0,'New/Hash=','New'),_op(1,'Absent=','None')])
    equal(plan['outputs'],[(1,0),(1,1),(0,1),(1,0),(0,0)])
    equal(len(plan['first']),1)
    equal(len(plan['last']),0)
    equal(root.find('/Windows/System32/config/COMPONENTS').bytes(),source.bytes())
    owners['apply_update_driver_owners'](root,plan)
    hive=windows.hive(root.find('/Windows/System32/config/COMPONENTS'))
    equal(hive.find(['Drivers','amd64','test.inf','Old/Hash=']).values,{'Second':9})
    equal(hive.find(['Drivers','amd64','test.inf','Old/Hash=']).security,original)
    equal(hive.find(['Drivers','amd64','test.inf','New/Hash=']).values,{'New':0})
    equal(hive.find('/Drivers/amd64/test.inf/New'),None)
    equal(hive.find(['Drivers','amd64','test.inf','Untouched=']).values,{'Keep':3})
    equal(hive.find('/Unrelated').values,{'Keep':'untouched'})

def test_last_owner_recreation_gets_new_object_security():
    root,source,original=_fixture()
    plan=owners['plan_update_driver_owners'](source,[_op(1,'Old/Hash=','First'),_op(1,'Old/Hash=','Second'),_op(0,'Old/Hash=','Replacement'),_op(1,'Untouched=','Keep')])
    equal(plan['outputs'],[(1,1),(1,0),(0,1),(1,0)])
    owners['apply_update_driver_owners'](root,plan)
    hive=windows.hive(root.find('/Windows/System32/config/COMPONENTS'))
    leaf=hive.find(['Drivers','amd64','test.inf','Old/Hash='])
    equal(leaf.values,{'Replacement':0})
    equal(leaf.security==original,False)
    equal(windows.security_descriptor_parts(leaf.security)['owner'],windows.security_descriptor_parts(windows.compile_sddl('O:SYG:SY'))['owner'])
    equal(hive.find(['Drivers','amd64','test.inf','Untouched=']),None)
    equal(hive.find('/Unrelated').values,{'Keep':'untouched'})

def test_stale_owner_source_is_not_overwritten():
    root,source,unused=_fixture()
    plan=owners['plan_update_driver_owners'](source,[_op(0,'New=','Owner')])
    changed=windows.hive_from_patches('COMPONENTS',[dict(key='/Unrelated',name='Concurrent',type='REG_DWORD',value=1)],source=source)
    root.write('/Windows/System32/config/COMPONENTS',changed)
    raises(owners['apply_update_driver_owners'],args=[root,plan],message='source changed')
    equal(root.find('/Windows/System32/config/COMPONENTS').bytes(),changed.bytes())

def test_execution_order_keeps_shared_object_alive():
    root,source,original=_fixture()
    parts=['Drivers','amd64','test.inf','Old/Hash=']
    source=windows.patch_hive(source,[dict(key_parts=parts,name='pkg~First',type='REG_DWORD',value=7),dict(key_parts=parts,name='pkg~Second',type='REG_DWORD',value=9)],delete_values=[dict(key_parts=parts,name=n) for n in ['First','Second']])
    registered=[_op(1,'Old/Hash=','pkg~First'),_op(1,'Old/Hash=','pkg~Second'),_op(0,'Old/Hash=','newpkg~Replacement')]
    ordered=owners['order_update_driver_owner_operations'](registered)
    plan=owners['plan_update_driver_owners'](source,ordered)
    equal(plan['first'],[])
    equal(plan['last'],[])
    leaf=windows.hive(plan['file']).find(parts)
    equal(leaf.values,{'newpkg~Replacement':0})
    equal(leaf.security,original)
    equal([r['kind'] for r in registered],[1,1,0])

def test_critical_inf_group_runs_in_second_subpass():
    rows=[dict(_op(1,'A','p~remove'),inf='same.inf'),dict(_op(0,'B','p~CRITDOQ-arrive'),inf='SAME.INF'),dict(_op(0,'C','p~ordinary'),inf='same.inf',architecture='x86'),dict(_op(0,'D','p~critdoq-lowercase'),inf='other.inf'),dict(_op(1,'E','p~ordinary'),inf='other.inf')]
    equal(owners['order_update_driver_owner_operations'](rows),[rows[3],rows[1],rows[2],rows[4],rows[0]])
    raises(owners['order_update_driver_owner_operations'],args=[[dict(rows[0],canceled=True)]],message='reduced ordinary')

TEST_SUITE=suite('nt6_update_driver_owners',[
    case('shared_and_literal',test_owner_effects_preserve_shared_leaves_and_literal_hashes),
    case('recreated_security',test_last_owner_recreation_gets_new_object_security),
    case('stale_source',test_stale_owner_source_is_not_overwritten),
    case('execution_preserves_shared_object',test_execution_order_keeps_shared_object_alive),
    case('critical_subpass',test_critical_inf_group_runs_in_second_subpass),
])
