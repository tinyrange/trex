"""Catalog hints preserve aliases and unrelated EAs; stale evidence stops writes."""
load('//tests:testing.star','case','equal','raises','suite')
m=testing.module('@stdlib//windows/servicing:catalog_hints.star')

def _fixture():
    root=directory()
    root.write('/cat','signed proof fixture')
    root.write('/member','member bytes')
    keep=dict(name='USER.DATA',flags=0,value=b'keep')
    root.set_extended_attributes('/member',[keep])
    root.hardlink('/member','/alias')
    plan=dict(path='/member',hash=digest(root.find('/member')),order=root.get_metadata('/member').write_order,eas=[keep],hint=m['_hint']('driver.cat'),catalog='/cat',catalog_hash=digest(root.find('/cat')))
    return root,plan

def test_encoding_and_aliases():
    hint=m['_hint']('ntprint.cat')
    equal(hint['value'],binary.decode('01000b006e747072696e742e636174','hex'))
    for name in ['../a.cat','a/b.cat','a'+chr(92)+'b.cat','a:cat','a.cat'+chr(0),'notcat']:
        raises(m['_hint'],args=[name],message='invalid')
    root,plan=_fixture()
    identity=root.get_metadata('/member').hard_link_id
    equal(m['apply_catalog_hints'](root,[plan]),dict(files=1,objects=1))
    equal(root.get_metadata('/alias').extended_attributes,plan['eas']+[plan['hint']])
    equal(root.get_metadata('/alias').hard_link_id,identity)

def test_preflight():
    for target,message in [('/member','member changed'),('/cat','proof changed')]:
        root,plan=_fixture()
        root.write(target,'changed')
        raises(m['apply_catalog_hints'],args=[root,[plan]],message=message)
        equal(root.get_metadata('/member').extended_attributes,plan['eas'])
    root,plan=_fixture()
    second=dict(plan)
    second['path']='/alias'
    second['hint']=m['_hint']('other.cat')
    second['order']=root.get_metadata('/alias').write_order
    raises(m['apply_catalog_hints'],args=[root,[plan,second]],message='conflicting')
    equal(root.get_metadata('/member').extended_attributes,plan['eas'])

def test_signed_paths():
    attr=dict(oid='1.3.6.1.4.1.311.12.2.1',name_value=True,name='Hint',flags=0x10010001,value=binary.encode('component'+chr(92)+'file.dll'+chr(0),encoding='utf16le'))
    entry=dict(subject=b'x'*32,digest=b'y'*32,attributes=[attr])
    parsed=dict(version=2,entries=[entry])
    equal(m['package_hint_paths'](parsed),[dict(path='/Windows/WinSxS/component/file.dll',digest=b'y'*32)])
    # Native v2 skips short subject IDs even if an attribute looks like Hint.
    equal(m['package_hint_paths'](dict(version=2,entries=[dict(entry,subject=b'x'*20)])),[])
    equal(len(m['package_hint_paths'](dict(version=1,entries=[dict(entry,subject=b'x'*20)]))),1)
    for changed in [dict(attr,flags=1),dict(attr,name='File'),dict(attr,oid='1.2.3.4')]:
        equal(m['package_hint_paths'](dict(version=2,entries=[dict(entry,attributes=[changed])])),[])
    for path in ['../file.dll','/absolute','component/../file.dll','C:/x','component//x','component/'+chr(0)+'x']:
        bad=dict(attr,value=binary.encode(path+chr(0),encoding='utf16le'))
        raises(m['package_hint_paths'],args=[dict(version=2,entries=[dict(entry,attributes=[bad])])],message='unsafe')
    for raw in [b'',b'x',binary.encode('not terminated',encoding='utf16le')]:
        bad=dict(attr,value=raw)
        raises(m['package_hint_paths'],args=[dict(version=2,entries=[dict(entry,attributes=[bad])])],message='terminated')



def test_actual_hint_audit_rejects_unregistered_catalog():
    root, plan = _fixture()
    m['apply_catalog_hints'](root, [plan])
    before = root.get_metadata('/member').extended_attributes
    # A source catalog is not evidence that the lookup target was registered.
    # Both hardlinks are one audited object, not two independent successes.
    raises(m['audit_catalog_hints'], args=[root], message='audit failures (1,')
    equal(root.get_metadata('/member').extended_attributes, before)
    equal(root.get_metadata('/alias').extended_attributes, before)
    root.write('/Windows/System32/CatRoot/group1/driver.cat', 'one catalog')
    root.write('/Windows/System32/CatRoot/group2/DRIVER.CAT', 'another catalog')
    raises(m['audit_catalog_hints'], args=[root], message='ambiguous registered catalog leaf')
    equal(root.get_metadata('/member').extended_attributes, before)


def test_actual_hint_header_validation():
    hint = m['_hint']('driver.cat')
    equal(m['catalog_hint_name'](hint), 'driver.cat')
    for raw in [b'', b'\x01\x00', b'\x02\x00\x00\x00', hint['value'][:-1], binary.concat([hint['value'], b'\x00']).bytes()]:
        raises(m['catalog_hint_name'], args=[dict(hint, value=raw)], message='header')
    raises(m['catalog_hint_name'], args=[dict(hint, flags=1)], message='unsupported')
    root = directory()
    root.write('/plain', 'no hint')
    equal(m['audit_catalog_hints'](root), dict(objects=0, matched=0, catalogs=0, chains=0))

TEST_SUITE=suite('nt6_update_catalog_hints',[case('actual_hint_audit',test_actual_hint_audit_rejects_unregistered_catalog),case('actual_hint_header',test_actual_hint_header_validation),case('encoding_aliases',test_encoding_and_aliases),case('atomic_preflight',test_preflight),case('signed_paths',test_signed_paths)])
