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


def test_explicit_non_audit_preserves_guards():
    root, plan = _fixture()
    plan['hash'] = None
    # Missing proof must not accidentally count as an audit success.
    raises(m['apply_catalog_hints'], args=[root,[plan]], message='member changed')
    equal(m['apply_catalog_hints'](root,[plan],audit=False),dict(files=1,objects=1))
    equal(root.get_metadata('/alias').extended_attributes,plan['eas']+[plan['hint']])
    for target,message in [('/member','member changed'),('/cat','proof changed')]:
        root,plan=_fixture()
        plan['hash']=None
        root.write(target,'changed')
        raises(m['apply_catalog_hints'],args=[root,[plan]],kwargs=dict(audit=False),message=message)
        equal(root.get_metadata('/member').extended_attributes,plan['eas'])

def _der(tag, content):
    size=len(content)
    length=binary.u8(size) if size<128 else binary.concat([b'\x81',binary.u8(size)]) if size<256 else binary.concat([b'\x82',binary.u16be(size)])
    return binary.concat([binary.u8(tag),length,content]).bytes()

def _unsigned_catalog(member_digest, hint='component/file.dll', attribute_name='Hint'):
    # Real CTL member encoding, deliberately no signer: membership is not trust.
    nv=_der(0x30,binary.concat([_der(30,binary.encode(attribute_name,encoding='utf16be')),b'\x02\x03\x01\x00\x01',_der(4,binary.encode(hint+chr(0),encoding='utf16le'))]).bytes())
    attr=_der(0x30,binary.concat([binary.decode('060a2b0601040182370c0201','hex'),_der(0x31,nv)]).bytes())
    entry=_der(0x30,binary.concat([_der(4,member_digest),_der(0x31,attr)]).bytes())
    ctl=_der(0x30,binary.concat([_der(0x30,b''),_der(23,b'261022000000Z'),_der(0x30,binary.decode('060a2b0601040182370c0103','hex')),_der(0x30,entry)]).bytes())
    content=_der(0x30,binary.concat([binary.decode('06092b0601040182370a01','hex'),_der(0xa0,ctl)]).bytes())
    signed=_der(0x30,binary.concat([b'\x02\x01\x01',_der(0x31,b''),content,_der(0x31,b'')]).bytes())
    return _der(0x30,binary.concat([binary.decode('06092a864886f70d010702','hex'),_der(0xa0,signed)]).bytes())

def test_catalog_audit_is_explicit_not_fabricated_trust():
    root=directory()
    cat=_unsigned_catalog(digest('manifest'))
    root.write('/Windows/servicing/Packages/fixture.cat',cat)
    root.write('/Windows/servicing/Packages/fixture.mum','manifest')
    root.write('/Windows/WinSxS/component/file.dll','member')
    hints=m['plan_package_catalog_hints'](root,['fixture'],audit=False)
    equal(hints['signature_audit'],'not-performed')
    equal(hints['payload_audit'],'not-performed')
    equal(len(hints['plans']),1)
    equal(hints['plans'][0]['path'],'/Windows/WinSxS/component/file.dll')
    m['apply_catalog_hints'](root,hints['plans'],audit=False)
    equal(root.get_metadata('/Windows/WinSxS/component/file.dll').extended_attributes,[m['_hint']('fixture.cat')])
    raises(windows.catalog_signature,args=[cat])
    raises(m['plan_package_catalog_hints'],args=[root,['fixture']])
    root.write('/Windows/servicing/Packages/fixture.cat','malformed')
    raises(m['plan_package_catalog_hints'],args=[root,['fixture']],kwargs=dict(audit=False))

def test_catalog_named_projection():
    for name in ['Hint', 'hINT', 'Other']:
        encoded=_unsigned_catalog(b'x'*32,attribute_name=name)
        full=windows.catalog_entries(encoded)
        equal(windows.catalog_entries(encoded,name_value=None),full)
        selected=windows.catalog_entries(encoded,name_value='hint')
        equal(selected,full if name.lower()=='hint' else dict(version=2,entries=[]))
        equal(m['package_hint_paths'](selected),m['package_hint_paths'](full))
        # Returned projections do not share mutable result lists.
        selected['entries'].append('changed')
        equal(windows.catalog_entries(encoded),full)
    # Filtering does not excuse malformed metadata that would be omitted.
    raises(windows.catalog_entries,args=[_unsigned_catalog(b'x'*32,attribute_name=chr(0))],kwargs=dict(name_value='Hint'))
    raises(windows.catalog_entries,args=[_unsigned_catalog(b'x')],kwargs=dict(name_value='Absent'))
    for value in ['', 7, []]:
        raises(windows.catalog_entries,args=[_unsigned_catalog(b'x'*32)],kwargs=dict(name_value=value))

TEST_SUITE=suite('nt6_update_catalog_hints',[case('named_projection',test_catalog_named_projection),case('catalog_audit_separation',test_catalog_audit_is_explicit_not_fabricated_trust),case('explicit_non_audit_guards',test_explicit_non_audit_preserves_guards),case('actual_hint_audit',test_actual_hint_audit_rejects_unregistered_catalog),case('actual_hint_header',test_actual_hint_header_validation),case('encoding_aliases',test_encoding_and_aliases),case('atomic_preflight',test_preflight),case('signed_paths',test_signed_paths)])
