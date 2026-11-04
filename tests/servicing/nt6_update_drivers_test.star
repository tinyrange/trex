"""Declared driver provenance and native empty-queue reduction regressions."""

load("//tests:testing.star", "case", "equal", "raises", "suite")

policy = testing.module("@stdlib//windows/servicing:drivers.star")
reduce_queue = policy["reduce_update_driver_queue"]
plan = policy["plan_update_driver_operations"]

_ID = 'dual_unrelated.inf, Culture=neutral, Type=dualModeDriver, Version=10.0.26100.9711, PublicKeyToken=31bf3856ad364e35, ProcessorArchitecture=amd64, versionScope=nonSxS'
_PACKAGE = 'Example.Versioned~31bf3856ad364e35~amd64~~10.0.26100.9711'
_DIGEST = 'fIBj3Q2vd9yl0lCx54utm7N+po4/VKFH/3YwRagnRpo='
_DEPLOYMENT = '<assemblyIdentity name="dual_unrelated.inf" version="10.0.26100.9711" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" type="dualModeDriver"/>'


def _file(content):
    files = directory()
    files.write('/input', content)
    return files.find('/input')


def _fixture(attributes='inf="Declared.inf" ranking="normal"', update='NEW'):
    staged = '<selectable disposition="staged"><detectNone default="false"/></selectable>'
    def reference():
        return '<driver ' + attributes + '>' + _DEPLOYMENT + '</driver>'
    mum = _file('<assembly xmlns="urn:schemas-microsoft-com:asm.v3"><assemblyIdentity name="Example.Versioned" version="10.0.26100.9711" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral"/><package><update name="' + update + '">' + reference() + '</update><update name="OLD">' + staged + reference() + '</update><update name="STAGE">' + staged + reference() + '</update></package></assembly>')
    index = windows.cbs_update_index([dict(manifest=mum, intended_state=0)])
    def applicable(*unused):
        return 0x70
    def populate(*unused):
        return dict(before_updates=[], deferred=[])
    def initial(unused_package, update_name, unused_target, unused_snapshot):
        return dict(state=0x70 if update_name == 'OLD' else 0, has_deployments=True)
    def empty(*unused):
        return []
    population = index.ordinary_population([dict(package=_PACKAGE, owner=_PACKAGE, state=0x70, integration=2, ceiling=0x1000)], [], applicable, populate, 100, watch=dict(initial_update=initial, dependents=empty, satellites=empty))
    hash = '<h:hash xmlns:h="urn:schemas-microsoft-com:asm.v2" xmlns:d="http://www.w3.org/2000/09/xmldsig#"><d:Transforms><d:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity"/></d:Transforms><d:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><d:DigestValue>' + _DIGEST + '</d:DigestValue></h:hash>'
    # The declared INF is NOT the first INF, first file, or identity's basename.
    xml = '<assembly xmlns="urn:schemas-microsoft-com:asm.v3">' + _DEPLOYMENT + '<file name="Wrong.inf"/><file name="Other.sys"/><file name="declared.INF">' + hash + '</file></assembly>'
    return population, {_ID.lower():_file(xml)}, xml


def test_mum_to_plan_keeps_each_owner_and_the_declared_inf_digest():
    population, manifests, unused_xml = _fixture()
    actions = population.deployment_actions()
    equal([(a.name,a.value) for a in actions[0].driver_attributes], [('inf','Declared.inf'),('ranking','normal')])
    # Inspection mutations may not corrupt a later snapshot projection.
    actions[0].driver_attributes.clear()
    planned = plan(population.deployment_actions(), manifests, [])
    operations = planned['operations']
    equal([(r['kind'],r['inf'],r['hash'],r['owner']) for r in operations], [(0,'Declared.inf',_DIGEST,_PACKAGE+'~NEW'),(1,'Declared.inf',_DIGEST,_PACKAGE+'~OLD')])
    equal([r['owner'] for r in planned['stages']], [_PACKAGE+'~NEW',_PACKAGE+'~STAGE'])
    equal([r['owner'] for r in planned['staged_only']], [_PACKAGE+'~STAGE'])
    equal((planned['duplicates'],planned['canceled']), (0,0))
    equal([r['sequence'] for r in operations], [1,2])
    # Slash is an actual ownership-key component, never a display-path split.
    equal('/' in operations[0]['hash'], True)


def test_native_queue_controls_preserve_sequence_case_and_package_owner():
    row = dict(identity='Deployment',owner=_PACKAGE+'~NEW',inf='shared.inf',hash=_DIGEST)
    added = dict(row,kind=0)
    removed = dict(row,kind=1)
    other = dict(added,owner=_PACKAGE+'~OTHER')
    case_variant = dict(added,identity='deployment')
    inputs = [added, dict(added), other, removed, added, case_variant]
    result = reduce_queue(inputs, [])
    equal(result['duplicates'],1)
    equal(result['canceled'],1)
    equal([(r['sequence'],r['owner'],r['identity']) for r in result['operations']], [(2,_PACKAGE+'~OTHER','Deployment'),(3,_PACKAGE+'~NEW','Deployment'),(4,_PACKAGE+'~NEW','deployment')])
    equal([r['canceled'] for r in result['entries']], [True,False,False,False])
    equal(inputs[0], added)
    equal('canceled' in added,False)
    raises(reduce_queue,args=[[added,dict(added,hash='different')],[]],message='conflicting duplicate')
    raises(reduce_queue,args=[[added], [added]],message='load/recovery')
    raises(reduce_queue,args=[[dict(added,state=1)],[]],message='persisted execution state')
    raises(reduce_queue,args=[[dict(added,kind=2)],[]],message='unsupported ordinary')
    raises(reduce_queue,args=[[added],None],message='inventory list')


def test_unestablished_source_metadata_fails_before_effects():
    for attributes, message in [
        ('ranking="normal"','explicit INF'),
        ('inf="Declared.inf"','ranking'),
        ('inf="../Declared.inf" ranking="normal"','explicit INF'),
        ('inf="Declared.inf" ranking="future"','ranking'),
        ('inf="Declared.inf" ranking="normal" bootCritical="true"','policy'),
        ('xmlns:x="urn:opaque" x:inf="Declared.inf" ranking="normal"','policy'),
    ]:
        population, manifests, unused_xml = _fixture(attributes)
        raises(plan,args=[population.deployment_actions(),manifests,[]],message=message)
    population, manifests, xml = _fixture()
    for changed, message in [
        (xml.replace('name="dual_unrelated.inf"','name="Foreign"'), 'exact action identity'),
        (xml.replace('name="declared.INF"','name="missing.inf"'), 'unique declared INF'),
        (xml.replace('<file name="Wrong.inf"/>','<file name="Declared.inf"/>'), 'unique declared INF'),
        (xml.replace('HashTransforms.Identity','HashTransforms.PEImage'), 'algorithm or transform'),
        (xml.replace(_DIGEST,' '+_DIGEST), 'whitespace'),
    ]:
        raises(plan,args=[population.deployment_actions(),{_ID.lower():_file(changed)},[]],message=message)
    raises(plan,args=[population.deployment_actions(),{},[]],message='missing exact')
    population, manifests, unused_xml = _fixture(update='Contains.Dot')
    raises(plan,args=[population.deployment_actions(),manifests,[]],message='exact driver package/update owner')


def _catalog_der(tag,payload):
    payload=binary.view(payload)
    header=binary.builder()
    header.u8(tag)
    if len(payload)<128:
        header.u8(len(payload))
    elif len(payload)<256:
        header.u8(0x81)
        header.u8(len(payload))
    else:
        header.u8(0x82)
        header.u16be(len(payload))
    return binary.concat([header.bytes(),payload]).bytes()


def _catalog_fixture():
    # Real ntprint.cat catalog-level OSAttr extension, not a member attribute.
    extension=binary.decode('307b060a2b0601040182370c0201046d306b1e0c004f005300410074007400720203010001045632003a0035002e0031002c0032003a0035002e0032002c0032003a0036002e0030002c0032003a0036002e0031002c0032003a0036002e0032002c0032003a0036002e0033002c0032003a00310030002e0030000000',encoding='hex')
    ctl=_catalog_der(0x30,binary.concat([b'\x30\x00',_catalog_der(23,b'261010111300Z'),binary.decode('300c060a2b0601040182370c0103',encoding='hex'),b'\x30\x00',_catalog_der(0xa0,_catalog_der(0x30,extension))]))
    content=_catalog_der(0x30,binary.concat([binary.decode('06092b0601040182370a01',encoding='hex'),_catalog_der(0xa0,ctl)]))
    signed=_catalog_der(0x30,binary.concat([b'\x02\x01\x01\x31\x00',content,b'\x31\x00']))
    return _catalog_der(0x30,binary.concat([binary.decode('06092a864886f70d010702',encoding='hex'),_catalog_der(0xa0,signed)]))


def test_catalog_metadata_uses_actual_source_and_owned_buffers():
    models=testing.module('@stdlib//windows/servicing:driver_catalogs.star')
    win32=testing.module('@stdlib//windows/selfreg:win32.star')
    crypto_module=testing.module('@stdlib//windows/selfreg:crypto.star')
    raw=_catalog_fixture()
    attrs=windows.catalog_attributes(raw)
    expected='2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0'
    equal(len(attrs),1)
    equal((attrs[0]['name'],attrs[0]['flags'],attrs[0]['value']),('OSAttr',0x10001,binary.encode(expected,encoding='utf16le',nul=True)))
    physical='D:'+chr(92)+'Windows'+chr(92)+'WinSxS'+chr(92)+'Fixture'+chr(92)+'real.cat'
    for arch in ['x86','amd64']:
        machine=emulator.machine(code=b'\xc3',architecture=arch)
        kernel=win32['kernel32_plugin'](files={physical:_file(raw)})
        cryptoapi=crypto_module['cryptoapi_plugin'](kernel=kernel)
        cats=models['update_driver_catalogs'](kernel,cryptoapi)
        machine.use([kernel,cryptoapi,cats])
        output=machine.allocate(size=8)
        equal(machine.call(machine.resolve_export('advapi32.dll',name='CryptAcquireContextW'),args=[output,0,0,1,0xf0000000]).value,1)
        provider=machine.read_pointer(output)
        path=machine.allocate(value=binary.encode(physical,encoding='utf16le',nul=True))
        opened=machine.resolve_export('wintrust.dll',name='CryptCATOpen')
        enumerated=machine.resolve_export('wintrust.dll',name='CryptCATEnumerateCatAttr')
        close=machine.resolve_export('wintrust.dll',name='CryptCATClose')
        invalid=0xffffffffffffffff if arch=='amd64' else 0xffffffff
        equal(machine.call(opened,args=[path,0,123,0,0]).value,invalid)
        equal(cats.state['catalogs'],{})
        equal(machine.call(opened,args=[path,1,provider,0,0]).reason,'plugin')
        equal(cats.state['catalogs'],{})
        result=machine.call(opened,args=[path,0,provider,0,0])
        equal(result.reason,'return',result.detail)
        handle=result.value
        equal(handle!=invalid,True)
        first=machine.call(enumerated,args=[handle,0]).value
        equal(first!=0,True)
        # This independent native layout is also read by drvstore c2a1a.
        equal(machine.read_u32le(first),40 if arch=='amd64' else 24)
        equal(machine.read_cstring(machine.read_pointer(first+(8 if arch=='amd64' else 4)),encoding='utf16le'),'OSAttr')
        equal(machine.read_u32le(first+(16 if arch=='amd64' else 8)),0x10001)
        equal(machine.read_u32le(first+(20 if arch=='amd64' else 12)),86)
        data=machine.read_pointer(first+(24 if arch=='amd64' else 16))
        equal(machine.read(data,86),attrs[0]['value'])
        equal(machine.read_u32le(first+(32 if arch=='amd64' else 20)),0)
        equal(machine.call(enumerated,args=[handle,first]).value,0)
        equal(machine.call(enumerated,args=[handle,123]).value,0)
        equal(kernel.state['last_error'],87)
        equal(machine.call(enumerated,args=[handle,0]).value,first)
        verify=machine.resolve_export('wintrust.dll',name='WinVerifyTrust')
        stopped=machine.call(verify,args=[0,0,0])
        equal(stopped.reason,'plugin')
        equal('unmodeled driver catalog API' in stopped.detail,True)
        equal(stopped.eip,verify)
        equal(machine.call(close,args=[handle]).value,1)
        equal(machine.call(close,args=[handle]).value,0)
        equal(machine.call(enumerated,args=[handle,first]).value,0)
        equal(cats.state['catalogs'],{})
        equal(machine.call(machine.resolve_export('advapi32.dll',name='CryptReleaseContext'),args=[provider,0]).value,1)
        equal(cryptoapi.state['providers'],{})
        equal(kernel.state['file_data'](kernel.state['paths'][physical.lower()]),raw)


def test_driver_source_projection_keeps_exact_component_descendants():
    root=directory()
    first='/Windows/WinSxS/amd64_Exact_Identity'
    second='/Windows/WinSxS/x86_Other_Identity'
    wanted=[first+'/driver.inf',first+'/Amd64/UNIRES.DLL',first+'/Nested/Deep/Payload.bin',second+'/driver.inf']
    for path in wanted+[first+'-foreign/UNIRES.DLL','/Windows/WinSxS/Manifests/amd64_Exact_Identity.manifest']:
        root.write(path,'actual')
    select=policy['select_update_driver_source_paths']
    selected=select(root,[first.lower()+'/',second])
    equal(sorted(selected),sorted(wanted))
    for invalid in [first+'/Nested','/Windows/WinSxS/..','/Windows/WinSxS',first.replace('/','\\')]:
        raises(select,args=[root,[invalid]],message='exact WinSxS')
    raises(select,args=[root,[first,first+'-missing']],message='is absent')


def test_driver_ea_owns_access_and_persists_shared_metadata():
    abi = testing.module('@stdlib//windows/emulation:abi.star')
    win32 = testing.module('@stdlib//windows/selfreg:win32.star')
    policy = testing.module('@stdlib//windows/servicing:driver_eas.star')
    raw = b'\x00\x00\x00\x00\x00\x0f\x0f\x00$CI.CatalogHint\x00\x01\x00\x0b\x00ntprint.cat'
    hint = dict(name='$CI.CatalogHint',flags=0,value=b'\x01\x00\x0b\x00ntprint.cat')
    path = 'D:'+chr(92)+'Windows'+chr(92)+'System32'+chr(92)+'DriverStore'+chr(92)+'FileRepository'+chr(92)+'ntprint.inf_amd64_fixture'+chr(92)+'Amd64'+chr(92)+'UNIRES.DLL'
    for arch in ['x86','amd64']:
        m = emulator.machine(code=b'\xc3',architecture=arch)
        ea = dict(name='Existing',flags=0x80,value=b'keep')
        entries = win32['virtual_file_entries']({path:_file('actual DLL bytes')})
        entries[path.lower()].update(extended_attributes=[ea])
        kernel = win32['kernel32_plugin'](prepared_file_entries=entries)
        plugin = policy['update_driver_eas'](kernel)
        m.use([kernel,plugin])
        width = m.pointer_size
        layout = abi['object_attributes_layout'](width)
        string = abi['counted_string_layout'](width)
        obj = m.allocate(size=layout['Size'])
        desc = m.allocate(size=string['Size'])
        encoded = binary.encode(chr(92)+'??'+chr(92)+path,encoding='utf16le')
        m.write_u32le(obj,layout['Size'])
        m.write_pointer(obj+layout['ObjectName'],desc)
        m.write_u16le(desc,len(encoded))
        m.write_u16le(desc+2,len(encoded))
        m.write_pointer(desc+string['Buffer'],m.allocate(value=encoded))
        out = m.allocate(value=b'Z'*(width+8))
        status = m.allocate(value=b'Y'*(2*width+8))
        buf = m.allocate(value=binary.concat([raw,b'GUARDEND']).bytes())
        def call(name,args):
            r = m.call(m.resolve_export('ntdll.dll',name=name),args=args)
            equal(r.reason,'return',r.detail)
            return r.value
        for api in ['NtOpenFile','NtCreateFile']:
            for access in [0x100001,0x100010]:
                args = [out,access,obj,status,7,0x4060] if api=='NtOpenFile' else [out,access,obj,status,0,0x80,7,1,0x4060,0,0]
                equal(call(api,args),0)
                handle = m.read_pointer(out)
                equal(kernel.state['handles'][handle]['value']['desired_access'],access)
                m.write(status,b'Y'*(2*width+8))
                expected = 0 if access & 0x10 else 0xc0000022
                equal(call('NtSetEaFile',[handle,status,buf,len(raw)]),expected)
                equal(m.read_u32le(status),expected)
                if width == 8:
                    equal(m.read(status+4,4),b'Y'*4)
                equal(m.read_pointer(status+width),0)
                equal(m.read(status+2*width,8),b'Y'*8)
                equal(m.read(buf,len(raw)+8),binary.concat([raw,b'GUARDEND']).bytes())
                if expected==0:
                    equal(kernel.state['paths'][path.lower()]['extended_attributes'],[ea,hint])
                    # Invalid chaining cannot change previously committed metadata.
                    m.write_u32le(buf,4)
                    equal(call('NtSetEaFile',[handle,status,buf,len(raw)]),0x80000014)
                    equal(kernel.state['paths'][path.lower()]['extended_attributes'],[ea,hint])
                    m.write_u32le(buf,0)
                equal(m.call(m.resolve_export('kernel32.dll',name='CloseHandle'),args=[handle]).value,1)
                equal(call('NtSetEaFile',[handle,status,buf,len(raw)]),0xc0000008)
        equal(entries[path.lower()]['extended_attributes'],[ea])
        initial = windows.clone_file_entries(kernel.state['paths'])
        kernel.state['paths'][path.lower()]['extended_attributes'][0]['value']=b'changed'
        equal(initial[path.lower()]['extended_attributes'],[ea,hint])
        kernel.state['paths'][path.lower()]['writable']=False
        equal(call('NtOpenFile',[out,0x100010,obj,status,7,0x4060]),0xc0000022)
        equal(m.read(out+width,8),b'Z'*8)


TEST_SUITE = suite('private/nt6_update_drivers', [
    case('catalog_hint_ea',test_driver_ea_owns_access_and_persists_shared_metadata),
    case('source_descendants', test_driver_source_projection_keeps_exact_component_descendants),
    case('catalog_metadata', test_catalog_metadata_uses_actual_source_and_owned_buffers),
    case('declared_metadata',test_mum_to_plan_keeps_each_owner_and_the_declared_inf_digest),
    case('native_queue_rules',test_native_queue_controls_preserve_sequence_case_and_package_owner),
    case('unsupported_inputs',test_unestablished_source_metadata_fails_before_effects),
])
