"""Pinned native driver transaction for the offline update construction.

One retained session owns all three phases and Close. Instruction-limit stops
resume the same call, never recreate a phase. publish() returns an independently
verified filesystem tree, not a CBS completion flag. Payloads must already be
staged; do not replay staging after publishing native file objects.
"""

load('@stdlib//windows/servicing:driver_cleanup.star','retire_update_driver_process')
load('@stdlib//windows/servicing:driver_inputs.star','build_update_driver_input_entries')
load('@stdlib//windows/selfreg:registry.star','registry_plugin')
load('@stdlib//windows/emulation:runner.star',native_driver_run='run')
load('@stdlib//windows/servicing:driver_hives.star','update_driver_hive_mounts')
load('@stdlib//windows/servicing:registry_effects.star','update_driver_key_creation_provider')
load('@stdlib//windows/servicing:registry_access.star','update_driver_key_open_access')
load('@stdlib//windows/servicing:driver_catalogs.star','update_driver_catalogs')
load('@stdlib//windows/servicing:driver_eas.star','update_driver_eas')
load('@stdlib//windows/servicing:driver_random.star','update_driver_native_random')
load('@stdlib//windows/selfreg:win32.star','virtual_file_entries')
load('@stdlib//windows/servicing:drivers.star','plan_update_driver_operations','select_update_driver_source_paths')
load('@stdlib//windows/servicing:file_commit.star','image_path_names')
load('@stdlib//windows/servicing:driver_files.star','prepare_update_driver_transaction','collect_update_driver_entries')
load('@stdlib//windows/servicing:driver_destinations.star','qualify_update_driver_destinations','prepare_update_driver_destination_authority')

def prepare_update_driver_session(root, payloads, population, analysis, version):
    """Prepare start/advance/finish/publish callbacks for the exact qualified native driver ABI. The current SSU and DLL identity guards are intentional support limits, not a general Windows driver transaction."""
    # Internal log-token RVA and update-record ABI are established only for
    # this exact serviced pair. Never apply them to a merely similar DLL.
    stack=payloads['stages']['ServicingStackUpdate_KB5127647']
    for index,key in [(64,'15BAE6440621EC17F0665C0DBF9F40C61'),(65,'DE6143940C27BA1F0AF204E47261BED81')]:
        pe=windows.pe(stack.open(index))
        if pe.info['machine']!=0x8664 or pe.codeview==None or pe.codeview['key']!=key:
            fail('native driver transaction requires the exact serviced PE pair')
    current=windows.hive(root.find('/Windows/System32/config/SOFTWARE')).find('/Microsoft/Windows NT/CurrentVersion').values
    if version['major']!=current['CurrentMajorVersionNumber'] or version['minor']!=current['CurrentMinorVersionNumber'] or version['build']!=int(current['CurrentBuildNumber']) or version['revision']!=current['UBR']:
        fail('native driver OS version disagrees with the target hive')
    baseline = dict(root=root)

    driver_components=windows.hive(baseline['root'].find('/Windows/System32/config/COMPONENTS')); driver_manifest_map=dict(analysis['resident_manifests']); driver_manifest_map.update(analysis['manifests']); driver_plan=plan_update_driver_operations(population.deployment_actions(changed_only=True),driver_manifest_map,[]); driver_names=image_path_names(baseline['root']); print('FRESH_DRIVER_PLAN',len(driver_plan['operations']),len(driver_plan['stages']))

    def cbs_owner_batch_expected():
        groups={}
        names={}
        for arch in driver_components.find('/Drivers').children:
            for inf in arch.children:
                for leaf in inf.children:
                    key=(arch.name.lower(),inf.name.lower(),leaf.name.lower())
                    if key in groups: fail('duplicate physical driver owner key')
                    values={}
                    for name,record in leaf.value_records.items():
                        if record.type!=4 or len(record.raw)!=4: fail('driver baseline has an unmodeled owner value')
                        values[name.lower()]=(name,record.raw)
                    if not values: fail('driver baseline contains an unmodeled empty owner leaf')
                    groups[key]=values
                    names[key]=(arch.name,inf.name,leaf.name)
        expected={key:dict(values) for key,values in groups.items()}
        outputs=[]
        first=[]
        last=[]
        for row in driver_plan['operations']:
            key=(row['architecture'].lower(),row['inf'].lower(),row['hash'].lower())
            values=expected.get(key)
            owner=row['owner'].lower()
            present=values!=None and owner in values
            if row['kind']==0:
                result=(1 if present else 0,1 if values==None else 0)
                if values==None:
                    expected[key]={}
                    values=expected[key]
                    first.append(row)
                    names[key]=(row['architecture'],row['inf'],row['hash'])
                if not present: values[owner]=(row['owner'],binary.u32le(0))
            else:
                if present: values.pop(owner)
                result=(1 if present else 0,1 if values else 0)
                if values!=None and not values:
                    expected.pop(key)
                    last.append(row)
            outputs.append(result)
        print('EXPECTED_NATIVE_OWNER_BATCH',len(outputs),len(first),len(last),len(expected))
        return dict(initial=groups,expected=expected,names=names,outputs=outputs,first=first,last=last)

    cbs_owner_expected=cbs_owner_batch_expected()

    def cbs_driver_batch_sources():
        names=image_path_names(baseline['root'])
        stems={str(k.values['identity']).lower():k.name for k in driver_components.find('/DerivedData/Components').children}
        for stage in payloads['stages'].values():
            for component in stage.components:
                key=str(component.identity).lower()
                if key in stems and stems[key].lower()!=component.stem.lower(): fail('driver source identity has conflicting stems')
                stems[key]=component.stem
        result=[]
        prefixes={}
        for operation,rows in [('install',cbs_owner_expected['first']),('uninstall',cbs_owner_expected['last'])]:
            for row in rows:
                stem=stems.get(row['identity'].lower())
                if stem==None: fail('driver job has no exact staged/resident source stem')
                prefix='/Windows/WinSxS/'+stem+'/'
                path=names.get((prefix+row['inf']).lower())
                if path==None: fail('driver job has no actual INF source path')
                file=baseline['root'].find(path)
                if digest(file,algorithm='sha256')!=binary.decode(row['hash'],'base64'):
                    fail('driver job source content disagrees with the exact manifest INF hash: '+path)
                result.append(dict(row,operation=operation,path=path))
                prefixes[prefix.lower()]=True
        print('EXACT_NATIVE_DRIVER_JOBS',len(result),len(prefixes),[(r['operation'],r['inf'],r['path']) for r in result[:3]])
        return dict(jobs=result,prefixes=prefixes)

    driver_batch_sources=cbs_driver_batch_sources()

    driver_source_bindings={('D:/Windows/System32/config/'+n).replace('/',chr(92)).lower():dict(target=n,path='/Windows/System32/config/'+n) for n in ['SYSTEM','SOFTWARE','DRIVERS']}

    def make_driver_batch_hive_root():
        root=directory()
        for name in ['SYSTEM','SOFTWARE','DRIVERS']:
            path='/Windows/System32/config/'+name
            root.write(path,baseline['root'].find(path))
        return root

    # Declare the private host mount container separately from every mounted
    # target hive. Only SYSTEM administers this in-memory namespace. Its ACL
    # cannot authorize opens within a mounted hive or become an image effect.
    host_namespace=windows.hive(windows.hive_from_patches('SYSTEM',[],keys=[dict(key='/',security=windows.compile_sddl('O:SYG:SYD:P(A;;KA;;;SY)'))]))
    driver_batch_hive_root=make_driver_batch_hive_root(); driver_registry_ref={}; driver_cbs_registry=registry_plugin(on_create_key=update_driver_key_creation_provider(driver_registry_ref,'S-1-5-18','S-1-5-18',0x3000),on_open_key=update_driver_key_open_access); driver_registry_ref['registry']=driver_cbs_registry; driver_cbs_mount=update_driver_hive_mounts(driver_cbs_registry,driver_batch_hive_root,driver_source_bindings,host_namespace=host_namespace); driver_cbs_registry.state['sources']['SOFTWARE']=driver_cbs_mount; driver_session={'registry':driver_cbs_registry,'mount':driver_cbs_mount}; print('FRESH_BATCH_HIVES',len(driver_batch_hive_root.files))

    driver_input_entries=build_update_driver_input_entries(root,driver_batch_sources['jobs']); driver_initial_entries=windows.clone_file_entries(driver_input_entries); driver_native_ntdll=windows.pe(baseline['root'].find(driver_names['/windows/system32/ntdll.dll']))

    def driver_loader_probe():
        def callback(event):
            m=event.machine
            if event.name.lower()=='ldrgetdllhandle':
                d=event.args[2]
                text=binary.text(m.read(m.read_pointer(d+8),m.read_u16le(d)),encoding='utf16le')
                if text.lower()!='ntdll.dll': fail('unexpected loader module '+text)
                m.write_pointer(event.args[3],0x12340000)
                return 0
            d=event.args[1]
            text=binary.text(m.read(m.read_pointer(d+8),m.read_u16le(d)),encoding='ascii')
            address=m.resolve_export('ntdll.dll',name=text)
            if not address:
                print('OPTIONAL_NTDLL_SYMBOL_ABSENT',text)
                m.write_pointer(event.args[3],0)
                return 0xc000007a
            m.write_pointer(event.args[3],address)
            return 0
        def install(m):
            for imported in m.imports_named(['LdrGetDllHandle','LdrGetProcedureAddress']):
                m.hook(callback,address=imported.address,argc=4)
        return emulator.plugin(install,name='probe.ntdll-resolution-fixture')

    def driver_log_fixture():
        def callback(event): return 1
        def install(m): m.provide_export(callback,module='driver-probe.dll',name='GetLogToken',argc=0)
        return emulator.plugin(install,name='probe.disabled-log-token')

    def driver_bind_fixture_kernel(fixture):
        def factory(context):
            fixture.state['kernel']=context['kernel']
            def install(m): pass
            return emulator.plugin(install,name='probe.explicit-handle-authority')
        return factory

    def driver_cbs_open_execute(m):
        setter=m.resolve_export('drvstore.dll',name='DriverStoreSetLogContext')
        log=m.resolve_export('driver-probe.dll',name='GetLogToken')
        setup=m.call(setter,args=[log])
        if setup.reason!='return' or setup.value!=1: fail('native driver log setup failed')
        log_token=m.call(m.modules[0].base+0x10410,args=[1])
        if log_token.reason!='return': return log_token
        path=m.allocate(value=binary.encode('D:/Windows'.replace('/',chr(92)),encoding='utf16le',nul=True))
        result=m.call_export('DriverUpdateOpenContext',args=[path,0])
        print('NATIVE_DRIVER_UPDATE_OPEN',result.reason,result.detail,hex(result.value))
        if result.reason=='return' and result.value:
            print('NATIVE_DRIVER_UPDATE_OFFLINE',m.read_u32le(result.value+0x410))
        return result

    def driver_unload_fixture():
        def callback(event):
            m=event.machine
            name=m.allocate(value=binary.encode('ntdll.dll',encoding='utf16le',nul=True))
            handle=m.invoke(m.resolve_export('kernel32.dll',name='GetModuleHandleW'),args=[name])
            if handle.reason!='return' or handle.value!=event.args[0]: fail('unexpected pinned-module release')
            return 0
        def install(m):
            for i in m.imports_named(['LdrUnloadDll']): m.hook(callback,address=i.address,argc=1)
        return emulator.plugin(install,name='probe.pinned-ntdll-release')

    def driver_catalog_factory(context):
        catalog=update_driver_catalogs(context['kernel'],context['cryptoapi'])
        driver_session['catalogs']=catalog
        driver_session['cryptoapi']=context['cryptoapi']
        driver_session['bcrypt']=context['bcrypt']
        eas=update_driver_eas(context['kernel'])
        driver_session['eas']=eas
        random=update_driver_native_random(driver_native_ntdll,process_cookie=0x6ec81234)
        driver_session['random']=random
        def install(m): m.use([catalog,eas,random])
        return emulator.plugin(install,name='windows.update.driver-native-files',state={'catalog':catalog,'eas':eas,'random':random})

    def driver_prepare_target_namespace():
        file=baseline['root'].find(driver_names['/windows/system32/apisetschema.dll'])
        pe=windows.pe(file)
        sections=[s for s in pe.sections if s['name']=='.apiset']
        if len(sections)!=1: fail('target API-set section is not unique')
        section=sections[0]
        namespace=windows.api_set_namespace(file.slice(section['raw_offset'],section['raw_size']))
        print('ACTUAL_TARGET_API_NAMESPACE',namespace.version,len(namespace.entries),namespace.hash_factor)
        return namespace

    def driver_declared_delay_dependencies(m,module,pe):
        header=pe.data.slice(0,min(4096,pe.data.size)).bytes()
        if len(header)<64: fail('truncated DOS header')
        nt=binary.read_u32le(header[60:64])
        if nt>len(header)-24: fail('unbounded NT header')
        optional=nt+24
        optional_size=binary.read_u16le(header[nt+20:nt+22])
        if optional_size>len(header)-optional or optional_size<112+14*8 or binary.read_u16le(header[optional:optional+2])!=0x20b: fail('unbounded AMD64 directory header')
        if binary.read_u32le(header[optional+108:optional+112])<14: return []
        entry=optional+112+13*8
        rva=binary.read_u32le(header[entry:entry+4])
        size=binary.read_u32le(header[entry+4:entry+8])
        if not size: return []
        image_size=pe.info['image_size']
        if size%32 or size>32*128 or rva>image_size or size>image_size-rva: fail('unbounded delay descriptor table')
        result=[]
        def text(rva):
            if rva>=image_size: fail('delay string outside image')
            out=b''
            builder=binary.builder(capacity=260)
            for offset in range(min(260,image_size-rva)):
                byte=m.read_u8(module.base+rva+offset)
                if not byte: return binary.text(builder.bytes(),encoding='ascii')
                if byte<32 or byte>126: fail('non-ASCII delay import')
                builder.u8(byte)
            fail('unbounded delay import string')
        for offset in range(0,size,32):
            descriptor=m.read(module.base+rva+offset,32)
            if descriptor==b'\x00'*32: return result
            if binary.read_u32le(descriptor[:4])!=1: fail('non-RVA delay imports not admitted')
            dll=text(binary.read_u32le(descriptor[4:8]))
            table=binary.read_u32le(descriptor[16:20])
            if not table or table>image_size-8: fail('invalid delay import name table')
            funcs=[]
            terminated=False
            for index in range(min(1024,(image_size-table)//8)):
                value=m.read_u64le(module.base+table+8*index)
                if not value:
                    terminated=True
                    break
                funcs.append('#'+str(value&0xffff) if value>>63 else text(value+2))
            if not terminated: fail('unbounded delay name table')
            result.append((dll,funcs))
        fail('unterminated delay descriptor table')

    driver_api_namespace=driver_prepare_target_namespace()

    def driver_prepare_loader_requirements():
        source=payloads['stages']['ServicingStackUpdate_KB5127647'].open(65)
        pe=windows.pe(source)
        probe=emulator.machine(image=source,image_name='drvstore.dll',instruction_limit=1000,memory_limit=16<<20)
        declared=driver_declared_delay_dependencies(probe,probe.modules[0],pe)
        modules={}
        exports={}
        hosts={}
        for dll,procedures in declared:
            dll=dll.lower()
            host=driver_api_namespace.resolve(dll,importer='drvstore.dll') if dll.startswith('api-') or dll.startswith('ext-') else dll
            if host==None: fail('target namespace has no declared native delay contract: '+dll)
            path=driver_names.get('/windows/system32/'+host)
            if path==None: fail('actual target lacks declared host DLL: '+host)
            physical=windows.pe(baseline['root'].find(path))
            names={row.get('name','').lower():True for row in physical.exports}
            for procedure in procedures:
                if procedure.lower() not in names: fail('actual host does not export the declared procedure: '+host+'!'+procedure)
                exports[(host,procedure.lower())]=True
            modules[dll]=True
            hosts[host]=True
        print('ACTUAL_DECLARED_LOADER_CLOSURE',len(declared),len(hosts),len(exports),sorted(hosts))
        return dict(modules=modules,hosts=hosts,exports=exports)

    driver_loader_requirements=driver_prepare_loader_requirements()

    driver_virtual_modules=['driver-probe.dll']+sorted(driver_loader_requirements['hosts'])

    def driver_loader_capability_observer(m,query):
        if query['found']: return
        if query['kind']=='module':
            requested=query['module'].lower()
            resolved=query.get('resolved_module',requested)
            if requested in driver_loader_requirements['modules'] or resolved in driver_loader_requirements['hosts']:
                fail('required native loader module has no admitted implementation: '+requested)
        elif query['kind']=='procedure':
            key=(query['module'].lower(),query['procedure'].lower())
            if key in driver_loader_requirements['exports']:
                fail('required declared native export needs an implementation before returning to delay loader: '+query['module']+'!'+query['procedure'])

    def prepare_arrays(m):
        session=driver_session
        arrays={}
        for phase in ['install','uninstall']:
            jobs=[r for r in driver_batch_sources['jobs'] if r['operation']==phase]
            if len(jobs)!=132 or any([j['ranking']!='normal' for j in jobs]): fail('unestablished native driver batch policy')
            array=m.allocate(size=0x220*len(jobs)+8)
            for index,job in enumerate(jobs):
                record=array+index*0x220
                encoded=binary.encode(('D:'+job['path']).replace('/',chr(92)),encoding='utf16le',nul=True)
                if len(encoded)>0x208: fail('driver source exceeds native update path capacity')
                m.write(record,encoded)
                m.write_u16le(record+0x208,{'amd64':9,'x86':0}[job['architecture']])
                m.write_pointer(record+0x210,0)
                m.write_u32le(record+0x218,1)
            m.write(array+0x220*len(jobs),b'GUARDEND')
            arrays[phase]=dict(address=array,count=len(jobs),jobs=jobs)
        session['arrays']=arrays

    driver_session.update(started=False, phase='open', completed=[])
    def accept(result):
        session=driver_session
        session['result']=result
        phase=session['phase']
        if result.reason=='instruction-limit': return result
        if result.reason!='return': fail('native driver '+phase+' stopped: '+result.reason+' '+result.detail)
        expected=1 if phase=='close' else 0
        if (phase=='open' and not result.value) or (phase!='open' and result.value!=expected):
            fail('native driver '+phase+' failed: '+hex(result.value))
        if phase=='open':
            session['context']=result.value
        elif phase!='close':
            batch=session['arrays']['uninstall' if phase=='uninstall' else 'install']
            if session['machine'].read(batch['address']+0x220*batch['count'],8)!=b'GUARDEND':
                fail('native driver phase overwrote its array guard')
        if phase in session['completed']: fail('native driver phase returned twice')
        session['completed'].append(phase)
        print('NATIVE_DRIVER_COMPLETED',phase,hex(result.value))
        return result

    def begin(m):
        driver_session['machine']=m
        return driver_cbs_open_execute(m)

    def start():
        if driver_session['started']: fail('native driver session already started')
        driver_session['started']=True
        report=native_driver_run(payloads['stages']['ServicingStackUpdate_KB5127647'].open(64),module='D:'+payloads['stages']['ServicingStackUpdate_KB5127647'].files[64].store_path,modules={'drvstore.dll':payloads['stages']['ServicingStackUpdate_KB5127647'].open(65)},execute=begin,plugins=[driver_session['registry'],driver_loader_probe(),driver_log_fixture(),driver_session['mount'],driver_unload_fixture()],plugin_factories=[driver_bind_fixture_kernel(driver_session['mount']),driver_catalog_factory],prepared_file_entries=driver_input_entries,volumes={'C:':{'filesystem':'NTFS','serial':8},'D:':{'filesystem':'NTFS','serial':9}},version=version,user_name='SYSTEM',user_sid='S-1-5-18',initialize=True,instruction_limit=2000000,memory_limit=512<<20,token_privileges={17:0,18:0},api_set_namespace=driver_api_namespace,loader_lookup_observer=driver_loader_capability_observer,virtual_modules=driver_virtual_modules)
        driver_session['initial_report']=report
        if 'machine' not in driver_session: fail('native driver module initialization failed before execution')
        return accept(report['result'])

    def advance(quanta=16):
        if not driver_session['started']: fail('native driver session has not started')
        if quanta<1 or quanta>64: fail('native driver continuation needs 1..64 quanta')
        m=driver_session['machine']
        for quantum in range(quanta):
            phase=driver_session['phase']
            if phase=='close' and phase in driver_session['completed']: break
            if phase not in driver_session['completed']:
                if driver_session['result'].reason!='instruction-limit': fail('native stop requires inspection, not replay')
                accept(m.run())
                continue
            if phase=='open':
                prepare_arrays(m)
            next_phase={'open':'stage','stage':'install','install':'uninstall','uninstall':'close'}[phase]
            driver_session['phase']=next_phase
            if next_phase=='close':
                result=m.call_export('DriverUpdateCloseContext',args=[driver_session['context']])
            else:
                batch=driver_session['arrays']['uninstall' if next_phase=='uninstall' else 'install']
                arguments=[driver_session['context'],batch['address'],batch['count'],0,0]
                if next_phase!='stage': arguments.append(0)
                export={'stage':'DriverUpdateStageUpdates','install':'DriverUpdateInstallUpdates','uninstall':'DriverUpdateUninstallUpdates'}[next_phase]
                result=m.call_export(export,args=arguments)
            accept(result)
        return driver_session['result']

    def finish():
        for chunk in range(65536):
            result=advance()
            if driver_session['completed']==['open','stage','install','uninstall','close']:
                retire_update_driver_process(driver_session)
                return result
            if chunk%32==0:
                print('NATIVE_DRIVER_PROGRESS',chunk,driver_session['phase'],result.reason,hex(result.pc))
        fail('native driver continuation bound exceeded; no output published')

    def publish(runtime, hives):
        if driver_session['completed']!=['open','stage','install','uninstall','close']:
            fail('native driver publication requires every completed phase and close')
        if driver_session['bcrypt'].state['hashes'] or driver_session['bcrypt'].state['objects']:
            fail('native driver CNG objects remain live')
        borrowed=[0x80000000,0x80000001,0x80000002,0x80000003]
        if any([key!=None and h not in borrowed for h,key in driver_cbs_registry.state['handles'].items()]):
            fail('native driver registry references remain live')
        kernel=driver_cbs_mount.state['kernel']
        report=dict(generated_entries=collect_update_driver_entries(kernel),file_queries=kernel.state['file_queries'])
        authority=prepare_update_driver_destination_authority(runtime,hives,report['generated_entries'])
        destinations=qualify_update_driver_destinations(root,authority,payloads,report['generated_entries'])
        result=prepare_update_driver_transaction(root,report,driver_initial_entries,kernel,driver_batch_hive_root,driver_cbs_mount,authorized=destinations['paths'])
        result['counts']['qualified_destinations']=destinations['counts']
        result['owner_plan']=cbs_owner_expected
        result['operations']=driver_plan['operations']
        return result

    return dict(start=start,advance=advance,finish=finish,publish=publish,state=driver_session)
