"""Manifest-owned deferred NGEN commands. Never runs ngen or marks it complete."""
load("@stdlib//windows/servicing:runtime.star", "servicing_runtime_manifest_root")
load('@stdlib//windows/servicing:registry_effects.star', 'plan_update_registry_effects', 'apply_update_registry_effects')
_NS='urn:schemas-microsoft-com:asm.v3'
_PATH='/Windows/System32/config/SOFTWARE'
_QUEUE='/Microsoft/.NETFramework/NGenQueue'

def _attrs(node):
    result={}
    for item in node.attributes:
        if item['name']=='xmlns' and item['namespace']=='xmlns' and item['value']==node.namespace:
            continue
        if item['namespace'] or item['name'] in result:
            fail('unsupported NGEN attribute')
        result[item['name']]=item['value']
    return result

def _safe(value):
    if not value or any([c in value for c in ['"', ',', '/', chr(92), chr(0), chr(10), chr(13)]]):
        fail('unsafe NGEN identity field')
    return value

def _declarations(document, change=None, side="after"):
    if document==None: return []
    if 'ngen' not in windows.assembly_manifest(document).file_elements: return []
    tree=servicing_runtime_manifest_root(change, side) if change!=None else binary.xml(document,discard_whitespace=True).root
    marked=[(n,c) for n in tree.children if n.namespace==_NS and n.name=='file' for c in n.children if c.namespace==_NS and c.name=='ngen']
    if not marked: return []
    identities=[_attrs(n) for n in tree.children if n.namespace==_NS and n.name=='assemblyIdentity']
    if len(identities)!=1: fail('NGEN requires one component identity')
    identity=identities[0]
    result=[]
    for node,child in marked:
        arch=identity.get('processorArchitecture')
        # WCP GetAssemblySpecificInfo applies gac.clrarch before storing the
        # AssemblyInfo architecture used by CreateRegKeysForNGen. In .NET
        # updates an amd64 component can own an MSIL assembly; an explicit
        # x86 override on a WOW64 component dispatches to Win32.
        gacs=[c for c in node.children if c.namespace==_NS and c.name=='gac']
        if len(gacs)>1: fail('multiple GAC declarations for NGEN assembly')
        if gacs:
            override=_attrs(gacs[0]).get('clrarch')
            if override!=None:
                if override not in ['amd64','x86','msil']: fail('unsupported NGEN CLR architecture')
                arch=override
        targets={'amd64':['Win64'],'x86':['Win32'],'wow64':[],'msil':['Win32','Win64']}.get(arch)
        if targets==None: fail('unsupported NGEN target architecture')
        arch='x86' if arch=='wow64' else arch
        attrs=_attrs(child)
        if child.children or any([k not in ['managedversion','managedculture','parameter','win64targetarch'] for k in attrs]):
            fail('unsupported NGEN declaration')
        if 'win64targetarch' in attrs:
            # WCP 26100.33634 ModifyGacFiles validates this annotation using
            # ordinal case-insensitive comparison, but does not assign it to
            # AssemblyInfo's target-mode field. That field stays at default 0;
            # CreateRegKeysForNGen consequently queues MSIL on both platforms.
            # Do not infer Win64-only dispatch from the attribute's spelling.
            # Admit only the observed Server shape; other modes need proof.
            if arch!='msil' or attrs['win64targetarch'].lower()!='64bitonly':
                fail('unsupported NGEN win64targetarch')
        # Native ModifyGacFiles treats this exact directive as a transaction
        # flag, not an assembly identity or an ngen.exe argument. CommitChanges
        # issues one global update /queue per supported target platform.
        if attrs.get('parameter')=='IssueNgenUpdate':
            result.append(dict(update=True))
            continue
        name=_safe(_attrs(node)['name'])
        if not name.lower().endswith('.dll') and not name.lower().endswith('.exe'): fail('NGEN requires DLL or EXE assembly identity')
        version=attrs.get('managedversion','')
        if len(version.split('.'))!=4 or any([not p or not all([c in '0123456789' for c in p.elems()]) for p in version.split('.')]):
            fail('invalid NGEN managed version')
        token=identity.get('publicKeyToken','').lower()
        if len(token)!=16 or any([c not in '0123456789abcdef' for c in token.elems()]): fail('invalid NGEN public key token')
        culture=_safe(attrs.get('managedculture') or 'Neutral')
        parameter=attrs.get('parameter','')
        # Admit only measured switches. In particular, do not accept arbitrary
        # command text, paths or options that change assembly selection.
        words=parameter.split()
        if len(set(words))!=len(words) or any([w not in ['/NoDependencies','/queue:1','/queue:2','/queue:3'] for w in words]) or len([w for w in words if w.startswith('/queue:')])>1:
            fail('unsupported NGEN parameters')
        # WCP uses the component identity's assembly name, not filename case.
        full='%s, Version=%s, Culture=%s, PublicKeyToken=%s, processorArchitecture=%s'%(_safe(identity['name']),version,culture,token,arch)
        result.append(dict(identity=full,targets=targets,parameter=parameter))
    return result

def collect_update_ngen(runtime):
    """Collect supported NGEN declarations from runtime transitions, retaining architecture and native ordering."""
    commands={'Win32':[],'Win64':[]}
    update=False
    for transition in runtime['transitions']:
        for phase,operation in [('before','uninstall'),('after','install')]:
            for item in _declarations(transition[phase], transition, phase):
                if item.get('update',False):
                    update=True
                    continue
                parameter=item['parameter']
                # Native removal drops the priority switch, retaining any
                # separating whitespace. Do not apply install priority on removal.
                if operation=='uninstall':
                    for option in ['/queue:1','/queue:2','/queue:3']:
                        parameter=parameter.replace(option,'')
                command=operation+' "'+item['identity']+'"'+(' '+parameter if parameter else '')
                for target in item['targets']:
                    commands[target].append(command)
    if update:
        for platform in commands:
            commands[platform].append('update /queue')
    return commands

def plan_update_ngen(root,runtime):
    """Plan deferred native-image queue entries from admitted runtime declarations without compiling managed code."""
    commands=collect_update_ngen(runtime)
    source=root.find(_PATH)
    if source==None: fail('NGEN requires SOFTWARE hive')
    hive=windows.hive(source, snapshot=True)
    components_path='/Windows/System32/config/COMPONENTS'
    components_source=root.find(components_path)
    if components_source==None: fail('NGEN requires COMPONENTS hive')
    components=windows.hive(components_source, snapshot=True)
    if components.find('/').values.get('StoreArchitecture')!=binary.u32le(9): fail('NGEN queue planner requires amd64 component store')
    # Native CreatePlatformSpecificNgenKey sets the priority-transfer flag
    # after every successful command write. Removal also requests update /queue
    # for both supported platform queues on this amd64 target.
    if any(commands.values()):
        removed=any([c.startswith('uninstall ') for items in commands.values() for c in items])
        for platform in ['Win32','Win64']:
            if removed and 'update /queue' not in commands[platform]: commands[platform].append('update /queue')
            persisted=hive.find(_QUEUE+'/'+platform+'/PersistedPriorities')
            if persisted==None: fail('NGEN persisted priorities parent is missing')
            for name,value in persisted.value_records.items():
                if value.type!=1: continue
                command=binary.text(value.raw,encoding='utf16le')
                if not command.endswith(chr(0)) or chr(0) in command[:-1]: fail('invalid persisted NGEN command')
                commands[platform].append(command[:-1])
    effects=dict(keys=[],values=[],key_deletions=[],value_deletions=[])
    records=[]
    for platform in ['Win32','Win64']:
        if not commands[platform]: continue
        path=_QUEUE+'/'+platform+'/Default'
        parent=hive.find(path)
        if parent==None: fail('NGEN platform queue parent is missing')
        ids=[]
        for child in parent.children:
            if not child.name or not all([c in '0123456789' for c in child.name.elems()]):
                fail('NGEN queue contains a nonnumeric child')
            ids.append(int(child.name))
        number=max(ids+[0])
        security=windows.inherit_registry_security(windows.compile_sddl('O:SYG:SYD:'),parent=parent.security)
        # Commands must remain ordered: a repeated install from an earlier
        # transaction is not proof that this replacement has been processed.
        for command in commands[platform]:
            number+=1
            if number>0xffffffff: fail('NGEN queue sequence overflow')
            key=path+'/'+str(number)
            effects['keys'].append(dict(hive='SOFTWARE',key=key,security=security))
            effects['values'].append(dict(hive='SOFTWARE',key=key,name='(default)',type=1,value=binary.encode(command+chr(0),encoding='utf16le')))
            records.append((platform,command))
    if records:
        descriptor=components.find('/').security
        for key in ['/Installers','/Installers/Ngen']:
            existing=components.find(key)
            if existing!=None:
                descriptor=existing.security
            else:
                descriptor=windows.inherit_registry_security(windows.compile_sddl('O:SYG:SYD:'),parent=descriptor)
                effects['keys'].append(dict(hive='COMPONENTS',key=key,security=descriptor))
        for platform,name in [('Win32','TicklerArchWow'),('Win64','TicklerArchNative')]:
            if commands[platform]: effects['values'].append(dict(hive='COMPONENTS',key='/Installers/Ngen',name=name,type=4,value=binary.u32le(1)))
    plans=plan_update_registry_effects(root,effects,[
        dict(hive='SOFTWARE',target='SOFTWARE',prefix='/',path=_PATH,source=source),
        dict(hive='COMPONENTS',target='COMPONENTS',prefix='/',path=components_path,source=components_source),
    ])
    return dict(plans=plans,records=records)

def apply_update_ngen(root,plan):
    """Preflight queue inputs and publish prepared deferred NGEN registry effects; return publication evidence, not completed compilation."""
    return dict(queued=len(plan['records']),validation='runtime NGen execution not observed by this queue-publication helper',publication=apply_update_registry_effects(root,plan['plans']))
