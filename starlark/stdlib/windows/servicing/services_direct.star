"""Apply declared service deltas without running the service installer.

Unchanged settings (including image policy) are preserved. This handles explicit
SCM configuration and SvcHost membership; it neither starts services nor invents
an advanced-installer completion record.
"""
load('@stdlib//windows/servicing:registry_effects.star','plan_update_registry_effects','apply_update_registry_effects')
_NS='urn:schemas-microsoft-com:asm.v3'
_SYSTEM='/Windows/System32/config/SYSTEM'
_SOFTWARE='/Windows/System32/config/SOFTWARE'
_GROUP='/Microsoft/Windows NT/CurrentVersion/SvcHost'

_FIELDS={
    'displayName':('DisplayName',1), 'description':('Description',1),
    'imagePath':('ImagePath',2), 'objectName':('ObjectName',1),
    'group':('Group',1), 'dependOnService':('DependOnService',7),
    'dependOnGroup':('DependOnGroup',7), 'requiredPrivileges':('RequiredPrivileges',7),
    'start':('Start',4), 'type':('Type',4), 'errorControl':('ErrorControl',4),
    'sidType':('ServiceSidType',4), 'delayedAutoStart':('DelayedAutoStart',4),
    'launchProtected':('LaunchProtected',4),
}
_ENUMS={
    'start':{'boot':0,'system':1,'auto':2,'demand':3,'disabled':4},
    'type':{'kernelDriver':1,'fileSystemDriver':2,'win32OwnProcess':16,'win32ShareProcess':32},
    'errorControl':{'ignore':0,'normal':1,'severe':2,'critical':3},
    'sidType':{'none':0,'unrestricted':1,'restricted':3},
    'delayedAutoStart':{'false':0,'true':1},
    'launchProtected':{'windows':1,'windowsLight':2,'antimalwareLight':3},
}

def _attrs(n):
    result={a['name']:a['value'] for a in n.attributes if not a['namespace']}
    if len(result)!=len(n.attributes): fail('ambiguous service declaration attributes')
    return result

def _children(n,name):
    return [c for c in n.children if c.namespace==_NS and c.name==name]

def _walk(n,name):
    return n.select_descendants([name], namespace=_NS, include_self=True)[name]

def _leaf(value):
    if not value or value in ['.','..'] or any([c in value for c in ['/',chr(92),chr(0),'$(']]):
        fail('invalid service or group name')
    return value

def _shape(n):
    return (n.name,sorted(_attrs(n).items()),[_shape(c) for c in n.children])

def _svc_host_shapes(root):
    return [_shape(n) for n in _walk(root,'categoryMembership') if any([_attrs(i).get('typeName')=='SvcHost' for i in _children(n,'id')])]

def collect_direct_services(runtime):
    """Collect before/after service and group contributions from manifest-bound runtime transitions."""
    services={'before':{},'after':{}}
    groups={'before':{},'after':{}}
    for transition in runtime['transitions']:
        for side,document in transition.get('documents',{}).items():
            root=document[1]
            identity=windows.csi_identity(transition['component_identities'][side])
            nodes=root.select_descendants(['serviceData','securityDescriptorDefinition','categoryMembership'], namespace=_NS, include_self=True)
            declarations=nodes['serviceData']
            if declarations and identity.processor_architecture not in ['amd64','wow64','x86']:
                fail('service declaration requires explicit target architecture')
            definitions={}
            for d in nodes['securityDescriptorDefinition']:
                a=_attrs(d)
                if a['name'] in definitions and definitions[a['name']]!=a['sddl']:
                    fail('conflicting service security definition')
                definitions[a['name']]=a['sddl']
            for n in declarations:
                attrs=_attrs(n)
                name=_leaf(attrs['name']).lower()
                children={}
                for c in n.children:
                    if c.namespace!=_NS: fail('unsupported service child namespace')
                    children.setdefault(c.name,[]).append(c)
                security=None
                if 'securityDescriptor' in children:
                    if len(children['securityDescriptor'])!=1: fail('ambiguous service security reference')
                    security_node=children['securityDescriptor'][0]
                    reference=_attrs(security_node)
                    if sorted(reference)!=['name'] or security_node.children:
                        fail('unsupported service security reference')
                    security=definitions.get(reference['name'])
                    if security==None: fail('missing service security definition')
                record=dict(attrs=attrs,children=children,security=security,architecture=identity.processor_architecture,
                    signature=json.encode((sorted(attrs.items()),[_shape(c) for c in n.children],security)))
                services[side].setdefault(name,[]).append(record)
            for membership in nodes['categoryMembership']:
                ids=_children(membership,'id')
                if len(ids)!=1 or _attrs(ids[0]).get('typeName')!='SvcHost': continue
                category=_attrs(ids[0])
                if category.get('name')!='Microsoft.Windows.Categories' or category.get('publicKeyToken')!='365143bb27e7ac8b':
                    fail('unsupported SvcHost category')
                if identity.processor_architecture=='x86':
                    # No registry-view decision is needed for an unchanged
                    # contribution. Do not authorize changed x86 membership.
                    other='after' if side=='before' else 'before'
                    paired=transition.get('documents',{}).get(other)
                    if paired==None or windows.csi_identity(transition['component_identities'][other]).processor_architecture!='x86' or json.encode(_svc_host_shapes(root))!=json.encode(_svc_host_shapes(paired[1])):
                        fail('changed x86 SvcHost membership requires separate policy')
                    continue
                prefix=('/Wow6432Node' if identity.processor_architecture=='wow64' else '')+_GROUP
                if identity.processor_architecture not in ['amd64','wow64']: fail('unsupported SvcHost architecture')
                for instance in _children(membership,'categoryInstance'):
                    group=_leaf(_attrs(instance)['subcategory'])
                    for member in _children(instance,'serviceGroup'):
                        a=_attrs(member)
                        if any([k not in ['position','serviceName'] for k in a]) or a.get('position','any') not in ['first','last','any']:
                            fail('unsupported SvcHost ordering declaration')
                        service=_leaf(a['serviceName'])
                        key=(prefix,group.lower(),service.lower())
                        value=(group,service,a.get('position','any'))
                        if key in groups[side] and groups[side][key]!=value: fail('conflicting SvcHost membership')
                        groups[side][key]=value
    selected={'before':{},'after':{}}
    for name in set(services['before'])|set(services['after']):
        old,new=services['before'].get(name,[]),services['after'].get(name,[])
        if sorted([v['signature'] for v in old])==sorted([v['signature'] for v in new]):
            continue  # Unchanged competing declarations do not require ranking.
        if any([v['architecture']=='x86' for v in old+new]):
            fail('changed service has unestablished x86 contribution: '+name)
        for side,records in [('before',old),('after',new)]:
            if len(set([v['signature'] for v in records]))>1:
                fail('changed service has competing declarations: '+name)
            if records: selected[side][name]=records[0]
    return dict(services=selected,groups=groups)

def _raw(field,value):
    if '$(' in value or chr(0) in value: fail('unresolved service configuration value')
    name,kind=_FIELDS[field]
    if kind==4:
        if value not in _ENUMS[field]: fail('unsupported service '+field+': '+value)
        return name,kind,binary.u32le(_ENUMS[field][value])
    if kind==7:
        values=[v.strip() for v in value.split(',')]
        if any([not v for v in values]): fail('empty service list member')
        value=chr(0).join(values)+chr(0)
    return name,kind,binary.encode(value+chr(0),encoding='utf16le')

def _failure(n):
    attrs=_attrs(n)
    if sorted(attrs)!=['resetPeriod'] or len(n.children)!=1 or n.children[0].name!='actions':
        fail('unsupported service failure actions')
    actions=[]
    for c in n.children[0].children:
        a=_attrs(c)
        if c.name!='action' or c.children or sorted(a)!=['delay','type'] or a['type'] not in ['none','restartService']:
            fail('unsupported service failure action')
        actions.append(binary.concat([binary.u32le(1 if a['type']=='restartService' else 0),binary.u32le(int(a['delay']))]))
    if not actions or len(actions)>64: fail('invalid service failure action count')
    return binary.concat([binary.u32le(int(attrs['resetPeriod'])),binary.u32le(0),binary.u32le(0),binary.u32le(len(actions)),binary.u32le(20)]+actions).bytes()

def _service_acl(acl):
    if acl==None: return None
    entries=[]
    for ace in windows.acl_entries(acl)['entries']:
        if ace['type'] not in [0,1,2]: fail('unsupported service ACE')
        mask=ace['mask']&0x0fffffff
        for generic,rights in [(0x80000000,0x2008d),(0x40000000,0x20002),(0x20000000,0x20170),(0x10000000,0xf01ff)]:
            if ace['mask']&generic: mask|=rights
        entries.append(binary.concat([ace['data'][:4],binary.u32le(mask),ace['data'][8:]]))
    return binary.concat([acl[:8]]+entries).bytes()

def _service_security(sddl,current):
    # Service rights differ from registry generic mappings. Preserve existing
    # principals, and preserve auditing unless this declaration supplies it.
    if not sddl.startswith('D:') or 'O:' in sddl or 'G:' in sddl:
        fail('service security requires a DACL update without principal changes')
    # The shipped Wlpasvc declaration contains one redundant opening bracket
    # between ACEs. Admit only this separator spelling, not arbitrary malformed
    # SDDL. Its parsed grants are checked against the reference and tests.
    sddl=sddl.replace(')((A;',')(A;')
    request=windows.security_descriptor_parts(windows.compile_sddl('O:SYG:SY'+sddl))
    prior=windows.security_descriptor_parts(current) if current!=None else request
    if request['dacl']==None or prior['owner']==None or prior['group']==None:
        fail('unsupported service security layout')
    dacl=_service_acl(request['dacl'])
    sacl=_service_acl(request['sacl']) if 'S:' in sddl else prior['sacl']
    owner,group=prior['owner'],prior['group']
    sacl_size=len(sacl) if sacl!=None else 0
    control=0x8004|(request['control']&0x1000)|(0x10 if sacl!=None else 0)
    control|=(request['control'] if 'S:' in sddl else prior['control'])&0x2000
    return binary.concat([binary.u16le(1),binary.u16le(control),
        binary.u32le(20+len(dacl)+sacl_size),binary.u32le(20+len(dacl)+sacl_size+len(owner)),
        binary.u32le(20+len(dacl) if sacl!=None else 0),binary.u32le(20),
        dacl,sacl if sacl!=None else b'',owner,group]).bytes()

def plan_direct_services(root,runtime):
    """Plan qualified service/group changes against actual SYSTEM and SOFTWARE state, preserving unrelated configuration and security."""
    declarations=collect_direct_services(runtime)
    sources={h:root.find(p) for h,p in [('SYSTEM',_SYSTEM),('SOFTWARE',_SOFTWARE)]}
    hives={h:windows.hive(f, snapshot=True) for h,f in sources.items()}
    current=hives['SYSTEM'].find('/Select').values['Current']
    if type(current)!='int' or current<1 or current>999: fail('invalid service control set')
    prefix='/ControlSet'+('00'+str(current))[-3:]+'/Services/'
    effects=dict(keys=[],key_deletions=[],values=[],value_deletions=[])
    key_security={}
    def put(hive,key,name,kind,raw):
        effects['values'].append(dict(hive=hive,key=key,name=name,type=kind,value=raw))
    def ensure(hive,key):
        parts=key.strip('/').split('/')
        for count in range(1,len(parts)+1):
            child=parts[:count]; identity=(hive,tuple([v.lower() for v in child]))
            if hives[hive].find(child)!=None or identity in key_security: continue
            parent=child[:-1]
            node=hives[hive].find(parent)
            descriptor=node.security if node!=None else key_security.get((hive,tuple([v.lower() for v in parent])))
            if descriptor==None: fail('service registry parent has no security')
            key_security[identity]=windows.inherit_registry_security(windows.compile_sddl('O:SYG:SYD:'),parent=descriptor)
    before,after=declarations['services']['before'],declarations['services']['after']
    changed=[]
    for name in sorted(set(before)|set(after)):
        old,new=before.get(name),after.get(name)
        if old!=None and new!=None and old['signature']==new['signature']: continue
        key=prefix+(new or old)['attrs']['name']
        changed.append(name)
        if new==None:
            effects['key_deletions'].append(dict(hive='SYSTEM',key=key))
            continue
        ensure('SYSTEM',key)
        a,b=(old['attrs'] if old!=None else {}),new['attrs']
        for field in set(a)|set(b):
            if field=='name' or a.get(field)==b.get(field): continue
            if field not in _FIELDS or field not in b: fail('unsupported changed service field: '+field)
            value,kind,raw=_raw(field,b[field])
            put('SYSTEM',key,value,kind,raw)
        old_children=old['children'] if old!=None else {}
        for child in set(old_children)|set(new['children']):
            if child=='securityDescriptor': continue
            x,y=old_children.get(child,[]),new['children'].get(child,[])
            if json.encode([_shape(n) for n in x])==json.encode([_shape(n) for n in y]): continue
            if child!='failureActions' or len(y)!=1: fail('unsupported changed service child: '+child)
            put('SYSTEM',key,'FailureActions',3,_failure(y[0]))
        if new['security']!=(old['security'] if old!=None else None):
            if new['security']==None: fail('service DACL removal requires explicit policy')
            security_key=key+'/Security'
            node=hives['SYSTEM'].find(security_key)
            prior=node.values.get('Security') if node!=None else None
            ensure('SYSTEM',security_key)
            put('SYSTEM',security_key,'Security',3,_service_security(new['security'],prior))
    old_groups,new_groups=declarations['groups']['before'],declarations['groups']['after']
    changed_groups={k[:2]:True for k in set(old_groups)|set(new_groups) if old_groups.get(k)!=new_groups.get(k)}
    for key,folded in sorted(changed_groups):
        members=[k for k in set(old_groups)|set(new_groups) if k[:2]==(key,folded)]
        name=(new_groups.get(members[0]) or old_groups[members[0]])[0]
        node=hives['SOFTWARE'].find(key)
        if node==None: fail('SvcHost registry key is absent')
        values={n.lower():(n,v) for n,v in node.values.items()}
        actual,entries=values.get(folded,(name,[]))
        if type(entries)!='list': fail('SvcHost value is not MULTI_SZ')
        entries=list(entries)
        for member in sorted(members):
            old,new=old_groups.get(member),new_groups.get(member)
            if old==new: continue
            entries=[v for v in entries if v.lower()!=member[2]]
            if new!=None:
                if new[2]=='first': entries.insert(0,new[1])
                else: entries.append(new[1])
        if entries: put('SOFTWARE',key,actual,7,binary.encode(chr(0).join(entries)+chr(0)*2,encoding='utf16le'))
        elif folded in values: effects['value_deletions'].append(dict(hive='SOFTWARE',key=key,name=actual))
    bindings=[dict(hive=h,target=h,prefix='/',path=p,source=sources[h]) for h,p in [('SYSTEM',_SYSTEM),('SOFTWARE',_SOFTWARE)]]
    return dict(plans=plan_update_registry_effects(root,effects,bindings,key_security=key_security),services=changed,groups=len(changed_groups))

def apply_direct_services(root,runtime):
    """Plan and publish supported direct service effects on root; return service/group and registry publication counts."""
    plan=plan_direct_services(root,runtime)
    return dict(services=plan['services'],groups=plan['groups'],publication=apply_update_registry_effects(root,plan['plans']))
