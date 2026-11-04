"""Queue admitted native-architecture printer replacements for first boot.

Records come from exact installed replacement INF inputs, never a reference
hive. Queue presence means pending work, not successful printer installation.
Opaque entry IDs are deterministic; Windows' incidental random IDs are not an
image-construction requirement.
"""
load('@stdlib//windows/servicing:registry_effects.star','plan_update_registry_effects','apply_update_registry_effects')
_PATH='/Windows/System32/config/SOFTWARE'
_KEY='/Microsoft/Windows NT/CurrentVersion/Print/PackagesToAdd'
_CLASS='{4d36e979-e325-11ce-bfc1-08002be10318}'

def _identity(values):
    return (values['Architecture'],values['Inf Path'].lower(),values['KB Name'].lower(),values['Published Name'].lower())

def plan_direct_print_queue(root,replacements):
    """Plan supported print-driver pending operations from explicit driver jobs and repository bindings."""
    source=root.find(_PATH)
    hive=windows.hive(source)
    parent=hive.find(_KEY)
    if parent==None: fail('printer pending queue parent is absent')
    current=hive.find('/Microsoft/Windows NT/CurrentVersion')
    windows_path=current.values.get('SystemRoot','') if current!=None else ''
    if len(windows_path)<4 or windows_path[1:3]!=':'+chr(92) or not windows_path[0].isalpha() or windows_path.endswith(chr(92)):
        fail('printer queue requires the target Windows directory')
    seen={}
    occupied={}
    for child in parent.children:
        occupied[child.name.lower()]=True
        folded={k.lower():v for k,v in child.values.items()}
        values={k:folded[k.lower()] for k in ['Architecture','Inf Path','KB Name','Published Name'] if k.lower() in folded}
        if len(values)==4:
            if type(values['Architecture'])!='int' or any([type(values[k])!='string' for k in ['Inf Path','KB Name','Published Name']]):
                fail('existing printer queue record has invalid types')
            seen[_identity(values)]=True
    effects=dict(keys=[],key_deletions=[],values=[],value_deletions=[])
    files=[]
    records=[]
    for replacement in replacements:
        if replacement['unchanged']: continue
        after=replacement['after']
        # This image's native print queue is consumed by the amd64 spooler.
        # Cross-architecture package staging does not imply native installation.
        if after['row']['architecture'].lower()!='amd64': continue
        path=after['path']
        file=root.find(path)
        if file==None or digest(file)!=binary.decode(after['row']['hash'],'base64'):
            fail('printer queue INF differs from admitted replacement')
        fields={}
        for section,key,values in windows.inf(file).directives:
            if section.lower()!='version' or key==None or key.lower() not in ['class','classguid','driverver']: continue
            key=key.lower()
            if key in fields: fail('ambiguous printer INF version field')
            fields[key]=list(values)
        if fields.get('class')==None or len(fields['class'])!=1: fail('driver INF class is missing or ambiguous')
        if fields['class'][0].lower()!='printer': continue
        if len(fields.get('classguid',[]))!=1 or fields['classguid'][0].lower()!=_CLASS:
            fail('printer class GUID disagrees')
        version=fields.get('driverver',[])
        if version!=replacement['comparison']['after']: fail('printer INF version changed after admission')
        date=version[0].split('/') if len(version)==2 else []
        if len(date)!=3 or any([not p.isdigit() for p in date]): fail('invalid printer DriverVer date')
        inf=after['row']['inf']
        if not inf or any([c in inf for c in ['/',chr(92),':',chr(0)]]): fail('invalid published printer name')
        if not path.lower().startswith('/windows/winsxs/') or any([p in ['.','..',''] for p in path.split('/')[1:]]):
            fail('printer source is outside the staged component store')
        values={'Architecture':9,'Inf Path':windows_path+path[len('/Windows'):].replace('/',chr(92)),
            'KB Name':inf+'_'+'-'.join([str(int(p)) for p in date])+'_'+version[1],
            'Published Name':inf}
        identity=_identity(values)
        if identity in seen: continue
        seen[identity]=True
        # Version-8 UUID: application-defined SHA256 name, RFC variant bits.
        token=hex(digest(json.encode(identity)))[:32]
        entry='{'+token[:8]+'-'+token[8:12]+'-8'+token[13:16]+'-8'+token[17:20]+'-'+token[20:]+'}'
        if entry.lower() in occupied: fail('printer pending queue ID collision')
        occupied[entry.lower()]=True
        key=_KEY+'/'+entry
        descriptor=windows.inherit_registry_security(windows.compile_sddl('O:SYG:SYD:'),parent=parent.security)
        effects['keys'].append(dict(hive='SOFTWARE',key=key,security=descriptor))
        for name,value in values.items():
            kind,raw=(4,binary.u32le(value)) if type(value)=='int' else (1,binary.encode(value+chr(0),encoding='utf16le'))
            effects['values'].append(dict(hive='SOFTWARE',key=key,name=name,type=kind,value=raw))
        files.append((path,root.get_metadata(path).write_order))
        records.append(values)
    plans=plan_update_registry_effects(root,effects,[dict(hive='SOFTWARE',target='SOFTWARE',prefix='/',path=_PATH,source=source)])
    return dict(plans=plans,files=files,records=records)

def apply_direct_print_queue(root,plan):
    """Validate the pending print plan input epochs and publish its registry effects."""
    for path,order in plan['files']:
        if root.find(path)==None or root.get_metadata(path).write_order!=order:
            fail('printer source changed before queue publication')
    return dict(queued=len(plan['records']),installation='pending-first-boot',publication=apply_update_registry_effects(root,plan['plans']))
