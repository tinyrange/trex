"""Plan version-only replacements from actual driver inputs, without emulation.

This is deliberately not a general INF installer. A matching CBS first/last
owner pair, exact manifest hashes, and unchanged INF instructions are required.
The plan does not itself publish files, invent package state, or run a guest.
"""
load('@stdlib//windows/servicing:drivers.star','plan_update_driver_operations')
load('@stdlib//windows/servicing:driver_owners.star','plan_update_driver_owners','order_update_driver_owner_operations')
load('@stdlib//windows/servicing:file_commit.star','image_path_names')

_NS = 'urn:schemas-microsoft-com:asm.v3'
_REPOSITORY = '/Windows/System32/DriverStore/FileRepository/'

def _inf_instructions(source):
    result = []
    version = None
    for section, key, fields in windows.inf(source).directives:
        if section.lower() == 'version' and key != None and key.lower() == 'driverver':
            if version != None or len(fields) != 2: fail('driver replacement requires one complete DriverVer')
            version = list(fields)
        else:
            result.append((section, key, fields))
    if version == None: fail('driver replacement requires DriverVer')
    return result, version

def require_version_only_driver_inf(before, after):
    """Reject changed instructions, including ordering and duplicate directives."""
    old, old_version = _inf_instructions(before)
    new, new_version = _inf_instructions(after)
    if old != new: fail('driver replacement changes INF instructions')
    if _driver_rank(new_version) < _driver_rank(old_version):
        fail('driver replacement would downgrade the selected driver')
    return dict(before=old_version, after=new_version, identical=before.bytes()==after.bytes())

def _driver_rank(version):
    date = version[0].split('/')
    numbers = version[1].split('.')
    if len(date) != 3 or len(numbers) != 4 or not all([v.isdigit() for v in date+numbers]):
        fail('driver replacement has unsupported DriverVer')
    month, day, year = [int(v) for v in date]
    values = [int(v) for v in numbers]
    if month < 1 or month > 12 or day < 1 or day > 31 or year < 1601 or year > 9999 or any([v > 65535 for v in values]):
        fail('driver replacement has invalid DriverVer')
    return (year,month,day)+tuple(values)

def _driver_manifest(source, inf, document=None):
    # Only reuse the runtime analysis tree while it is bound to this exact
    # immutable source file; equal names or replacement files are not proof.
    root = document[1] if document != None and document[0] == source else binary.xml(source).root
    files = root.children_named('file', namespace=_NS)
    declared = [f for f in files if f.attribute('name').lower() == inf.lower()]
    if len(declared) != 1: fail('driver replacement requires one exact INF declaration')
    destination = declared[0].attribute('destinationPath').replace(chr(92), '/').rstrip('/')
    prefix = '$(runtime.system32)/DriverStore/FileRepository/'
    if not destination.lower().startswith(prefix.lower()): fail('driver INF has no explicit repository destination')
    repository = destination[len(prefix):]
    if not repository or any([c in repository for c in ['/', ':', chr(0)]]) or repository in ['.', '..']:
        fail('invalid driver repository name')
    registry = root.child('registryKeys', namespace=_NS)
    package = 'HKEY_LOCAL_MACHINE'+chr(92)+'SYSTEM'+chr(92)+'DriverDatabase'+chr(92)+'DriverPackages'+chr(92)+repository
    versions = [v for key in registry.children_named('registryKey', namespace=_NS) if key.attribute('keyName').lower() == package.lower() for v in key.children_named('registryValue', namespace=_NS) if v.attribute('name').lower() == 'version'] if registry != None else []
    if len(versions) != 1 or versions[0].attribute('valueType') != 'REG_BINARY':
        fail('driver replacement requires its declared package Version')
    version = windows.assembly_registry_data('REG_BINARY', versions[0].attribute('value'))
    if len(version) != 48: fail('unsupported driver package Version layout')
    return dict(repository=repository, version=version)

def plan_version_only_driver_replacements(root, payloads, population, analysis, runtime=None):
    """Bind before/after driver sources and owner operations, accepting only supported equivalent-INF version transitions."""
    documents = {}
    if runtime != None:
        for transition in runtime["transitions"]:
            for side, captured in transition.get("documents", {}).items():
                documents[str(transition["component_identities"][side]).lower()] = captured
    manifests = dict(analysis['resident_manifests'])
    manifests.update(analysis['manifests'])
    operations = plan_update_driver_operations(population.deployment_actions(changed_only=True), manifests, [])
    source = root.find('/Windows/System32/config/COMPONENTS')
    owners = plan_update_driver_owners(source, order_update_driver_owner_operations(operations['operations']))
    stems = {str(k.values['identity']).lower():k.name for k in windows.hive(source).find('/DerivedData/Components').children}
    for stage in payloads['stages'].values():
        for component in stage.components:
            identity = str(component.identity).lower()
            if identity in stems and stems[identity].lower() != component.stem.lower():
                fail('driver source identity has conflicting stems')
            stems[identity] = component.stem
    names = image_path_names(root, mutable=False)
    def bind(row):
        identity = row['identity'].lower()
        if windows.csi_identity(bytes(row['identity'])).type.lower() != 'dualmodedriver':
            fail('direct driver replacement requires a dual-mode declaration')
        stem = stems.get(identity)
        if stem == None: fail('driver replacement has no exact source component')
        path = names.get(('/Windows/WinSxS/'+stem+'/'+row['inf']).lower())
        file = root.find(path) if path != None else None
        if file == None or digest(file,algorithm='sha256') != binary.decode(row['hash'],'base64'):
            fail('driver replacement INF differs from its admitted manifest')
        declaration = _driver_manifest(manifests[identity], row['inf'], documents.get(identity))
        return dict(row=row, path=path, file=file, declaration=declaration)
    old = {}
    for row in owners['last']:
        key = (row['architecture'].lower(),row['inf'].lower())
        if key in old: fail('multiple retiring versions require driver ranking')
        old[key] = bind(row)
    new = {}
    for row in owners['first']:
        key = (row['architecture'].lower(),row['inf'].lower())
        if key in new: fail('multiple arriving versions require driver ranking')
        new[key] = bind(row)
    if set(old) != set(new): fail('direct driver replacement requires paired first/last owners')
    replacements = []
    for key, after in new.items():
        before = old[key]
        comparison = require_version_only_driver_inf(before['file'],after['file'])
        same_repository = before['declaration']['repository'].lower() == after['declaration']['repository'].lower()
        if same_repository and not comparison['identical']:
            fail('changed driver content reuses the old repository name')
        replacements.append(dict(before=before, after=after, comparison=comparison, unchanged=same_repository))
    return dict(operations=operations['operations'],owner_plan=owners,replacements=replacements)
