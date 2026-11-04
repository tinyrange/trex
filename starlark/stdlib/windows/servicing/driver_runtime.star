"""Refresh installed runtime aliases of admitted equivalent-INF replacements.

The installed file object, not a filename or matching bytes, establishes the
binding. No INF execution, new runtime destination, generic CSI projection or
FileMap ownership is inferred. Repository planning has already bound each new
source to an unchanged installed layout and a manifest hash.
"""

_REPOSITORY = '/Windows/System32/DriverStore/FileRepository/'

def plan_direct_driver_runtime(root, jobs, repositories):
    """Select installed runtime aliases for explicitly bound driver repository replacements."""
    names = root.path_names(lower=True)
    selected = {j['after'].lower():j.get('source', j['before']) for j in jobs}
    objects = {}
    for item in repositories['files']:
        path = item['path']
        if not path.lower().startswith(_REPOSITORY.lower()):
            fail('driver runtime source is outside its repository plan')
        package, relative = path[len(_REPOSITORY):].split('/', 1)
        old = selected.get(package.lower())
        if old == None:
            fail('driver runtime repository has no admitted replacement')
        original = names.get((_REPOSITORY + old + '/' + relative).lower())
        if original == None or root.find(original) == None:
            fail('driver runtime installed source is absent')
        identity = root.get_metadata(original).hard_link_id
        if not identity:
            continue
        previous = objects.get(identity)
        if previous != None and previous['source'] != item['source']:
            fail('shared installed driver object has competing replacements')
        objects[identity] = dict(source=item['source'], original=original,
            source_order=repositories['source_versions'][item['source']],
            original_order=root.get_metadata(original).write_order)
    files = []
    for path in root.files:
        lower = path.lower()
        # Store, published INF and catalog aliases have their own publishers.
        if any([lower.startswith(p) for p in ['/windows/winsxs/',
                _REPOSITORY.lower(), '/windows/inf/', '/windows/system32/catroot/']]):
            continue
        metadata = root.get_metadata(path)
        source = objects.get(metadata.hard_link_id) if metadata.hard_link_id else None
        if source == None:
            continue
        if not any([lower.startswith(p) for p in ['/windows/system32/', '/windows/syswow64/']]) or lower.startswith('/windows/system32/config/'):
            fail('installed driver alias requires explicit destination policy: ' + path)
        files.append(dict(source, path=path, original_id=metadata.hard_link_id,
            destination_order=metadata.write_order))
    return files

def apply_direct_driver_runtime(root, files):
    """Preflight runtime alias authority before replacing links; preserve independently selected winners and return replacement counts."""
    # Validate the complete batch before replacing any alias. The ordinary
    # file pass may already have selected the same exact new source object;
    # tolerate that, but never overwrite an independently selected winner.
    pending = []
    for item in files:
        source, path, original = item['source'], item['path'], item['original']
        if root.find(source) == None or root.get_metadata(source).write_order != item['source_order']:
            fail('driver runtime source changed before publication')
        if root.find(original) == None or root.get_metadata(original).write_order != item['original_order'] or root.get_metadata(original).hard_link_id != item['original_id']:
            fail('driver runtime installed binding changed before publication')
        if root.find(path) == None:
            fail('driver runtime destination disappeared before publication')
        current = root.get_metadata(path)
        source_id = root.get_metadata(source).hard_link_id
        if source_id and current.hard_link_id == source_id:
            continue
        if current.write_order != item['destination_order'] or current.hard_link_id != item['original_id']:
            fail('driver runtime destination changed before publication')
        pending.append(item)
    for item in pending:
        root.remove(item['path'])
        root.hardlink(item['source'], item['path'])
    return dict(installed_aliases=len(files), replaced=len(pending))
