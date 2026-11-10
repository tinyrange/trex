"""Retire repository directories only for admitted last-owner replacements.

Called after replacement files, registry bindings and CSI owners are published
on the private candidate. Retained source packages and WinSxS files are untouched.
"""
_PREFIX='/Windows/System32/DriverStore/FileRepository/'

def plan_direct_driver_retirement(root,jobs):
    """Plan removal of unretained predecessor repositories, capturing their complete namespace and file epochs."""
    retained={j.get('source',j['before']).lower():True for j in jobs if j.get('retain_source',False)}
    packages={}
    names=root.path_index(lower=True)
    for job in jobs:
        if job.get('retain_source',False): continue
        old=job['before']
        if not old or old in ['.','..'] or any([c in old for c in ['/',chr(92),':',chr(0)]]):
            fail('invalid retiring driver repository')
        if old.lower()==job['after'].lower() or old.lower() in retained:
            fail('driver retirement conflicts with retained package')
        prefix=names.get((_PREFIX+old).lower())
        if prefix==None: fail('retiring driver repository is absent')
        packages[prefix.lower()]=prefix
    files={}
    directories={}
    for lower,actual in names.items():
        if not lower.startswith(_PREFIX.lower()): continue
        package=lower[len(_PREFIX):].split('/',1)[0]
        if (_PREFIX+package).lower() not in packages: continue
        if root.find(actual)!=None:
            files[actual]=root.get_metadata(actual).write_order
        else:
            directories[actual]=True
    return dict(packages=packages,files=files,directories=directories)

def apply_direct_driver_retirement(root,plan):
    """Reject stale files or extra namespace entries before deleting planned predecessor repositories; return removal counts."""
    # Check both old file epochs and the complete namespace before deleting.
    # A late extra file must not be silently swept up by recursive removal.
    actual={}
    for lower,path in root.path_index(lower=True).items():
        if not lower.startswith(_PREFIX.lower()): continue
        package=lower[len(_PREFIX):].split('/',1)[0]
        if (_PREFIX+package).lower() in plan['packages']:
            actual[path]=True
    if set(actual)!=set(plan['files'])|set(plan['directories']):
        fail('driver retirement namespace changed before publication')
    for path,order in plan['files'].items():
        if root.find(path)==None or root.get_metadata(path).write_order!=order:
            fail('driver retirement file changed before publication')
    for path in plan['directories']:
        if root.find(path)!=None: fail('driver retirement directory changed before publication')
    for path in plan['files']: root.remove(path)
    for path in sorted(plan['directories'],key=lambda p:(p.count('/'),p),reverse=True):
        root.rmdir(path)
    return dict(packages=len(plan['packages']),files=len(plan['files']),directories=len(plan['directories']))
