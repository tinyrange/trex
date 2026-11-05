"""Direct equivalent-INF replacement; one staged payload and one file pass.

No native installer execution, guest-side repair, or prepared-image cache. The
caller still owns catalog trust, CSI/CBS lifecycle and non-driver installers.
"""
load('@stdlib//windows/servicing:driver_replacements.star','plan_version_only_driver_replacements','require_version_only_driver_inf')
load('@stdlib//windows/servicing:driver_replace_hives.star','plan_version_only_driver_hives','apply_version_only_driver_hives')
load('@stdlib//windows/servicing:driver_owners.star','apply_update_driver_owners')
load('@stdlib//windows/servicing:file_stage.star','stage_update_payload_files')
load('@stdlib//windows/servicing:file_apply.star','prepare_and_apply_staged_update_file_effects')
load('@stdlib//windows/servicing:file_commit.star','image_path_names')

load('@stdlib//windows/servicing:driver_repositories.star','plan_direct_driver_repositories','apply_direct_driver_repositories')
load('@stdlib//windows/servicing:driver_runtime.star','plan_direct_driver_runtime','apply_direct_driver_runtime')
load('@stdlib//windows/servicing:driver_retire.star','plan_direct_driver_retirement','apply_direct_driver_retirement')
load('@stdlib//windows/servicing:print_queue.star','plan_direct_print_queue','apply_direct_print_queue')
load('@stdlib//windows/servicing:catalog_hints.star','plan_driver_catalog_hints','apply_catalog_hints')

_REPOSITORY='/Windows/System32/DriverStore/FileRepository/'

def _bind_installed_sources(root, plan):
    names=image_path_names(root, mutable=False)
    hives=[windows.hive(root.find('/Windows/System32/config/'+name)) for name in ['SYSTEM','DRIVERS']]
    jobs=[]
    for replacement in plan['replacements']:
        if replacement['unchanged']: continue
        before,after=replacement['before'],replacement['after']
        old=before['declaration']['repository']
        new=after['declaration']['repository']
        row=dict(before=old,after=new,inf=after['row']['inf'],version=after['declaration']['version'],architecture=after['row']['architecture'])
        bindings=[h for h in hives if h.find(['DriverDatabase','DriverPackages',old]) != None]
        if not bindings:
            # A last CSI owner need not be the currently selected driver.
            # Reuse only an actual active same-architecture package with the
            # same ordered instructions, and keep that still-owned package.
            active=[h.find(['DriverDatabase','DriverInfFiles',row['inf']]) for h in hives if h.find(['DriverDatabase','DriverInfFiles',row['inf']]) != None]
            candidates=[k.values.get('Active','') for k in active]
            candidates=[p for p in candidates if p.lower().startswith(row['inf'].lower()+'_'+row['architecture'].lower()+'_')]
            if len(candidates) != 1: fail('missing retiring driver has no unique active source')
            row.update(source=candidates[0],retain_source=True)
        elif len(bindings) != 1:
            fail('driver replacement has ambiguous physical hive bindings')
        source=row.get('source',old)
        inf_path=names.get((_REPOSITORY+source+'/'+row['inf']).lower())
        if inf_path == None: fail('installed driver replacement source INF is absent')
        require_version_only_driver_inf(root.find(inf_path),after['file'])
        row['inf_source']=after['path']
        jobs.append(row)
    return jobs

def _publish_repository_aliases(root, jobs):
    names=image_path_names(root)
    repositories={row['after'].lower():[] for row in jobs}
    prefix=_REPOSITORY.lower()
    for path in root.files:
        if not path.lower().startswith(prefix): continue
        parts=path[len(prefix):].split('/',1)
        if len(parts)==2 and parts[0].lower() in repositories:
            repositories[parts[0].lower()].append((parts[1],path))
    counts=dict(infs=0,catalogs=0,pnf_removed=0)
    for row in jobs:
        files=repositories[row['after'].lower()]
        if not files: fail('direct driver replacement repository was not constructed')
        row['size']=0
        for relative,path in files: row['size']+=root.find(path).size
        inf=names.get((_REPOSITORY+row['after']+'/'+row['inf']).lower())
        if inf == None or root.find(inf).bytes() != root.find(row['inf_source']).bytes():
            fail('constructed driver INF differs from its admitted source')
        for relative,path in files:
            if relative.lower().endswith('.cat'):
                if '/' in relative: fail('driver catalog requires an explicit leaf destination')
                windows.catalog_index(root.find(path))
                destination='/Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/'+relative
                parent=names.get(destination.rsplit('/',1)[0].lower())
                if parent == None: fail('driver catalog destination has no actual parent')
                actual=names.get(destination.lower(),parent+'/'+relative)
                if root.find(actual) != None: root.remove(actual)
                root.hardlink(path,actual)
                names[destination.lower()]=actual
                counts['catalogs']+=1
        if row['architecture'].lower() == 'amd64':
            destination='/Windows/INF/'+row['inf']
            parent=names.get('/windows/inf')
            if parent == None: fail('published driver INF directory is absent')
            actual=names.get(destination.lower(),parent+'/'+row['inf'])
            if root.find(actual) != None: root.remove(actual)
            root.hardlink(inf,actual)
            counts['infs']+=1
            pnf=names.get(destination[:-4].lower()+'.pnf')
            if pnf != None:
                root.remove(pnf)
                counts['pnf_removed']+=1
    return counts

def prepare_update_direct_driver_tree(root, runtime, hives, payloads, population, analysis, while_verifying=None, audit_payloads=False):
    """Clone root, stage payloads once and apply qualified direct driver/file changes; return the independent candidate and phase report."""
    updated=root.clone()
    staged=stage_update_payload_files(updated,payloads)
    return finish_update_direct_driver_tree(updated,staged,runtime,hives,payloads,population,analysis,while_verifying=while_verifying,audit_payloads=audit_payloads)

def finish_update_direct_driver_tree(updated, staged, runtime, hives, payloads, population, analysis, while_verifying=None, audit_payloads=False):
    """Continue a staged candidate without replaying recovery generation."""
    # These planners read staged sources and the unchanged baseline only.
    # Run them once on the caller thread, overlapped with native byte hashing
    # only in explicit audit mode. Publish no effects before planning finishes.
    prepared_driver = {}
    def plan_while_verifying():
        began = clock.monotonic()
        plan = plan_version_only_driver_replacements(updated,payloads,population,analysis,runtime=runtime)
        jobs = _bind_installed_sources(updated,plan)
        repositories = plan_direct_driver_repositories(updated,jobs,plan['replacements'],analysis['manifests'])
        runtime_aliases = plan_direct_driver_runtime(updated,jobs,repositories)
        retirement = plan_direct_driver_retirement(updated,jobs)
        prepared_driver.update(plan=plan,jobs=jobs,repositories=repositories,runtime_aliases=runtime_aliases,retirement=retirement)
        print('direct driver sources bound',len(jobs),'planning',clock.monotonic()-began)
        if while_verifying != None:
            while_verifying()
    # Ordinary CSI files and driver-owned aliases have separate authority.
    # Repositories require the full layout even for x86 drivers on amd64.
    files=prepare_and_apply_staged_update_file_effects(updated,runtime,hives,payloads,while_verifying=plan_while_verifying, audit_payloads=audit_payloads)
    plan,jobs,repositories=prepared_driver['plan'],prepared_driver['jobs'],prepared_driver['repositories']
    files['repositories']=apply_direct_driver_repositories(updated,repositories,audit_payloads=audit_payloads)
    files['driver_runtime']=apply_direct_driver_runtime(updated,prepared_driver['runtime_aliases'])
    aliases=_publish_repository_aliases(updated,jobs)
    files['driver_catalog_hints']=apply_catalog_hints(updated,plan_driver_catalog_hints(updated,jobs,repositories,host_architecture='amd64'))
    replacements=plan_version_only_driver_hives(updated,jobs)
    hive_count=apply_version_only_driver_hives(updated,replacements)
    owners=apply_update_driver_owners(updated,plan['owner_plan'])
    files['retired_driver_repositories']=apply_direct_driver_retirement(updated,prepared_driver['retirement'])
    files['printer_queue']=apply_direct_print_queue(updated,plan_direct_print_queue(updated,plan['replacements']))
    files.update(staged=staged,drivers=dict(replaced=len(jobs),unchanged=len(plan['replacements'])-len(jobs),hives=hive_count,aliases=aliases),driver_owners=owners)
    return dict(root=updated,files=files,driver_jobs=jobs,driver_repositories=repositories)
