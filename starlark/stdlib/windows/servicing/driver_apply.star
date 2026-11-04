"""Ordered driver/ownership/file construction; CBS finalization remains separate."""
load('@stdlib//windows/servicing:driver_session.star','prepare_update_driver_session')
load('@stdlib//windows/servicing:driver_direct.star','prepare_update_direct_driver_tree')
load('@stdlib//windows/servicing:driver_owners.star','plan_update_driver_owners','apply_update_driver_owners')
load('@stdlib//windows/servicing:file_stage.star','stage_update_payload_files')
load('@stdlib//windows/servicing:file_apply.star','prepare_and_apply_staged_update_file_effects')

def finish_update_driver_file_tree(root, candidate, runtime, hives, payloads, while_verifying=None, audit_payloads=False):
    """Publish a completed native session, then apply files WITHOUT restaging.

    The session checks actual phase returns, array guards, closed references,
    backing-hive bytes and complete native file objects before yielding a clone.
    Original COMPONENTS must still match the owner's source inventory. Changes
    stay on that independent tree until the entire function returns successfully.
    """
    owners=plan_update_driver_owners(root.find('/Windows/System32/config/COMPONENTS'),candidate['operations'])
    if owners['outputs']!=candidate['owner_plan']['outputs']:
        fail('driver owner source no longer selects the executed native jobs')
    updated=candidate['root']
    owner_counts=apply_update_driver_owners(updated,owners)
    files=prepare_and_apply_staged_update_file_effects(updated,runtime,hives,payloads,while_verifying=while_verifying,audit_payloads=audit_payloads)
    files['drivers']=candidate['counts']
    files['driver_owners']=owner_counts
    files['scope']='driver/file phase; other effects are applied by the caller'
    return dict(root=updated,files=files)

def prepare_update_driver_file_tree(root, runtime, hives, payloads, population, analysis, version, while_verifying=None, audit_payloads=False):
    """Build an independent direct-replacement candidate and file report. This uses qualified equivalent-INF replacement, not the separate native-session API; version is retained for caller compatibility."""
    # Retain the existing entry point until the complete native driver result
    # has passed publication checks and fresh-image validation.
    return prepare_update_direct_driver_tree(root,runtime,hives,payloads,population,analysis,while_verifying=while_verifying, audit_payloads=audit_payloads)


def prepare_update_native_driver_file_tree(root, runtime, hives, payloads, population, analysis, version, while_verifying=None, audit_payloads=False):
    """Execute the native transaction on staged sources, then finish once.

    Neither target mutations nor partial phase output escape on failure. In
    particular, do not restage after native driver installation: that would
    overwrite native security, aliases and deletions before qualification.
    """
    staged_root=root.clone()
    staged=stage_update_payload_files(staged_root,payloads)
    candidate=_run_update_native_driver_tree(staged_root,runtime,hives,payloads,population,analysis,version)
    result=finish_update_driver_file_tree(root,candidate,runtime,hives,payloads,while_verifying=while_verifying,audit_payloads=audit_payloads)
    result['files']['staged']=staged
    return result


def _run_update_native_driver_tree(root, runtime, hives, payloads, population, analysis, version):
    # Native emulator/registry state and publication inventories die with this
    # frame. Do not retain a transaction in the caller during the global file
    # hierarchy/FileMap construction: each phase is independently substantial.
    transaction=prepare_update_driver_session(root,payloads,population,analysis,version)
    transaction['start']()
    transaction['finish']()
    return transaction['publish'](runtime,hives)
