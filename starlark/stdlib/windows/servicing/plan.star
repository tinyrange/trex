"""Plan package phases without mutating an image or selecting product policy.

The caller supplies one immutable baseline and explicit metadata closure.
A successful plan is admission evidence, NOT a completed CBS transaction.
"""

load("@stdlib//windows/servicing:population.star", "plan_servicing_population")
load("@stdlib//windows/servicing:package_store.star", "package_metadata_executions")


def plan_package_phases(base, image, closure, hives=None, work_limit=2097152):
    """Return install population and a compact, independently owned closure.

    StageChain ordering is captured before install planning. Both phases use
    the same baseline and complete closure; only afterward are unused MUMs and
    decoded XML released from the returned record. The input closure is not
    modified. Equal-state admitted wrappers remain present even when their
    final action is a no-op. Missing closed metadata fails rather than silently
    manufacturing a package disposition.

    No payload staging, registry publication, emulation, VM boot, network
    selection, or host output occurs here. Source objects may retain lazy
    readers; keep their backing capabilities alive through construction.
    """
    stage = plan_servicing_population(base, image, closure, hives=hives,
        phase="stage", work_limit=work_limit).deployment_plan()
    catalog_hint_packages = [e.package for e in stage.executions]
    stage = None
    population = plan_servicing_population(base, image, closure, hives=hives,
        work_limit=work_limit).deployment_plan()
    needed = {a.package.lower(): True for a in population.deployment_actions(changed_only=True)}
    needed.update({e.package.lower(): True for e in package_metadata_executions(population, list(closure["files"]))})
    files = {name: file for name, file in closure["files"].items() if name.lower() in needed}
    if {name.lower(): True for name in files} != needed:
        fail("validated deployment action lacks its closed package metadata")
    compact = dict(closure, files=files, xmls=None, catalog_hint_packages=catalog_hint_packages)
    return dict(population=population, closure=compact)
