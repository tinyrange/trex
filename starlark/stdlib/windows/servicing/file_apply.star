"""Bounded file/FileMap phase orchestration; not complete CBS servicing."""

load("@stdlib//windows/servicing:files.star", "prepare_update_file_hierarchy", "plan_update_filemaps", "apply_update_filemaps")
load("@stdlib//windows/servicing:file_commit.star", "plan_update_directories", "plan_update_file_commits", "apply_update_directories", "apply_update_file_commits", "image_path_names")
load("@stdlib//windows/servicing:file_stage.star", "stage_update_payload_files", "resolve_update_source_paths")
load("@stdlib//windows/servicing:filemap_security.star", "prepare_update_filemap_security")


def apply_update_directory_removals(root, prepared, names):
    """Remove changed empty directories bottom-up only when no FileMap ownership remains; return removed and retained-owned paths."""
    # Preserve the pre-commit casing of directories that have just become
    # empty; reconstructing names solely from remaining files loses them.
    removed = []
    retained = []
    for depth, path in sorted([(p.count("/"), p) for p in prepared["hierarchy"]], reverse=True):
        node = prepared["hierarchy"][path]
        if path == "/" or node["kind"] != "directory" or not node["subtree_changed"]:
            continue
        if not node["implicit"] and node["after"]["state"] != 0:
            continue
        actual = names.get(path, path)
        if not testing.attempt(root.get_metadata,args=[actual]).ok or root.list_dir(actual):
            continue
        map_path = "/Windows/WinSxS/FileMaps/" + windows.cdf_filemap_name(path)
        resident = root.find(names.get(map_path.lower(), map_path))
        if resident != None:
            # An extant map is ownership, not an invitation to prune an empty
            # physical directory. LUA must remove that ownership first.
            windows.cdf_filemap(resident.bytes())
            retained.append(actual)
            continue
        root.rmdir(actual)
        removed.append(actual)
    return dict(removed=removed, retained_owned=retained)


def prepare_and_apply_update_file_effects(root, runtime, hives, payloads, audit_payloads=False):
    """Plan hierarchy and directories, stage payloads, and apply ordered file/FileMap effects on root; this is a mutating phase, not complete servicing."""
    prepared = prepare_update_file_hierarchy(runtime, hives)
    directories = plan_update_directories(root, prepared)
    staged = stage_update_payload_files(root, payloads)
    result = _apply_prepared_update_file_effects(root, prepared, directories, payloads, audit_payloads=audit_payloads)
    result["staged"] = staged
    return result


def prepare_and_apply_staged_update_file_effects(root, runtime, hives, payloads, while_verifying=None, audit_payloads=False):
    """Commit existing hash-qualified sources without recreating their objects.

    Native driver staging may already own links, EAs and final file metadata.
    Replaying payload staging here would unlink those real objects. This entry
    plans from the actual current tree; source bindings/security and mutable
    projections are checked without eagerly reading every payload.
    """
    prepared = prepare_update_file_hierarchy(runtime, hives)
    directories = plan_update_directories(root, prepared)
    print("runtime file hierarchy prepared",len(prepared["hierarchy"]))
    return _apply_prepared_update_file_effects(root, prepared, directories, payloads, while_verifying=while_verifying, audit_payloads=audit_payloads)


def _apply_prepared_update_file_effects(root, prepared, directories, payloads, while_verifying=None, audit_payloads=False):
    sources = resolve_update_source_paths(root, prepared, payloads)
    files = plan_update_file_commits(root, prepared, sources, directories, while_verifying=while_verifying, audit_payloads=audit_payloads)
    maps = plan_update_filemaps(root, prepared)
    security = prepare_update_filemap_security(root, maps)
    directory_effects = apply_update_directories(root, directories)
    preliminary = apply_update_file_commits(root, files, 1)
    lua = apply_update_filemaps(root, maps, security)
    final = apply_update_file_commits(root, files, 2)
    removed = apply_update_directory_removals(root, prepared, directories["names"])
    return dict(payload_audit="completed" if audit_payloads else "not-performed", directories=directory_effects, preliminary=preliminary, filemaps=lua, final=final, removed_directories=removed,
        scope="file/FileMap phase; other effects are applied by the caller",
        policy="native file and LUA effects only; no package completion is inferred")
