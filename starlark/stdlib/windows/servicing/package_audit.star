"""Read-only package-state provenance audit; never repair or downgrade state."""

_CBS = "/Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages/"

def _packages(software):
    hive = windows.hive(software)
    parent = hive.find(_CBS.rstrip("/"))
    if parent == None:
        fail("package audit requires a CBS package inventory")
    result = {}
    for key in parent.children:
        owners = hive.find(_CBS + key.name + "/Owners")
        result[key.name.lower()] = dict(package=key.name, state=key.values.get("CurrentState"),
            owners=dict(owners.values) if owners != None else {})
    return result

def audit_package_states(root, source_software, publication, recipe_state):
    """Account for EVERY final package, including native non-installed entries.

    State provenance is not independent payload/installer validation. Report
    concrete metadata contradictions separately; never infer missing effects
    from a missing timestamp, an unrun check or a constructed state value.
    """
    source = _packages(source_software)
    actual = _packages(root.find("/Windows/System32/config/SOFTWARE"))
    published = {p["package"].lower(): p for p in publication["dispositions"]}
    explicit = {}
    for patch in recipe_state["patches"]:
        key = patch["key"]
        if patch.get("hive") == "SOFTWARE" and key.lower().startswith(_CBS.lower()) and patch["name"].lower() == "currentstate":
            explicit[key[len(_CBS):].lower()] = patch["value"]
    removed = {key.lower():True for key in recipe_state.get("excluded_hive_subtrees", {}).get("SOFTWARE", [])}
    rows, issues, counts = [], [], {}
    for name, row in sorted(actual.items()):
        prior = source.get(name)
        new = published.get(name)
        evidence = "unchanged source-media disposition"
        expected = prior["state"] if prior != None else None
        expected_owners = prior["owners"] if prior != None else None
        if new != None:
            expected, expected_owners = new["state"], new["owners"]
            evidence = new["evidence"]
        if name in explicit:
            expected = explicit[name]
            evidence = "explicit recipe removal; exact ownership/pin/payload guards in recall.star"
            # Compare all owner writes in this explicit recipe rather than
            # requiring the deliberately removed staging owner to stay staged.
            expected_owners = dict(expected_owners or {})
            for patch in recipe_state["patches"]:
                if patch.get("hive") == "SOFTWARE" and patch["key"].lower() == (_CBS + row["package"] + "/Owners").lower():
                    expected_owners[patch["name"]] = patch["value"]
        findings = []
        if expected == None:
            findings.append("no source/admission/removal provenance for published state")
        elif row["state"] != expected:
            findings.append("published state differs from source/admitted/removal disposition")
        if expected_owners != None and {k.lower():v for k,v in row["owners"].items()} != {k.lower():v for k,v in expected_owners.items()}:
            findings.append("published owners differ from source/admitted/removal disposition")
        for extension in [".mum", ".cat"]:
            if root.find("/Windows/servicing/Packages/" + row["package"] + extension) == None:
                findings.append("registered package missing " + extension + " metadata")
        if findings:
            issues.append(dict(package=row["package"], findings=findings))
        bucket = str(row["state"])
        counts[bucket] = counts.get(bucket, 0) + 1
        rows.append(dict(row, source_state=prior["state"] if prior != None else None,
            admitted_state=new["state"] if new != None else None, evidence=evidence, findings=findings))
    removals = []
    all_names = dict(source)
    all_names.update(published)
    for name in sorted(all_names):
        if name not in actual:
            package = (source.get(name) or published[name])["package"]
            documented = (_CBS + package).lower() in removed
            removals.append(dict(package=package, explicit_recipe_removal=documented))
            if not documented:
                issues.append(dict(package=package, findings=["package registration disappeared without explicit recipe removal"]))
    return dict(packages=len(rows), counts=counts, source_packages=len(source),
        published_packages=len(published), rows=rows, removals=removals, issues=issues,
        scope="all final CBS package states, owners, MUM/catalog presence and source/admission/removal provenance; not a full per-file or installer execution audit")
