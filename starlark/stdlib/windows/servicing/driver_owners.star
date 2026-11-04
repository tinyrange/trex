"""Ordinary CBS driver owner mutations, independently verified against native CBS.

The pinned 26100.9703 Add/RemoveDriver owner controls (RVAs 10f9d4/10a234)
establish first/last owner results and zero-valued additions. All 1,648 update
operations were compared to native output. This constructs those same physical
keys, preserving literal Base64 components and unrelated values/security.
It is NOT driver installation: callers publish only with the completed matching
driver-store transaction. No package state, privileges or completion flags change.
"""
load('@stdlib//windows/servicing:registry_effects.star','build_update_driver_key_security')

def order_update_driver_owner_operations(operations):
    """Ordinary forward DOQ execution, not queue registration order.

    CBS9703 DoqExecuteImmediate 10dfed..10e06e installs noncritical then
    critical groups before either uninstall pass. DoqIsCritical 10bb98
    groups every case-insensitive INF match with a CRITDOQ- update; the
    update prefix comparison at 12b892 is case-sensitive wcsncmp.
    Input is the already reduced, uncompleted queue in sequence order.
    """
    critical = {}
    for row in operations:
        if row['kind'] not in [0, 1] or row.get('canceled', False):
            fail('owner execution requires reduced ordinary driver operations')
        update = row['owner'].rsplit('~', 1)
        if len(update) != 2 or not update[1]:
            fail('owner execution requires an exact package~update owner')
        if update[1].startswith('CRITDOQ-'):
            critical[row['inf'].lower()] = True
    return [row for kind in [0, 1] for is_critical in [False, True] for row in operations if row['kind'] == kind and (row['inf'].lower() in critical) == is_critical]

def plan_update_driver_owners(source, operations):
    """Apply owner primitives in the supplied execution order, without sorting."""
    driver_components=windows.hive(source)
    groups={}
    names={}
    for arch in driver_components.find('/Drivers').children:
        for inf in arch.children:
            for leaf in inf.children:
                if leaf.children: fail('driver owner leaf has unmodeled children')
                key=(arch.name.lower(),inf.name.lower(),leaf.name.lower())
                if key in groups: fail('duplicate physical driver owner key')
                values={}
                for name,record in leaf.value_records.items():
                    if record.type!=4 or len(record.raw)!=4: fail('driver baseline has an unmodeled owner value')
                    values[name.lower()]=(name,record.raw)
                if not values: fail('driver baseline contains an unmodeled empty owner leaf')
                groups[key]=values
                names[key]=(arch.name,inf.name,leaf.name)
    expected={key:dict(values) for key,values in groups.items()}
    outputs=[]
    first=[]
    last=[]
    for row in operations:
        key=(row['architecture'].lower(),row['inf'].lower(),row['hash'].lower())
        values=expected.get(key)
        owner=row['owner'].lower()
        present=values!=None and owner in values
        if row['kind']==0:
            result=(1 if present else 0,1 if values==None else 0)
            if values==None:
                expected[key]={}
                values=expected[key]
                first.append(row)
                names[key]=(row['architecture'],row['inf'],row['hash'])
            if not present: values[owner]=(row['owner'],binary.u32le(0))
        else:
            if present: values.pop(owner)
            result=(1 if present else 0,1 if values else 0)
            if values!=None and not values:
                expected.pop(key)
                last.append(row)
        outputs.append(result)
    print('EXPECTED_NATIVE_OWNER_BATCH',len(outputs),len(first),len(last),len(expected))
    return _prepare_owner_hive(source,groups,expected,names,outputs,first,last)

def _prepare_owner_hive(source, initial, expected, names, outputs, first, last):
    hive=windows.hive(source, snapshot=True)
    patches=[]
    removed=[]
    deleted_values=[]
    keys={}
    retired={(r['architecture'].lower(),r['inf'].lower(),r['hash'].lower()):True for r in last}
    recreated={key:True for key in retired if key in initial and key in expected}
    for key,values in initial.items():
        parts=['Drivers']+list(names[key])
        if key not in expected or key in recreated:
            removed.append(dict(key_parts=parts))
        else:
            for owner,(name,raw) in values.items():
                if owner not in expected[key]:
                    deleted_values.append(dict(key_parts=parts,name=name))
    for key,values in expected.items():
        parts=['Drivers']+list(names[key])
        for depth in range(2,len(parts)+1):
            branch=parts[:depth]
            identity=tuple([p.lower() for p in branch])
            if identity in keys or (hive.find(branch)!=None and not (depth==4 and key in recreated)): continue
            parent_id=identity[:-1]
            parent=keys[parent_id]['security'] if parent_id in keys else hive.find(branch[:-1]).security
            keys[identity]=dict(key_parts=branch,security=build_update_driver_key_security(parent))
        before={} if key in recreated else initial.get(key,{})
        for owner,(name,raw) in values.items():
            if owner not in before or before[owner][1]!=raw:
                patches.append(dict(key_parts=parts,name=name,type=4,value=raw))
    file=windows.patch_hive(source,patches,keys=list(keys.values()),delete_keys=removed,delete_values=deleted_values)
    after=windows.hive(file, snapshot=True)
    actual={}
    for arch in after.find('/Drivers').children:
        for inf in arch.children:
            for leaf in inf.children:
                identity=(arch.name.lower(),inf.name.lower(),leaf.name.lower())
                if identity in actual or leaf.children: fail('driver ownership readback has an unexpected shape')
                actual[identity]={n.lower():(v.type,v.raw) for n,v in leaf.value_records.items()}
                prior=hive.find(['Drivers',arch.name,inf.name,leaf.name])
                descriptor=prior.security if prior!=None and identity not in recreated else keys[('drivers',)+identity]['security']
                if leaf.security!=descriptor: fail('driver ownership security readback disagrees')
    wanted={key:{owner:(4,value[1]) for owner,value in values.items()} for key,values in expected.items()}
    if actual!=wanted: fail('complete driver owner inventory disagrees with the native plan')
    for key in keys.values():
        if after.find(key['key_parts']).security!=key['security']: fail('driver owner parent security readback disagrees')
    return dict(source_sha256=digest(source,algorithm='sha256'),file=file,outputs=outputs,first=first,last=last,leaves=len(expected),new_keys=len(keys),set_values=len(patches),deleted_values=len(deleted_values),removed_keys=len(removed))

def apply_update_driver_owners(root, plan):
    """Require the original COMPONENTS digest before publishing the prepared owner hive; return owner-change counts."""
    path='/Windows/System32/config/COMPONENTS'
    if digest(root.find(path),algorithm='sha256')!=plan['source_sha256']:
        fail('driver owner source changed before publication')
    root.write(path,plan['file'])
    return {k:plan[k] for k in ['leaves','new_keys','set_values','deleted_values','removed_keys']}
