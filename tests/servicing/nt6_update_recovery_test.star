"""Recovery hardlink publication and physical CSI-marker guards."""
load('//tests:testing.star','case','equal','raises','suite')
m=testing.module('@stdlib//windows/servicing:recovery.star')

def fixture():
    root=directory()
    component='/Windows/WinSxS/new'
    root.mkdir(component)
    sd=windows.compile_sddl('O:SYG:SYD:AI(A;OICI;FA;;;SY)')
    root.set_security(component,sd)
    source='/Windows/WinSxS/old/r/file.bin'
    installed=component+'/nested/file.bin'
    root.write(source,'record')
    root.set_security(source,sd)
    root.set_file_attributes(source,32)
    root.write(installed,'installed')
    row=dict(source=source,installed=installed,path=component+'/r/nested/file.bin',stem='new',key='f!file.bin',
        record_hash=digest(root.find(source),algorithm='sha256'),order=root.get_metadata(source).write_order,
        installed_order=root.get_metadata(installed).write_order)
    return root,row

def test_link_security_and_physical_flags():
    root,row=fixture()
    markers=m['apply_inherited_recovery'](root,[row])
    equal(root.find(row['path']).read(),'record')
    equal(root.get_metadata(row['path']).hard_link_id,root.get_metadata(row['source']).hard_link_id)
    equal(root.get_security(row['path']),root.get_security(row['source']))
    equal(root.get_metadata(row['path']).file_attributes,32)
    payloads=dict(retained_recovery=markers)
    equal(m['retained_recovery_flags'](root,payloads,'new','f!file.bin',1),0x101)
    equal(m['retained_recovery_flags'](root,payloads,'new','f!other',1),1)
    root.remove(row['path'])
    raises(m['retained_recovery_flags'],args=[root,payloads,'new','f!file.bin',1],message='changed before CSI persistence')

def test_source_or_destination_change_prevents_publication():
    for change in ['source','installed','path']:
        root,row=fixture()
        root.write(row[change],'changed')
        raises(m['apply_inherited_recovery'],args=[root,[row]],message='changed')
        if change!='path': equal(root.find(row['path']),None)

def test_same_length_record_replacement_rejects_marker():
    root,row=fixture()
    markers=m['apply_inherited_recovery'](root,[row])
    root.remove(row['path'])
    root.write(row['path'],'broken')
    raises(m['retained_recovery_flags'],args=[root,dict(retained_recovery=markers),'new','f!file.bin',1],message='changed before CSI persistence')

def generated_fixture():
    root,row=fixture()
    row['file']=root.find(row['source'])
    row['security']=root.get_security(row['source'])
    row['attributes']=32
    return root,row

def test_generated_independent_file_and_marker():
    root,row=generated_fixture()
    markers=m['apply_generated_recovery'](root,[row])
    equal(root.find(row['path']).read(),'record')
    equal(root.get_security(row['path']),row['security'])
    equal(root.get_metadata(row['path']).file_attributes,32)
    root.remove(row['source'])
    root.write(row['source'],'changed')
    equal(root.find(row['path']).read(),'record')
    equal(m['retained_recovery_flags'](root,dict(retained_recovery=markers),'new','f!file.bin',1),0x101)

def test_generated_batch_preflight():
    for change in ['installed','path','record']:
        root,row=generated_fixture()
        later=dict(row)
        later['path']=row['path']+'.second'
        later['key']='f!second'
        if change=='record':
            later['record_hash']=b'wrong'
        elif change=='installed':
            later['installed']=row['installed']+'.second'
            root.write(later['installed'],'changed')
        else:
            root.write(later['path'],'collision')
        raises(m['apply_generated_recovery'],args=[root,[row,later]],message='changed')
        equal(root.find(row['path']),None)
    root,row=generated_fixture()
    raises(m['apply_generated_recovery'],args=[root,[row,row]],message='destination changed')
    equal(root.find(row['path']),None)

def test_deferred_marker_rejects_same_length_replacement():
    root,row=generated_fixture()
    row['record_hash']=None
    markers=m['apply_generated_recovery'](root,[row])
    equal(m['retained_recovery_flags'](root,dict(retained_recovery=markers),'new','f!file.bin',1),0x101)
    root.remove(row['path'])
    root.write(row['path'],'xxxxxx')
    raises(m['retained_recovery_flags'],args=[root,dict(retained_recovery=markers),'new','f!file.bin',1],message='changed before CSI persistence')

TEST_SUITE=suite('nt6_update_recovery',[
    case('deferred_marker_rejects_same_length_replacement',test_deferred_marker_rejects_same_length_replacement),
    case('generated_independent_file_and_marker',test_generated_independent_file_and_marker),
    case('generated_batch_preflight',test_generated_batch_preflight),
    case('link_security_and_physical_flags',test_link_security_and_physical_flags),
    case('source_or_destination_change_prevents_publication',test_source_or_destination_change_prevents_publication),
    case('same_length_record_replacement_rejects_marker',test_same_length_record_replacement_rejects_marker),
])
