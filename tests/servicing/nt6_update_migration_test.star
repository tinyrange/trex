"""Migration membership and immutable-source publication checks."""
load('//tests:testing.star','case','equal','raises','suite')
m=testing.module('@stdlib//windows/servicing:migration.star')

def test_membership():
    content=m['_rewrite'](['keep.manifest','old.manifest','removed.manifest'],['OLD.manifest','removed.manifest'],['new.manifest','keep.manifest'])
    equal(m['_entries'](content),['keep.manifest','new.manifest'])
    raises(m['_entries'],args=['<migrationManifests><file>a.manifest</file><file>A.manifest</file></migrationManifests>'],message='duplicate')
    raises(m['_entries'],args=['<migrationManifests><file>../a.manifest</file></migrationManifests>'],message='invalid')
    raises(m['_entries'],args=['<migrationManifests xmlns="foreign"/>'],message='unsupported')

def _fixture():
    root=directory()
    path='/Windows/WinSxS/migration.xml'
    root.write(path,'<migrationManifests/>')
    root.set_security(path,windows.compile_sddl('O:SYG:SYD:(A;;FA;;;SY)'))
    root.write('/source','encoded')
    plan=dict(path=path,source_hash=digest(root.find(path)),order=root.get_metadata(path).write_order,security=root.get_security(path),proofs=[dict(path='/source',hash=digest(root.find('/source')))],content='<migrationManifests><file>new.manifest</file></migrationManifests>',before=0,after=1,removed=0,added=1)
    return root,plan

def test_preflight():
    root,plan=_fixture()
    root.write('/source','changed')
    raises(m['apply_update_migration'],args=[root,plan],message='source changed')
    equal(digest(root.find(plan['path'])),plan['source_hash'])
    root,plan=_fixture()
    root.write(plan['path'],'concurrent')
    raises(m['apply_update_migration'],args=[root,plan],message='index changed')
    root,plan=_fixture()
    equal(m['apply_update_migration'](root,plan),dict(before=0,after=1,removed=0,added=1))
    equal(root.get_security(plan['path']),plan['security'])
    equal(m['_entries'](root.find(plan['path'])),['new.manifest'])

TEST_SUITE=suite('nt6_update_migration',[case('membership',test_membership),case('source_preflight',test_preflight)])
