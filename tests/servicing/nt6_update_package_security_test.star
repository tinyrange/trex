"""CBS publication keeps protected MUM policy distinct from catalog staging."""
load("//tests:testing.star", "case", "equal", "raises", "run", "suite")
policy = testing.module("@stdlib//windows/servicing:package_security.star")
catalogs = testing.module("@stdlib//windows/servicing:catalogs.star")

def _fixture():
    root = directory()
    root.mkdir("/Windows/servicing/Packages")
    ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    root.set_security("/Windows/servicing/Packages", windows.compile_sddl("O:%sG:%sD:PAI(A;OICI;FA;;;%s)" % (ti,ti,ti)))
    return root

def test_manifest_creation_and_existing_metadata():
    root = _fixture()
    old = "/Windows/servicing/Packages/Existing.MUM"
    preserved = windows.compile_sddl("O:SYG:SYD:P(A;;FR;;;SY)")
    root.write(old, "old")
    root.set_security(old, preserved)
    fixtures = testing.module("//tests/servicing:nt6_package_store_test.star")
    unused_root, unused_name, unused_closure, population, unused_catalogs = fixtures["_resolved_fixture"]()
    prepared = dict(files=[("existing", "replacement", "cat"), ("new", "new mum", "new cat")], summary=dict(catalogs=2))
    catalogs["apply_package_catalogs"](root, None, None, population, prepared=prepared)
    equal(root.find(old).read(), "replacement")
    equal(root.get_security(old), preserved)
    parts = windows.security_descriptor_parts(root.get_security("/Windows/servicing/Packages/new.mum"))
    equal(parts["control"], 0x9c14)
    entries = windows.acl_entries(parts["dacl"])["entries"]
    equal([(windows.sid_string(e["sid"]), e["mask"], e["flags"]) for e in entries[1:3]], [("S-1-5-18", 0x1200a9, 0), ("S-1-5-32-544", 0x1200a9, 0)])
    audit = windows.acl_entries(parts["sacl"])["entries"]
    equal([(e["type"], e["flags"], e["mask"]) for e in audit], [(2, 0xc0, 0x1f0116)])
    # A metadata-only catalog retains resource protection; installed catalogs
    # take the distinct staged policy, without the MUM audit ACE.
    equal(root.get_security("/Windows/servicing/Packages/new.cat"), root.get_security("/Windows/servicing/Packages/new.mum"))
    staged = windows.security_descriptor_parts(policy["new_package_catalog_security"](root, True))
    equal(staged["control"], 0x9014)
    equal(staged["sacl"], None)
    equal(root.get_metadata("/Windows/servicing/Packages/new.cat").hard_link_id, root.get_metadata("/Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}/new.cat").hard_link_id)

def test_publication_preflight_rejects_unprotected_parent():
    root = _fixture()
    root.set_security("/Windows/servicing/Packages", windows.compile_sddl("O:BAG:BAD:(A;;FA;;;BA)"))
    prepared = dict(files=[("new", "mum", "cat")], summary=dict(catalogs=1))
    raises(catalogs["apply_package_catalogs"], args=[root, None, None, None], kwargs=dict(prepared=prepared), message="protected TrustedInstaller")
    equal(root.find("/Windows/servicing/Packages/new.mum"), None)
    equal(root.find("/Windows/servicing/Packages/new.cat"), None)

TEST_SUITE = suite("nt6_update_package_security", [case("manifest_publication", test_manifest_creation_and_existing_metadata), case("preflight", test_publication_preflight_rejects_unprotected_parent)])
def main(args):
    run([TEST_SUITE])
