"""Protection for newly published CBS package manifests and catalogs.

CBS package publication is not WCP payload staging: the former keeps the
protected resource ACL and audit policy, including auto-inheritance controls.
Catalogs with installed deployments take WCP staging protection instead.
Neither constructor replaces the security of already resident objects.
"""


load("@stdlib//windows/servicing:runtime.star", "assign_servicing_staged_file_security", "build_servicing_staged_file_security_request")

def new_package_catalog_security(root, installed):
    """Derive the native staged catalog descriptor from the actual destination parent."""
    if not installed:
        return new_package_manifest_security(root)
    return assign_servicing_staged_file_security(windows.compile_sddl("O:SYG:SY"), build_servicing_staged_file_security_request(root.get_security("/Windows/servicing/Packages")))

def new_package_manifest_security(root):
    """Derive the native staged package-manifest descriptor from the actual destination parent."""
    # Require the target's protected servicing directory, not an arbitrary
    # writable staging location. This policy is independent of reference WIMs.
    parent = root.get_security("/Windows/servicing/Packages")
    if parent == None:
        fail("package manifest publication requires protected Packages directory")
    parts = windows.security_descriptor_parts(parent)
    ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    if parts["owner"] == None or windows.sid_string(parts["owner"]) != ti or not parts["control"] & 0x1000:
        fail("package manifest publication requires protected TrustedInstaller parent")
    # File rights, not unmapped GENERIC_READ/EXECUTE. SY precedes BA here;
    # the staged CSI catalog policy has the opposite order and no audit ACE.
    return windows.compile_sddl("O:%sG:%sD:PAI(A;;FA;;;%s)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;S-1-15-2-1)(A;;0x1200a9;;;S-1-15-2-2)S:AI(AU;FASA;0x001f0116;;;WD)" % (ti, ti, ti))
