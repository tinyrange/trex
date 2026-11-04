"""Final FileMap security from the observed native WCP default pair.

This is a final metadata constructor, not token acquisition or a shortcut that
copies a resident map's permissions. Creation's default DACL is overwritten by
this complete setter; the bounded new-map path establishes absence of labels.
"""

load("@stdlib//windows/servicing:runtime.star", "build_servicing_file_security_request", "assign_servicing_file_security")


def prepare_update_filemap_security(root, planned):
    """Prepare FileMap descriptors from the actual parent and planned records, preserving native audit and integrity-label semantics."""
    parent = root.get_security("/Windows/WinSxS/FileMaps")
    ancestor = windows.security_descriptor_parts(parent)
    # The native FileMaps creation control has a noninheriting audit SACL.
    # A SYSTEM-integrity subject supplies no new label. Thus the final result
    # has no dependency on the unavailable token-default creation DACL.
    if ancestor["sacl"] != None:
        for entry in windows.acl_entries(ancestor["sacl"])["entries"]:
            if entry["type"] != 2 or entry["flags"] & 0x1f:
                fail("FileMap creation label/audit inheritance is unsupported")
    ti = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    selected = windows.compile_sddl("O:%sG:%sD:P(A;;FA;;;%s)(A;;GRGX;;;BA)(A;;GRGX;;;SY)(A;;GRGX;;;BU)(A;;GRGX;;;S-1-15-2-1)(A;;GRGX;;;S-1-15-2-2)S:(AU;FASA;0x001f0116;;;WD)" % (ti, ti, ti))
    request = build_servicing_file_security_request(selected, parent)
    if request["security_information"] != 0x9000000f:
        fail("unexpected native FileMap security request")
    result = {}
    for plan in planned["plans"]:
        if plan["operation"] != "write":
            continue
        current = root.get_security(plan["path"]) if root.find(plan["path"]) != None else windows.compile_sddl("O:SYG:SY")
        # The new-file seed denotes only a proven absent prior label; it is
        # deliberately not offered as the transient creation descriptor.
        result[plan["path"]] = assign_servicing_file_security(current, request)
    return result
