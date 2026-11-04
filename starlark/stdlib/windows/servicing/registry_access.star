"""Bounded existing-key access policy for the declared offline driver subject.

This is not a general Windows token/authorization service. The driver session
uses a non-restricted SYSTEM subject, enabled BA/WD/AU groups, high integrity,
and no privilege-based ordinary-open grants. Unknown ACEs or higher-integrity
objects stop construction rather than silently relaxing access.
"""

def _registry_mask(mask):
    mapped = mask & 0x0fffffff
    for bit, rights in [(0x80000000, 0x20019), (0x40000000, 0x20006), (0x20000000, 0x20019), (0x10000000, 0xf003f)]:
        if mask & bit:
            mapped |= rights
    if mapped & ~0x20f003f:
        fail("unsupported ordinary registry access rights")
    return mapped


def update_driver_key_open_access(machine, request):
    """Evaluate driver registry access against an established descriptor and request; return granted access or denial."""
    security = request["security"]
    if security == None:
        fail("driver registry open requires an established key descriptor")
    parts = windows.security_descriptor_parts(security)
    if parts["resource_manager_control"]:
        fail("unsupported registry resource-manager security policy")
    # Audit ACEs do not grant rights. Mandatory labels above this subject's
    # declared high integrity require a separate, established policy.
    if parts["sacl"] != None:
        for ace in windows.acl_entries(parts["sacl"])["entries"]:
            if ace["flags"] & 8:
                continue
            if ace["type"] == 2:
                continue
            if ace["type"] != 0x11 or ace["mask"] & ~7:
                fail("unsupported registry system ACE")
            sid = windows.sid_string(ace["sid"])
            if not sid.startswith("S-1-16-") or int(sid[7:]) > 0x3000:
                fail("registry object exceeds established driver integrity policy")
    desired = _registry_mask(request["access"])
    maximum = bool(desired & 0x2000000)
    desired &= ~0x2000000
    owner = windows.sid_string(parts["owner"]) if parts["owner"] != None else ""
    entries = windows.acl_entries(parts["dacl"])["entries"] if parts["dacl"] != None else []
    owner_rights = False
    for ace in entries:
        if ace["flags"] & 8:
            continue
        if ace["type"] not in [0, 1]:
            fail("unsupported registry discretionary ACE")
        if windows.sid_string(ace["sid"]) == "S-1-3-4":
            owner_rights = True
    granted = 0x60000 if owner == "S-1-5-18" and not owner_rights else 0
    denied = 0
    if parts["dacl"] == None:
        granted = 0xf003f
    for ace in entries:
        if ace["flags"] & 8:
            continue
        sid = windows.sid_string(ace["sid"])
        if sid not in ["S-1-5-18", "S-1-5-32-544", "S-1-1-0", "S-1-5-11"] and not (sid == "S-1-3-4" and owner == "S-1-5-18"):
            continue
        mask = _registry_mask(ace["mask"])
        if mask & 0x2000000:
            fail("MAXIMUM_ALLOWED is not a concrete ACE grant")
        if ace["type"] == 1:
            denied |= mask & ~granted
        else:
            granted |= mask & ~denied
    if desired & ~granted or (maximum and not granted):
        return None
    return granted if maximum else desired
