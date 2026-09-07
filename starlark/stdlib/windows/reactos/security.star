"""Declarative ReactOS account and local-security policy, without hive templates."""

load("@stdlib//windows:security.star", "sid", "acl", "access_allowed_ace", "security_descriptor", "des_56_key")

ADMINISTRATOR_RID = 500
GUEST_RID = 501
PRIMARY_GROUP_RID = 513
BUILTIN_SID = "S-1-5-32"
ADMINISTRATORS_SID = BUILTIN_SID + "-544"
SYSTEM_SID = "S-1-5-18"
EVERYONE_SID = "S-1-1-0"
NT_TIME_NEVER = (1 << 63) - 1
NT_RELATIVE_NEVER = -(1 << 63)
NT_TICKS_PER_SECOND = 10000000
# Conversion between the portable Unix clock and NT FILETIME.
_UNIX_EPOCH_IN_NT_SECONDS = 11644473600
GROUP_ATTRIBUTES = {"mandatory": 1, "enabled_by_default": 2, "enabled": 4}
ACCOUNT_FLAGS = {"disabled": 1, "password_not_required": 4, "normal": 16, "password_never_expires": 512}
LOGON_RIGHTS = {
    "interactive": 1, "network": 2, "batch": 4, "service": 16,
    "deny_interactive": 64, "deny_network": 128, "deny_batch": 256,
    "deny_service": 512, "remote_interactive": 1024, "deny_remote_interactive": 2048,
}
PRIVILEGES = {
    "SeCreateTokenPrivilege": 2, "SeAssignPrimaryTokenPrivilege": 3,
    "SeLockMemoryPrivilege": 4, "SeIncreaseQuotaPrivilege": 5,
    "SeTcbPrivilege": 7, "SeSecurityPrivilege": 8, "SeTakeOwnershipPrivilege": 9,
    "SeLoadDriverPrivilege": 10, "SeSystemProfilePrivilege": 11,
    "SeSystemtimePrivilege": 12, "SeProfileSingleProcessPrivilege": 13,
    "SeIncreaseBasePriorityPrivilege": 14, "SeCreatePagefilePrivilege": 15,
    "SeCreatePermanentPrivilege": 16, "SeBackupPrivilege": 17,
    "SeRestorePrivilege": 18, "SeShutdownPrivilege": 19, "SeDebugPrivilege": 20,
    "SeAuditPrivilege": 21, "SeSystemEnvironmentPrivilege": 22,
    "SeChangeNotifyPrivilege": 23, "SeRemoteShutdownPrivilege": 24,
    "SeUndockPrivilege": 25, "SeSyncAgentPrivilege": 26,
    "SeEnableDelegationPrivilege": 27, "SeManageVolumePrivilege": 28,
    "SeImpersonatePrivilege": 29, "SeCreateGlobalPrivilege": 30,
}
PRIVILEGE_ATTRIBUTES = {"enabled_by_default": 1, "enabled": 2}

# MS-SAMR/MS-LSAD object access masks. Recipes use read/all/change_password.
_READ_CONTROL = 1 << 17
_STANDARD_REQUIRED = (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19)
_OBJECT_ACCESS = {
    "server": {"read": _READ_CONTROL | 1 | 16 | 32, "all": _STANDARD_REQUIRED | 63},
    "domain": {"read": _READ_CONTROL | 1 | 4 | 128 | 256 | 512, "all": _STANDARD_REQUIRED | 2047},
    "user": {"read": _READ_CONTROL | 1 | 2 | 8 | 16 | 64 | 256 | 512, "all": _STANDARD_REQUIRED | 2047, "change_password": _READ_CONTROL | 4 | 64},
    "group": {"read": _READ_CONTROL | 1 | 16, "all": _STANDARD_REQUIRED | 31},
    "alias": {"read": _READ_CONTROL | 4 | 8, "all": _STANDARD_REQUIRED | 31},
    "policy": {"read": _READ_CONTROL | 1 | 2048, "all": _STANDARD_REQUIRED | 8191},
    "account": {"read": _READ_CONTROL, "all": _STANDARD_REQUIRED | 15},
}

def _flags(names, table):
    result = 0
    for name in names:
        if name not in table:
            fail("unknown flag/right " + name)
        result |= table[name]
    return result

def _sid(text):
    parts = text.split("-")
    if len(parts) < 4 or parts[:2] != ["S", "1"] or len(parts) > 18:
        fail("invalid SID " + text)
    numbers = [int(part) for part in parts[2:]]
    if any([str(number) != part for number, part in zip(numbers, parts[2:])]):
        fail("SID must use canonical decimal spelling")
    return sid(numbers[0], numbers[1:])

def _fields(record, allowed):
    unknown = [key for key in record if key not in allowed]
    if unknown:
        fail("unknown security fields: " + str(unknown))

def _name(name):
    if not name or name in [".", ".."] or name != name.strip() or any([character in name for character in ["/", "\\", "\x00", ":", "*", "?", "\"", "<", ">", "|"]]):
        fail("invalid account name")
    return name

def _descriptor(kind, specification = None):
    specification = specification if specification != None else {
        "owner": ADMINISTRATORS_SID, "group": ADMINISTRATORS_SID,
        "allow": [
            {"sid": SYSTEM_SID, "rights": ["all"]},
            {"sid": ADMINISTRATORS_SID, "rights": ["all"]},
            {"sid": EVERYONE_SID, "rights": ["read"]},
        ],
    }
    _fields(specification, ["owner", "group", "allow"])
    aces = []
    for entry in specification["allow"]:
        _fields(entry, ["sid", "rights"])
        aces.append(access_allowed_ace(_sid(entry["sid"]), _flags(entry["rights"], _OBJECT_ACCESS[kind])))
    return security_descriptor(owner = _sid(specification["owner"]), group = _sid(specification["group"]), dacl = acl(aces))

def workstation_security(domain_sid, domain_name, workgroup = "WORKGROUP", administrator_password = "", creation_time = None):
    """Returns mutable, explicit defaults; customize this record before building."""
    creation_time = creation_time if creation_time != None else (_UNIX_EPOCH_IN_NT_SECONDS + clock.unix()) * NT_TICKS_PER_SECOND
    return {
        "domain_sid": domain_sid, "domain_name": domain_name, "workgroup": workgroup,
        "domain_policy": {
            "creation_time": creation_time,
            "next_rid": 1000, "maximum_password_age": -42 * 24 * 3600 * NT_TICKS_PER_SECOND,
            "minimum_password_age": 0, "force_logoff": NT_RELATIVE_NEVER,
            "lockout_duration": -30 * 60 * NT_TICKS_PER_SECOND,
            "lockout_observation_window": -30 * 60 * NT_TICKS_PER_SECOND,
        },
        "users": [
            {"name": "Administrator", "rid": ADMINISTRATOR_RID, "password": administrator_password,
             "flags": ["normal", "password_never_expires"], "primary_group": PRIMARY_GROUP_RID},
            {"name": "Guest", "rid": GUEST_RID, "password": "",
             "flags": ["normal", "password_never_expires", "disabled", "password_not_required"], "primary_group": PRIMARY_GROUP_RID},
        ],
        "groups": [{"name": "None", "rid": PRIMARY_GROUP_RID, "members": [ADMINISTRATOR_RID, GUEST_RID]}],
        "aliases": [
            {"name": name, "rid": rid, "members": members}
            for name, rid, members in [
                ("Administrators", 544, [domain_sid + "-500"]),
                ("Users", 545, []), ("Guests", 546, [domain_sid + "-501"]),
                ("Power Users", 547, []), ("Backup Operators", 551, []),
                ("Replicator", 552, []), ("Remote Desktop Users", 555, []),
                ("Network Configuration Operators", 556, []),
            ]
        ],
        "rights": [
            {"sid": EVERYONE_SID, "logon": ["interactive", "network", "remote_interactive"],
             "privileges": [{"name": "SeChangeNotifyPrivilege", "attributes": ["enabled", "enabled_by_default"]}, {"name": "SeShutdownPrivilege", "attributes": ["enabled", "enabled_by_default"]}]},
            {"sid": ADMINISTRATORS_SID, "logon": ["interactive", "network"],
             "privileges": [{"name": name, "attributes": []} for name in [
                 "SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeSystemtimePrivilege",
                 "SeShutdownPrivilege", "SeRemoteShutdownPrivilege", "SeTakeOwnershipPrivilege", "SeDebugPrivilege",
                 "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeProfileSingleProcessPrivilege",
                 "SeIncreaseBasePriorityPrivilege", "SeLoadDriverPrivilege", "SeCreatePagefilePrivilege", "SeIncreaseQuotaPrivilege",
             ]]},
        ],
    }

def _patch(key, name, value, kind = "REG_BINARY"):
    return {"key": key, "name": name, "type": kind, "value": value}

def _rid_key(rid):
    return hex(binary.u32be(rid)).upper()

def _password_hashes(password):
    # Raw hashes are ReactOS SAM fields, not RID-encrypted NT5 V-record data.
    encoded = binary.encode(password.upper(), encoding = "ascii")
    if len(encoded) > 14:
        fail("ReactOS LM-compatible passwords must have at most 14 ASCII bytes")
    padded = bytes_concat([encoded, b"\x00" * (14 - len(encoded))])
    return {
        "LMPwd": bytes_concat([crypto.des(des_56_key(padded[:7]), b"KGS!@#$%"), crypto.des(des_56_key(padded[7:]), b"KGS!@#$%")]),
        "NTPwd": crypto.hash("md4", binary.encode(password, encoding = "utf16le")),
    }

def security_database(specification, hive_format = None):
    """Builds SAM/SECURITY from account records; no host paths or seed templates."""
    _fields(specification, ["domain_sid", "domain_name", "workgroup", "domain_policy", "users", "groups", "aliases", "rights", "descriptors", "audit", "quota"])
    domain_sid = specification["domain_sid"]
    _sid(domain_sid)
    if not domain_sid.startswith("S-1-5-21-") or len(domain_sid.split("-")) != 7:
        fail("account domain requires S-1-5-21 with three domain subauthorities")
    domain_name = _name(specification["domain_name"])
    creation_time = specification.get("domain_policy", {}).get("creation_time")
    if type(creation_time) != "int" or creation_time <= 0 or creation_time > NT_TIME_NEVER:
        fail("domain_policy.creation_time must be a positive NT FILETIME")
    descriptors = specification.get("descriptors", {})
    _fields(descriptors, _OBJECT_ACCESS.keys())
    users, groups, aliases = specification["users"], specification["groups"], specification["aliases"]
    if not users or not groups:
        fail("security requires users and primary groups")
    seen_rids = {}
    for index, collection in enumerate([users + groups, aliases]):
        rids, names = {}, {}
        for entry in collection:
            name, rid = _name(entry["name"]), entry["rid"]
            if type(rid) != "int" or rid <= 0 or rid > 0xffffffff or rid in rids or name.lower() in names:
                fail("duplicate/invalid account RID or name")
            rids[rid], names[name.lower()] = True, True
        if index == 0:
            seen_rids = rids
    user_rids = {u["rid"]: True for u in users}
    group_rids = {g["rid"]: g for g in groups}
    alias_rids = {a["rid"]: True for a in aliases}
    def principal(text):
        _sid(text)
        if text.startswith(domain_sid + "-") and int(text.split("-")[-1]) not in seen_rids:
            fail("membership/right refers to missing local account " + text)
        if text.startswith(BUILTIN_SID + "-") and int(text.split("-")[-1]) not in alias_rids:
            fail("membership/right refers to missing built-in alias " + text)
        return text
    sam = [_patch("/SAM", "SecDesc", _descriptor("server", descriptors.get("server")))]
    keys = []
    account_path = "/SAM/Domains/Account"
    for domain, name, identifier in [("Account", domain_name, domain_sid), ("Builtin", "Builtin", BUILTIN_SID)]:
        base = "/SAM/Domains/" + domain
        policy = {"next_rid": 1000}
        policy.update(specification.get("domain_policy", {}))
        if domain == "Account" and policy.get("next_rid", 1000) <= max(seen_rids.keys()):
            fail("next_rid must exceed allocated account RIDs")
        sam += [
            _patch(base, "F", windows.reactos_record("domain", policy)),
            _patch(base, "SID", _sid(identifier)),
            _patch(base, "SecDesc", _descriptor("domain", descriptors.get("domain"))),
        ]
        for field, text in [("Name", name), ("OemInformation", ""), ("ReplicaSourceNodeName", "")]:
            sam.append(_patch(base, field, text, "REG_SZ"))
        for category in ["Users", "Groups", "Aliases"]:
            keys += [base + "/" + category, base + "/" + category + "/Names"]
    for group in groups:
        _fields(group, ["name", "rid", "members", "description", "descriptor"])
        members = group["members"]
        if len(members) != len({rid: True for rid in members}) or any([rid not in user_rids for rid in members]):
            fail("group members must be distinct existing users")
        base = account_path + "/Groups/" + _rid_key(group["rid"])
        sam += [
            _patch(base, "F", windows.reactos_record("group", {"rid": group["rid"]})),
            _patch(base, "Name", group["name"], "REG_SZ"),
            _patch(base, "AdminComment", group.get("description", ""), "REG_SZ"),
            _patch(base, "Members", bytes_concat([binary.u32le(rid) for rid in members])),
            _patch(base, "SecDesc", _descriptor("group", group.get("descriptor", descriptors.get("group")))),
            _patch(account_path + "/Groups/Names", group["name"], group["rid"], "REG_DWORD"),
        ]
    string_fields = {"full_name": "FullName", "description": "AdminComment", "user_comment": "UserComment", "home_directory": "HomeDirectory", "home_drive": "HomeDirectoryDrive", "script_path": "ScriptPath", "profile_path": "ProfilePath", "workstations": "WorkStations", "parameters": "Parameters"}
    for user in users:
        _fields(user, ["name", "rid", "password", "flags", "primary_group", "descriptor", "expires", "logon_hours", "password_last_set", "must_change_password"] + string_fields.keys())
        rid, primary = user["rid"], user["primary_group"]
        if type(user.get("must_change_password", False)) != "bool":
            fail("must_change_password must be a boolean")
        if primary not in group_rids or rid not in group_rids[primary]["members"]:
            fail("primary group must exist and include its user")
        base = account_path + "/Users/" + _rid_key(rid)
        sam += [
            _patch(base, "F", windows.reactos_record("user", {"rid": rid, "primary_group_rid": primary, "account_control": _flags(user["flags"], ACCOUNT_FLAGS), "account_expires": user.get("expires", NT_TIME_NEVER), "password_last_set": 0 if user.get("must_change_password", False) else user.get("password_last_set", creation_time)})),
            _patch(base, "Name", user["name"], "REG_SZ"),
            _patch(base, "SecDesc", _descriptor("user", user.get("descriptor", descriptors.get("user")))),
            _patch(base, "Groups", windows.reactos_record("group_memberships", {"groups": [{"rid": group["rid"], "attributes": _flags(GROUP_ATTRIBUTES.keys(), GROUP_ATTRIBUTES)} for group in groups if rid in group["members"]]})),
            _patch(base, "LogonHours", windows.reactos_record("logon_hours", {"allowed": user.get("logon_hours", [True] * (7 * 24))})),
            _patch(base, "PrivateData", "", "REG_SZ"),
            _patch(account_path + "/Users/Names", user["name"], rid, "REG_DWORD"),
        ]
        for field, name in string_fields.items():
            sam.append(_patch(base, name, user.get(field, ""), "REG_SZ"))
        for name, value in _password_hashes(user["password"]).items():
            sam += [_patch(base, name, value), _patch(base, name + "History", b"")]
    for alias in aliases:
        _fields(alias, ["name", "rid", "members", "description", "descriptor"])
        if len(alias["members"]) != len({member: True for member in alias["members"]}):
            fail("duplicate alias member")
        base = "/SAM/Domains/Builtin/Aliases/" + _rid_key(alias["rid"])
        keys.append(base + "/Members")
        sam += [
            _patch(base, "Name", alias["name"], "REG_SZ"),
            _patch(base, "Description", alias.get("description", ""), "REG_SZ"),
            _patch(base, "SecDesc", _descriptor("alias", alias.get("descriptor", descriptors.get("alias")))),
            _patch("/SAM/Domains/Builtin/Aliases/Names", alias["name"], alias["rid"], "REG_DWORD"),
        ]
        for member in alias["members"]:
            sam.append(_patch(base + "/Members", principal(member), _sid(member)))
    security = [_patch("/Policy", "(default)", "", "REG_SZ")]
    def policy(name, value):
        security.append(_patch("/Policy/" + name, "(default)", value, 0))
    policy("PolAcDmN", windows.reactos_record("policy_string", {"value": domain_name}))
    policy("PolAcDmS", _sid(domain_sid))
    policy("PolPrDmN", windows.reactos_record("policy_string", {"value": specification.get("workgroup", "WORKGROUP")}))
    for name in ["PolPrDmS", "PolDnDDN", "PolDnTrN"]:
        policy(name, b"")
    policy("PolDnDmG", b"\x00" * 16)
    policy("PolRevision", bytes_concat([binary.u16le(7), binary.u16le(1)]))
    policy("PolState", binary.u32le(0))
    policy("PolMod", windows.reactos_record("policy_modification", {"modified_count": 1}))
    policy("PolAdtEv", windows.reactos_record("policy_audit", specification.get("audit", {"enabled": False, "options": [0] * 9})))
    policy("PolAdtFL", b"\x00\x00")
    policy("DefQuota", windows.reactos_record("policy_quota", specification.get("quota", {"paged_pool": 32 << 20, "non_paged_pool": 1 << 20, "minimum_working_set": 64 << 10, "maximum_working_set": 240 << 20})))
    policy("SecDesc", _descriptor("policy", descriptors.get("policy")))
    rights_seen = {}
    for right in specification["rights"]:
        _fields(right, ["sid", "logon", "privileges", "descriptor"])
        if right["sid"] in rights_seen:
            fail("duplicate policy account")
        rights_seen[right["sid"]] = True
        base = "Accounts/" + principal(right["sid"])
        policy(base + "/Sid", _sid(right["sid"]))
        policy(base + "/ActSysAc", binary.u32le(_flags(right["logon"], LOGON_RIGHTS)))
        policy(base + "/SecDesc", _descriptor("account", right.get("descriptor", descriptors.get("account"))))
        privileges = []
        privilege_names = {}
        for privilege in right["privileges"]:
            _fields(privilege, ["name", "attributes"])
            if privilege["name"] not in PRIVILEGES:
                fail("unknown privilege " + privilege["name"])
            if privilege["name"] in privilege_names:
                fail("duplicate privilege")
            privilege_names[privilege["name"]] = True
            privileges.append({"luid": PRIVILEGES[privilege["name"]], "attributes": _flags(privilege["attributes"], PRIVILEGE_ATTRIBUTES)})
        policy(base + "/Privilgs", windows.reactos_record("privileges", {"privileges": privileges}))
    return {
        "SAM": windows.hive_from_patches("SAM", sam, keys = keys, format = hive_format),
        "SECURITY": windows.hive_from_patches("SECURITY", security, keys = ["/Policy/Accounts", "/Policy/Domains", "/Policy/Secrets"], format = hive_format),
        "system_patches": [], "system_keys": [],
    }
