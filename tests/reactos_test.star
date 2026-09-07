"""Template-free ReactOS account construction and customization tests."""
load("//tests:testing.star", "case", "equal", "true", "raises", "suite")
load("@stdlib//windows/reactos:security.star", "workstation_security", "security_database")
load("@stdlib//windows/reactos:registry.star", "shell_registration_actions")
load("@stdlib//windows/reactos:profiles.star", "add_profile_skeleton", "mkdir_tree")

def _spec():
    return workstation_security("S-1-5-21-101-202-303", "TEST-ROS", creation_time = 128000000000000000)

def test_defaults():
    hives = security_database(_spec())
    sam = windows.hive(hives["SAM"])
    equal(sam["/SAM/Domains/Account/Users/Names"].values, {"Administrator": 500, "Guest": 501})
    user = sam["/SAM/Domains/Account/Users/000001F4"].values
    equal(len(user["F"]), 72)
    equal(binary.read_u64le(user["F"], 24), 128000000000000000, "password-set time must follow the explicit construction time")
    equal(hex(user["NTPwd"]), "31d6cfe0d16ae931b73c59d7e0c089c0")
    equal(hex(user["LMPwd"]), "aad3b435b51404eeaad3b435b51404ee")
    equal(hex(user["LogonHours"]), "a800" + "ff" * 21)
    equal(sam["/SAM/Domains/Account"].values["Name"], "TEST-ROS")
    equal(len(sam["/SAM/Domains/Account"].values["F"]), 104)
    true("C" not in sam["/SAM"].values)
    true("V" not in user)

def test_custom_accounts():
    spec = _spec()
    spec["users"].append({"name": "Builder", "rid": 1001, "password": "test-password", "flags": ["normal"], "primary_group": 513, "full_name": "Image Builder"})
    spec["groups"][0]["members"].append(1001)
    spec["domain_policy"]["next_rid"] = 1002
    spec["aliases"][0]["members"].append(spec["domain_sid"] + "-1001")
    spec["rights"].append({"sid": spec["domain_sid"] + "-1001", "logon": ["interactive"], "privileges": []})
    hives = security_database(spec)
    sam = windows.hive(hives["SAM"])
    user = sam["/SAM/Domains/Account/Users/000003E9"].values
    equal(user["FullName"], "Image Builder")
    equal(user["NTPwd"], crypto.hash("md4", binary.encode("test-password", encoding = "utf16le")))
    equal(sam["/SAM/Domains/Account/Users/Names"].values["Builder"], 1001)
    true(spec["domain_sid"] + "-1001" in sam["/SAM/Domains/Builtin/Aliases/00000220/Members"].values)
    policy = windows.hive(hives["SECURITY"])
    equal(policy["/Policy/Accounts/" + spec["domain_sid"] + "-1001/ActSysAc"].values["(default)"], binary.u32le(1))

def test_reject_inconsistent_accounts():
    spec = _spec()
    spec["users"][1]["name"] = "administrator"
    raises(security_database, [spec], message = "duplicate")
    spec = _spec()
    spec["groups"][0]["members"] = []
    raises(security_database, [spec], message = "primary group")
    spec = _spec()
    spec["aliases"][0]["members"].append(spec["domain_sid"] + "-999")
    raises(security_database, [spec], message = "missing local account")
    spec = _spec()
    spec["domain_policy"]["next_rdi"] = 1000
    raises(security_database, [spec], message = "unknown field")
    spec = _spec()
    spec["users"][0]["flags"].append("typo")
    raises(security_database, [spec], message = "unknown flag")

def test_registration_flags():
    inf = windows.inf(b'[EarlyRegisterDlls]\n[OleControlDlls]\n11,,comctl32.dll,2\n11,,shell32.dll,3\n11,,atl.dll,1\n')
    actions = shell_registration_actions(inf)
    equal([(a["dll"], a["export"]) for a in actions], [("comctl32.dll", "DllInstall"), ("shell32.dll", "DllRegisterServer"), ("shell32.dll", "DllInstall"), ("atl.dll", "DllRegisterServer")])

def test_profile_paths():
    root = directory()
    mkdir_tree(root, "/ReactOS/system32/config")
    add_profile_skeleton(root, windows.hive_from_patches("DEFAULT", []), ["Builder"])
    profile = windows.hive(root.find("/Documents and Settings/Builder/NTUSER.DAT"))
    equal(profile["/Software/Microsoft/Windows/CurrentVersion/Explorer/Shell Folders"].values["Desktop"], "C:\\Documents and Settings\\Builder\\Desktop")

def test_password_policy():
    spec = _spec()
    spec["users"][0]["must_change_password"] = True
    user = windows.hive(security_database(spec)["SAM"])["/SAM/Domains/Account/Users/000001F4"].values
    equal(binary.read_u64le(user["F"], 24), 0)
    spec["users"][0]["must_change_password"] = "false"
    raises(security_database, [spec], message = "boolean")
    spec = _spec()
    spec["rights"][0]["privileges"].append(spec["rights"][0]["privileges"][0])
    raises(security_database, [spec], message = "duplicate privilege")

TEST_SUITE = suite("reactos", [case("defaults", test_defaults), case("custom_accounts", test_custom_accounts), case("reject_inconsistent_accounts", test_reject_inconsistent_accounts), case("registration_flags", test_registration_flags), case("profile_paths", test_profile_paths), case("password_policy", test_password_policy)])
