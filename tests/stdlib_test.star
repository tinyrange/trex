"""Tests for portable standard-library policy helpers."""

load("//tests:testing.star", "case", "equal", "suite", "true")
load("@stdlib//:doc.star", "identity")
load("@stdlib//windows:process.star", "walk_linked_list")
load("@stdlib//windows:symbols.star", "module_name")
load("@stdlib//windows/selfreg:common.star", "coalesce", "expand_environment")

def test_identity():
    equal(identity("documented"), "documented")

def test_module_name():
    equal(module_name("\\SystemRoot\\system32\\NTKRNLPA.EXE"), "ntkrnlpa.exe")

def test_walk_linked_list():
    pointers = {0x1000: 0x2020, 0x2020: 0x3020, 0x3020: 0x1000}
    def read_pointer(address):
        return pointers[address]
    equal(walk_linked_list(read_pointer, 0x1000, 0x20), [0x2000, 0x3000])

def test_coalesce_registry_patches():
    patches = [
        {"hive": "DEFAULT", "key": "/Software/Example", "name": "Value", "type": "REG_DWORD", "value": 0},
        {"hive": "DEFAULT", "key": "/Other", "name": "Kept", "type": "REG_SZ", "value": "yes"},
        {"hive": "default", "key": "/software/example", "name": "value", "type": "REG_DWORD", "value": 1},
    ]
    equal(coalesce(patches), [patches[1], patches[2]])

def test_expand_environment():
    equal(expand_environment(r"%SystemDrive%\Users\%USERNAME%\%UNKNOWN%", {"systemdrive": "C:", "UserName": "Ada"}), r"C:\Users\Ada\%UNKNOWN%")

TEST_SUITE = suite("stdlib", [
    case("identity", test_identity),
    case("module_name", test_module_name),
    case("walk_linked_list", test_walk_linked_list),
    case("coalesce_registry_patches", test_coalesce_registry_patches),
    case("expand_environment", test_expand_environment),
])
