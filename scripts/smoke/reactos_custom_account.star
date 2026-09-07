"""Runs the ReactOS smoke with a declared, passworded additional local user."""
load("@stdlib//windows:identity.star", "machine_identity")
load("@stdlib//windows/reactos:image.star", "reactos_disk")
load("@stdlib//windows/reactos:security.star", "workstation_security", "PRIMARY_GROUP_RID")
load("//scripts/smoke:reactos.star", "reactos_smoke_case")
load("@stdlib//vmm:smoke.star", smoke_run = "run")

def custom_disk(source):
    identity = machine_identity("TREX-ROS-TEST")
    security = workstation_security(identity["sid"], identity["computer_name"])
    user_rid = 1001
    user_sid = identity["sid"] + "-" + str(user_rid)
    security["users"].append({"name": "Builder", "rid": user_rid, "password": "smoke-only", "flags": ["normal", "password_never_expires"], "primary_group": PRIMARY_GROUP_RID, "full_name": "trex image builder"})
    security["groups"][0]["members"].append(user_rid)
    security["aliases"][0]["members"].append(user_sid)
    security["domain_policy"]["next_rid"] = user_rid + 1
    security["rights"].append({"sid": user_sid, "logon": ["interactive"], "privileges": []})
    return reactos_disk(source, security = security, computer_name = identity["computer_name"], autologon = "Builder")

def main(args):
    smoke_run([reactos_smoke_case(custom_disk)], args, title = "trex ReactOS custom-account smoke")
