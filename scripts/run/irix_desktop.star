"""Serve IRIX's graphical login and Interactive Desktop on a Newport Indy."""

load("//scripts/smoke:irix_ip24.star", "prepare")
load("//scripts/smoke:irix_ip24_system.star", "build_system", "start_system", "system_catalog")

def main(args):
    if len(args) == 6:
        print("Constructing IRIX 6.5.22m from the Foundation, Overlay, and Applications discs")
        system = build_system(system_catalog(*[open(name) for name in args]))
        machine, _ = start_system(system, single_user = False)
        return vmm.workspace({"IRIX 6.5.22m · SGI Indy": machine})
    if len(args) == 1:
        machine, _ = prepare(open(args[0]), "system", newport = True, single_user = False)
        return vmm.workspace({"IRIX 6.5.22f · SGI Indy": machine})
    fail("usage: trex -serve ADDRESS scripts/run/irix_desktop.star FOUNDATION1 FOUNDATION2 OVERLAY1 OVERLAY2 OVERLAY3 APPLICATIONS or INSTALLED_CHD")
