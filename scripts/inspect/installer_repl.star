"""Opens an installer from an ISO 9660 image in the scoped REPL."""

load("@stdlib//windows:installer.star", "analyze", installation = "installer")
load("@stdlib//windows/emulation:runner.star", emulate = "run")
load("@stdlib//windows/selfreg:facts.star", windows_class_ids = "class_ids")
load("@stdlib//windows/selfreg:policy.star", inspect_registration = "registration_patches")

def main(args):
    if len(args) != 2:
        fail("usage: installer_repl.star IMAGE.iso /PATH/TO/SETUP.exe")

    disc = filesystem.iso9660(open(args[0]))
    source = disc.find(args[1])
    if source == None or type(source) != "file":
        fail("installer path not found: %s" % args[1])
    probe = archive.installer_probe(source)
    installer = archive.installer(source) if probe["supported"] else None
    payload = installer.payload if installer != None else None
    script = installer.installscript if installer != None else None
    # Bind the imported helper in main's scope so the scoped REPL can use it.
    analyze_installer = analyze
    installer_modifications = installation
    run_executable = emulate
    class_ids = windows_class_ids
    registration_patches = inspect_registration

    print("disc, source, probe, installer, payload, script, analyze_installer, installer_modifications, run_executable, class_ids, and registration_patches are available")
    if installer == None:
        print("unsupported installer:", probe)
    else:
        print("format=%s files=%d" % (installer.format, len(installer.files)))
    repl()
