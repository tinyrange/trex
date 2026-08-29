"""Opens an installer from an ISO 9660 image in the scoped REPL."""

load("@stdlib//windows:installer.star", "analyze", installation = "installer")

def main(args):
    if len(args) != 2:
        fail("usage: installer_repl.star IMAGE.iso /PATH/TO/SETUP.exe")

    disc = filesystem.iso9660(open(args[0]))
    source = disc.find(args[1])
    if source == None or type(source) != "file":
        fail("installer path not found: %s" % args[1])
    installer = archive.installer(source)
    payload = installer.payload
    script = installer.installscript
    # Bind the imported helper in main's scope so the scoped REPL can use it.
    analyze_installer = analyze
    installer_modifications = installation

    print("disc, source, installer, payload, script, analyze_installer, and installer_modifications are available")
    print("format=%s files=%d" % (installer.format, len(installer.files)))
    repl()
