"""List macOS installer metadata and package URLs without fetching payloads."""

load("@stdlib//macos:softwareupdate.star", "PUBLIC_CATALOG_26", "installers")

def main(args):
    if len(args) > 1:
        error("usage: macos_catalog.star [CATALOG_URL]")
    catalog = args[0] if args else PUBLIC_CATALOG_26
    print("Catalog:", catalog)
    for installer in installers(catalog):
        print(installer["id"], installer["title"], installer["version"], installer["build"])
        for package in installer["packages"]:
            print("  ", package.get("Size", "unknown"), package["URL"])
