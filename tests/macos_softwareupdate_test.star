"""Offline tests for full-installer discovery and transport boundaries."""

load("//tests:testing.star", "case", "equal", "raises", "suite")
load("@stdlib//macos:softwareupdate.star", "cache_packages", "installers", "products")

def _product(identifier, language = "en"):
    return {
        "ExtendedMetaInfo": {"InstallAssistantPackageIdentifiers": {"SharedSupport": "com.apple.pkg.InstallAssistant.Example"}},
        "Distributions": {language: "https://example.test/" + identifier + ".dist"},
        "Packages": [{"URL": "https://example.test/" + identifier + ".pkg", "Size": 18000000000, "Digest": b"abc"}],
    }

def _distribution(version, build):
    return '<installer-gui-script><title>macOS Example</title><auxinfo><dict><key>VERSION</key><string>%s</string><key>BUILD</key><string>%s</string></dict></auxinfo><script><![CDATA[throw new Error("must remain inert");]]></script></installer-gui-script>' % (version, build)

def test_manifest_and_metadata_only():
    requests = []
    a = _product("a")
    b = _product("b", "English")
    payloads = {
        "catalog": binary.plist_encode({"Products": {"b": b, "a": a, "update": {"Packages": []}}}),
        "https://example.test/a.dist": _distribution("26.0", "25A123"),
        "https://example.test/b.dist": _distribution("26.0", "25A124"),
    }
    def fetch(url, maximum):
        requests.append((url, maximum))
        return payloads[url]  # A payload URL is deliberately absent.
    rows = installers("catalog", fetch = fetch)
    equal(requests, [("catalog", 128 << 20), ("https://example.test/a.dist", 8 << 20), ("https://example.test/b.dist", 8 << 20)])
    equal([(r["id"], r["version"], r["build"]) for r in rows], [("a", "26.0", "25A123"), ("b", "26.0", "25A124")])
    equal(rows[0]["distribution_language"], "en")
    equal(rows[0]["packages"], a["Packages"])
    equal(rows[0]["metadata"], a)
    equal(rows[0]["distribution"]["scripts"][0]["text"], 'throw new Error("must remain inert");')
    equal(products(payloads["catalog"])[0]["id"], "a")

def test_explicit_language_and_incomplete_metadata():
    requests = []
    p = _product("a", "French")
    def fetch(url, maximum):
        requests.append(url)
        if url == "catalog":
            return binary.plist_encode({"Products": {"a": p}})
        return _distribution("", "")
    raises(installers, args = ["catalog"], kwargs = {"fetch": fetch}, message = "no requested Distribution language")
    equal(requests, ["catalog"])
    raises(installers, args = ["catalog"], kwargs = {"languages": ["French"], "fetch": fetch}, message = "no version/build")
    raises(installers, args = ["catalog"], kwargs = {"languages": [], "fetch": fetch}, message = "languages must not be empty")

def test_complete_package_acquisition():
    requests = []
    packages = [
        {"URL": "https://example.test/base.dmg", "Size": 3},
        {"URL": "https://example.test/install.pkg", "Size": 4},
    ]
    payloads = {packages[0]["URL"]: b"abc", packages[1]["URL"]: b"defg"}
    def fetch(package, cache):
        equal(cache, "source-cache")
        requests.append(package["URL"])
        return binary.concat([payloads[package["URL"]]])
    result = cache_packages(packages, "source-cache", maximum = 7, fetch = fetch)
    equal(requests, [p["URL"] for p in packages])
    equal({url: file.bytes() for url, file in result.items()}, payloads)

def test_acquisition_preflight_and_failure():
    requests = []
    valid = {"URL": "https://example.test/a", "Size": 3}
    def fetch(package, cache):
        requests.append(package["URL"])
        return binary.concat([b"abc"])
    kwargs = {"fetch": fetch, "maximum": 6}
    raises(cache_packages, [[valid, {"URL": "https://example.test/b", "Size": 4}], "cache"], kwargs, message = "total byte budget")
    raises(cache_packages, [[valid, {"URL": "https://example.test/b"}], "cache"], kwargs, message = "Size")
    raises(cache_packages, [[valid, valid], "cache"], kwargs, message = "duplicate")
    raises(cache_packages, [[valid, {"URL": "file:///bad", "Size": 0}], "cache"], kwargs, message = "HTTP(S)")
    equal(requests, [])  # No partial acquisition before a late preflight error.
    raises(cache_packages, [[dict(valid, Size = 4)], "cache"], kwargs, message = "size mismatch")
    def failed(package, cache):
        if package["URL"] != valid["URL"]:
            fail("transport interrupted")
        return binary.concat([b"abc"])
    raises(cache_packages, [[valid, {"URL": "https://example.test/b", "Size": 3}], "cache"], {"fetch": failed}, message = "transport interrupted")

TEST_SUITE = suite("macos_softwareupdate", [
    case("complete_package_acquisition", test_complete_package_acquisition),
    case("acquisition_preflight_and_failure", test_acquisition_preflight_and_failure),
    case("manifest_and_metadata_only", test_manifest_and_metadata_only),
    case("explicit_language_and_incomplete_metadata", test_explicit_language_and_incomplete_metadata),
])
