"""Discover macOS full installers from explicit Apple software-update catalogs.

Discovery reads metadata only; cache_packages acquires complete original sources.
Does not emulate softwareupdate's
machine eligibility rules, execute Distribution scripts, or infer Intel support.
"""

# A known public catalog, not an automatically selected "latest" endpoint.
PUBLIC_CATALOG_26 = "https://swscan.apple.com/content/catalogs/others/index-26-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"

def _fetch(url, maximum):
    return http_get(url, maximum = maximum)

def products(source):
    """Return installer product dictionaries from a plain/gzip catalog file.

    Results are ordered by product ID. Each has id and the complete original
    metadata dictionary; ordinary updates are excluded. No network requests.
    """
    return binary.software_update_catalog(source)

def installers(catalog_url, languages = ["English", "en"], fetch = _fetch):
    """Fetch a catalog and one Distribution per installer, returning manifests.

    catalog_url is explicit. languages is an ordered list of exact Distribution
    keys; absence is an error, not a silent omission. fetch(url, maximum) can
    supply an alternative byte transport or offline fixture. Results preserve
    product IDs, versions/builds, package dictionaries (including sizes, URLs
    and digests), all original product metadata, and parsed Distribution data.
    No payload is downloaded, no version is deduplicated, and no host/model
    eligibility filter is applied. Missing version/build metadata is an error.
    """
    if not languages:
        error("softwareupdate: languages must not be empty")
    result = []
    for product in products(fetch(catalog_url, 128 << 20)):
        metadata = product["metadata"]
        distributions = metadata.get("Distributions", {})
        selected = [lang for lang in languages if lang in distributions]
        if not selected:
            error("softwareupdate: product %s has no requested Distribution language" % product["id"])
        url = distributions[selected[0]]
        distribution = binary.software_update_distribution(fetch(url, 8 << 20))
        if not distribution["version"] or not distribution["build"]:
            error("softwareupdate: product %s has no version/build" % product["id"])
        packages = metadata.get("Packages")
        if type(packages) != "list" or not packages:
            error("softwareupdate: product %s has no package list" % product["id"])
        result.append(dict(
            product,
            title = distribution["title"],
            version = distribution["version"],
            build = distribution["build"],
            packages = packages,
            distribution_url = url,
            distribution_language = selected[0],
            distribution = distribution,
        ))
    return result


def _cache_package(package, cache):
    # Keep the original compressed source, not an extracted/rebuilt image.
    # Digest metadata namespaces the cache; it is not assumed to be SHA-256.
    key = json.encode([package["URL"], package["Size"], repr(package.get("Digest"))])
    return mirror_file(
        [package["URL"]], cache = cache, key = "macos-package:" + key,
        size = package["Size"], maximum = max(1, package["Size"]),
    )

def cache_packages(packages, cache, maximum = 64 << 30, fetch = _cache_package):
    """Acquire every original package before parsing or guest execution.

    Returns URL -> complete local file, using the native persistent mirror
    cache by default. No decompression or installer execution occurs here.
    Sizes, duplicate URLs and the aggregate budget are checked before fetching.
    A failed acquisition returns no partial mapping; completed source objects
    remain reusable and interrupted downloads remain resumable in the cache.

    Size is verified; catalog Digest is an opaque cache-identity component,
    not a claim of signature or cryptographic verification. Alternate backends
    may supply fetch(package, cache), returning a complete random-access file
    with no later network dependency. Cache configuration belongs to that
    backend; paths never enter the returned file interface.
    """
    if not packages:
        error("softwareupdate: packages must not be empty")
    if type(maximum) != "int" or maximum <= 0:
        error("softwareupdate: package budget must be positive")
    total, seen = 0, {}
    for package in packages:
        url, size = package.get("URL"), package.get("Size")
        if type(url) != "string" or not (url.startswith("https://") or url.startswith("http://")):
            error("softwareupdate: package requires an HTTP(S) URL")
        if type(size) != "int" or size < 0:
            error("softwareupdate: package requires a nonnegative Size")
        if url in seen:
            error("softwareupdate: duplicate package URL")
        seen[url] = True
        total += size
    if total > maximum:
        error("softwareupdate: packages exceed total byte budget")
    result = {}
    for package in packages:
        file = fetch(package, cache)
        if file.size != package["Size"]:
            error("softwareupdate: cached package size mismatch")
        result[package["URL"]] = file
    return result
