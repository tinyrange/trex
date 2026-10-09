# macOS full-installer discovery

`@stdlib//macos:softwareupdate.star` discovers full installer products from an
explicit Apple software-update catalog. It runs without macOS or the host
`softwareupdate` command. All parsing and decompression are native Go; network
transport stays in the native backend. No host intermediates are created.

## List installers

From the trex checkout:

```sh
go run ./cmd/trex scripts/inspect/macos_catalog.star
# Or choose an exact catalog/channel yourself:
go run ./cmd/trex scripts/inspect/macos_catalog.star 'CATALOG_URL'
```

The command prints the catalog URL, each product ID/title/version/build, and
package sizes and URLs. The default is the known generation-26 merged public
catalog (`PUBLIC_CATALOG_26`), not an automatically selected latest endpoint.
Changing catalog URLs is caller policy. A public catalog can still contain beta
labels and multiple versions/builds; results are neither ranked nor deduplicated.

In a script:

```python
load("@stdlib//macos:softwareupdate.star", "PUBLIC_CATALOG_26", "installers")

def main(args):
    for item in installers(PUBLIC_CATALOG_26):
        print(item["id"], item["title"], item["version"], item["build"])
        for package in item["packages"]:
            print(package["Size"], package["URL"])
```

Listing fetches only the catalog and one requested-language Distribution per
installer, **not installer payloads**. The default language priority is exact
keys `English`, then `en`. Supply `languages=[...]` for another preference.
An absent requested language, missing version/build, or missing package list is
an error, not a silently omitted product. Network errors propagate without
partial result truncation or automatic retries.

Each result retains `id` and the entire original product `metadata`, plus
`title`, `version`, `build`, `packages`, `distribution_url`,
`distribution_language`, and `distribution`. Original package dictionaries keep
URLs, 64-bit sizes, digests, metadata URLs and unknown fields. Digests are
metadata here: discovery does not authenticate or verify payload bytes.

## Offline and alternate transports

`products(source)` takes a file/string/bytes catalog and performs no network
requests. For offline discovery including Distribution metadata, pass
`installers(catalog_url, fetch=...)`. The callback is `fetch(url, maximum)` and
returns a file/string/bytes value; the native parsers still enforce input limits.
This also keeps the orchestration usable with a browser transport.

Low-level readers:

- `binary.software_update_catalog(source)` accepts XML or gzip catalogs and
  returns installer products in product-ID order. Recognized identifiers are
  `OSInstall == com.apple.mpkg.OSInstall` or a `SharedSupport` value beginning
  with `com.apple.pkg.InstallAssistant`.
- `binary.software_update_distribution(source)` reads `installer-gui-script`
  XML. It returns `title`, `raw_title`, `version`, `build`, `auxinfo`, `options`,
  `scripts`, and `localizations`. Version/build prefer `macOSProductVersion` /
  `macOSProductBuildVersion`, then `VERSION` / `BUILD`. Observed double-quoted
  localization title assignments are resolved; other grammar remains available
  in the raw fields. This is not a general .strings or JavaScript interpreter.
- `http_get(url, maximum=64<<20, timeout=60)` performs a bounded sequential
  HTTP(S) GET into a memory file. It supports redirects and HTTP gzip transfer
  decoding without HEAD/range requests or a disk cache. The maximum is enforced
  after transfer decoding; HTTP status other than 200 is an error.

Catalog XML is decoded one product at a time: an aggregate catalog can exceed
the ordinary plist reader's value-count limit without weakening that limit for
individual products. Stored and expanded catalogs are limited to 128 MiB;
individual products and Distributions to 8 MiB. XML scanning is bounded to four
million tokens and depth 128 per scanned value/tree. Products retain plist
value limits. Binary catalogs are also accepted through the existing plist
reader, with its stricter whole-input limits. Gzip checksums, duplicate
catalog/product keys, malformed XML and unresolved entities fail explicitly.
External entities are not fetched.

## Scope and compatibility

This implements **catalog discovery**, not an exact clone of
`softwareupdate --list-full-installers`:

- No host/model eligibility filter, board-ID matching, Intel-only filter, or
  guarantee that a listed installer will run on a particular Mac/VM.
- Distribution scripts and options are retained for inspection; JavaScript is
  never executed or converted into an invented compatibility decision.
- Catalog availability is not a promise of an exhaustive historical archive.
- Obtaining packages and constructing/booting an installed image remain
  separate operations. Cache the **complete original installer** before image
  construction or guest execution, as shown below. Do not put lazy HTTP range
  readers on a guest disk's source path, and do not use the bounded metadata
  GET for multi-gigabyte media.

The implementation is independent, based on the fields in published Apple
catalog/Distribution metadata. No third-party downloader code or installer
compatibility scripts are incorporated. Fixtures are synthetic, and automated
tests are offline. A manual live smoke covered legacy multi-package and modern
InstallAssistant products, without fetching their payloads.

## Cache the complete installer before use

```python
load("@stdlib//macos:softwareupdate.star", "PUBLIC_CATALOG_26", "products", "cache_packages")

def main(args):
    product = [p for p in products(http_get(PUBLIC_CATALOG_26, maximum=128<<20))
               if p["id"] == "041-91758"][0]
    sources = cache_packages(product["metadata"]["Packages"],
                             cache="local/cache/macos-sources", maximum=8<<30)
    # Only now parse sources or construct a guest disk. Values are local files.
    print("complete original packages:", len(sources))
```

`cache_packages(packages, cache, maximum=64<<30)` returns a URL-to-file mapping
only after **every** listed package has been fully acquired. `maximum` bounds
the aggregate declared size; duplicate URLs, missing/negative sizes and an
over-budget selection fail before downloading any package. A download failure
propagates rather than returning an incomplete installer. Completed cache
objects are reused and interrupted downloads can resume via `mirror_file`.

The native persistent cache stores original compressed source bytes. It does
not extract archives, pre-decompress PBZX/XZ payloads, or materialize a guest
disk. Returned file reads use local storage, with no network fallback. Keep
format decoding lazy unless a local-source experiment establishes a need for
additional materialization. Metadata discovery can still access the network;
that occurs before acquisition, not while the guest is running.

Expected sizes are checked. URL, size and original Digest metadata namespace
the cache, but this helper does **not** claim catalog-digest verification or
Apple signature authentication. Existing `mirror_file` callers with an explicit
trusted SHA-256 can use its digest-verification support directly.

For alternate storage backends, `fetch(package, cache)` can be supplied; it must
return a complete random-access source with no later network dependency. Native
cache paths stay in backend configuration, not the portable file interface.
