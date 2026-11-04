# Windows servicing from Starlark

The primary API consumer is Starlark. Portable implementation lives under
`@stdlib//windows/servicing:*.star`, backed by the native `windows.*`, archive,
filesystem and emulator primitives. No private recipe checkout is required.
`cmd/windows11` integration is separate follow-up work.

## Scope and phase contracts

This is a set of composable, fail-closed building blocks, **not** a promise that
arbitrary Windows media can be updated or that a complete servicing transaction
has passed validation. Native ABI runners accept only their documented,
identity-qualified inputs. Unsupported transitions are errors, not approximations.

| Phase | Module and entry points | Result / responsibility |
| --- | --- | --- |
| Metadata | `population.star`: `collect_servicing_metadata` | Complete bounded metadata closure, including unavailable references; no admission implied |
| Package planning | `plan.star`: `plan_package_phases` | Install `population` and compact `closure`, retaining independent stage catalog-hint order; input closure unchanged |
| Composition | `components.star`: `analyze_servicing_components`, `project_servicing_sources`, `plan_servicing_payloads` | Exact owners, winners, source bindings and lazy payload plans |
| Runtime declarations | `runtime.star`: `analyze_servicing_runtime` and path/security/registry helpers | Portable declarations and explicit transition semantics |
| Driver and file effects | `driver_apply.star`, `file_apply.star` | Candidate tree and phase report, **not** CBS completion |
| Registry and installers | `registry.star`, `registry_effects.star`, `events.star`, `services_direct.star`, and family-specific modules | Explicit plans and publication on caller-owned directories |
| Catalogs | `catalogs.star`: `prepare_package_catalogs`, `apply_package_catalogs` | Signed MUM membership, authenticated timestamp chains and explicit publication |
| CSI persistence | `csi.star`: `apply_csi_state` | Value-scoped source/pin/composition publication |
| Package persistence | `package_store.star`: `publish_package_metadata` | Admitted dispositions after effects and signed metadata checks |
| Audit | `package_audit.star`: `audit_package_states` | Observations, never repair or state overrides |

Catalog trust and hint ordering, GAC/NGEN, backup/recovery, settings/migration,
media categories, driver ownership, and native installer queues have separate
modules. Their `plan_*`/`prepare_*` and `apply_*` entry points expose the actual
phase boundary rather than hiding all effects behind one success flag.

### Planning example

```python
load("@stdlib//windows/servicing:population.star", "collect_servicing_metadata")
load("@stdlib//windows/servicing:plan.star", "plan_package_phases")
load("@stdlib//windows/servicing:components.star", "analyze_servicing_components")
load("@stdlib//windows/servicing:runtime.star", "analyze_servicing_runtime")

# base: archive.wim reader; image: explicit WIM image path.
# source: caller-prepared update media; features/roots: caller policy.
# hives: exact baseline COMPONENTS, SOFTWARE and SYSTEM file objects.
closure = collect_servicing_metadata(base, image, source, features, roots, hives=hives)
planned = plan_package_phases(base, image, closure, hives=hives)
closure, population = planned["closure"], planned["population"]
analysis = analyze_servicing_components(base, image, source, features, population, hives=hives)
runtime = analyze_servicing_runtime(analysis)
# Analysis is NOT permission to skip effect construction or publish all packages.
```

All phases must use the same immutable baseline. Recipe specialization happens
once, after servicing, from the serviced tree rather than the original WIM.
Acquisition/network policy, product/edition choice, credentials, VM boot and
host report paths remain the caller's responsibility. A supplied lazy source
may fetch through its own explicitly granted acquisition policy; the library
neither enables that policy nor substitutes a host servicing tool.

## Ownership, failure and validation

- Keep backing files/readers alive while lazy payloads or generated disks use
  them. Return from the construction function before retaining a guest; clearing
  one dictionary does not release other references or captured closures.
- Low-level `apply_*` functions mutate their supplied directory. There is no
  universal cross-phase rollback guarantee. Use an independent candidate clone,
  publish it only on success, and discard it on failure. Individual batches
  preflight source epochs and destination authority as documented and tested.
- Direct driver replacement accepts only equivalent ordered INF semantics with
  qualified version changes. Native driver sessions are a separate explicit API;
  they do not silently replace rejected direct construction. After staging and
  native publication, do not replay staging over native file objects.
- Native runner results and retained emulator machines are inspection values,
  not booted guests. Follow each runner's bounded instruction/memory and cleanup
  contract. No module import launches a VM or opens an interactive REPL.
- Package state is operational Windows state, not validation confidence. Read
  `docs/windows-package-state-policy.md`: installed/staged/superseded states and
  owner overlays are independent and must retain their admitted meaning.
- Boot success, native integrity checks, package audit, and clean shutdown are
  separate evidence. A host timeout is not a failed native integrity check.

## Tests and native controls

From the public checkout, `go run ./cmd/trex test.star nt6` runs portable
servicing conformance tests, with synthetic files/hives and no Windows media.
The normal public test manifest includes these suites.

`tests/servicing/native/` contains nine **manual, media-dependent** controls, not
ordinary suites. Each exposes `verify_*` functions and verifies its required
native identities. In a public-checkout REPL, for example:

```python
control = testing.module("//tests/servicing/native:nt6_update_native_queue_test.star")
# Supply file objects from explicitly selected licensed media, not host tools.
control["verify_native_queue"](wcp, before_manifest, after_manifest)
```

Read the selected module's signature and identity checks first. A passing normal
suite does not claim that these controls ran, or that fresh-image integration
passed. No media is downloaded or guessed by the test manifest.

## Migration

Former private `nt6/{servicing,csi,runtime,package_store}.star` became
`{population,components,runtime,package_indexes}.star`. Portable
`windows_update_<family>.star` inspection helpers became `<family>.star` here.
CSI and package writers are now `apply_csi_state` and `publish_package_metadata`.
Private reference comparisons, CLI argument parsing, media specialization,
interactive diagnostics, and boot observations remain outside this library.
