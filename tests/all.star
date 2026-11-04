"""Manifest of Starlark test suites shipped with trex."""

load(":stdlib_test.star", stdlib = "TEST_SUITE")
load(":stdlib_internal_test.star", stdlib_internal = "TEST_SUITE")
load(":emulation_conformance_test.star", emulation_conformance = "TEST_SUITE")
load(":reactos_test.star", reactos = "TEST_SUITE")
load(":media_decode_test.star", media_decode = "TEST_SUITE")

load(":scs_test.star", scs = "TEST_SUITE")

load(":linux_test.star", linux = "TEST_SUITE")
load(":macos_softwareupdate_test.star", macos_softwareupdate = "TEST_SUITE")

load("//tests/servicing:nt6_package_store_test.star", nt6_package_store = "TEST_SUITE")
load("//tests/servicing:nt6_update_appx_test.star", nt6_update_appx = "TEST_SUITE")
load("//tests/servicing:nt6_update_backup_test.star", nt6_update_backup = "TEST_SUITE")
load("//tests/servicing:nt6_update_basic_queue_test.star", nt6_update_basic_queue = "TEST_SUITE")
load("//tests/servicing:nt6_update_boot_installers_test.star", nt6_update_boot_installers = "TEST_SUITE")
load("//tests/servicing:nt6_update_catalog_hints_test.star", nt6_update_catalog_hints = "TEST_SUITE")
load("//tests/servicing:nt6_update_driver_owners_test.star", nt6_update_driver_owners = "TEST_SUITE")
load("//tests/servicing:nt6_update_driver_replacements_test.star", nt6_update_driver_replacements = "TEST_SUITE")
load("//tests/servicing:nt6_update_drivers_test.star", nt6_update_drivers = "TEST_SUITE")
load("//tests/servicing:nt6_update_events_publication_test.star", nt6_update_events_publication = "TEST_SUITE")
load("//tests/servicing:nt6_update_events_test.star", nt6_update_events = "TEST_SUITE")
load("//tests/servicing:nt6_update_files_test.star", nt6_update_files = "TEST_SUITE")
load("//tests/servicing:nt6_update_gac_test.star", nt6_update_gac = "TEST_SUITE")
load("//tests/servicing:nt6_update_http_test.star", nt6_update_http = "TEST_SUITE")
load("//tests/servicing:nt6_update_key_flags_publication_test.star", nt6_update_key_flags_publication = "TEST_SUITE")
load("//tests/servicing:nt6_update_media_categories_test.star", nt6_update_media_categories = "TEST_SUITE")
load("//tests/servicing:nt6_update_migration_test.star", nt6_update_migration = "TEST_SUITE")
load("//tests/servicing:nt6_update_native_lsa_test.star", nt6_update_native_lsa = "TEST_SUITE")
load("//tests/servicing:nt6_update_ngen_test.star", nt6_update_ngen = "TEST_SUITE")
load("//tests/servicing:nt6_update_print_queue_test.star", nt6_update_print_queue = "TEST_SUITE")
load("//tests/servicing:nt6_update_recovery_test.star", nt6_update_recovery = "TEST_SUITE")
load("//tests/servicing:nt6_update_registry_test.star", nt6_update_registry = "TEST_SUITE")
load("//tests/servicing:nt6_update_services_direct_test.star", nt6_update_services_direct = "TEST_SUITE")
load("//tests/servicing:nt6_update_services_test.star", nt6_update_services = "TEST_SUITE")
load("//tests/servicing:nt6_update_settings_test.star", nt6_update_settings = "TEST_SUITE")
load("//tests/servicing:nt6_update_smart_queue_test.star", nt6_update_smart_queue = "TEST_SUITE")
load("//tests/servicing:nt6_update_timezone_test.star", nt6_update_timezone = "TEST_SUITE")

load("//tests/servicing:nt6_servicing_test.star", nt6_servicing = "TEST_SUITE")

load("//tests/servicing:nt6_update_package_security_test.star", nt6_update_package_security = "TEST_SUITE")

TEST_SUITES = [
    nt6_update_package_security,
    nt6_servicing,
    nt6_package_store,
    nt6_update_appx,
    nt6_update_backup,
    nt6_update_basic_queue,
    nt6_update_boot_installers,
    nt6_update_catalog_hints,
    nt6_update_driver_owners,
    nt6_update_driver_replacements,
    nt6_update_drivers,
    nt6_update_events_publication,
    nt6_update_events,
    nt6_update_files,
    nt6_update_gac,
    nt6_update_http,
    nt6_update_key_flags_publication,
    nt6_update_media_categories,
    nt6_update_migration,
    nt6_update_native_lsa,
    nt6_update_ngen,
    nt6_update_print_queue,
    nt6_update_recovery,
    nt6_update_registry,
    nt6_update_services_direct,
    nt6_update_services,
    nt6_update_settings,
    nt6_update_smart_queue,
    nt6_update_timezone,

    macos_softwareupdate,
    linux,
    scs,
    media_decode,
    reactos,
    stdlib,
    stdlib_internal,
    emulation_conformance,
]
