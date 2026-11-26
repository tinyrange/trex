"""Run all 215 cataloged diagnostic and utility sections and the monitor checks.

From trex, run go run ./cmd/trex scripts/smoke/s370_diag_all.star [raw-card-deck].
The raw deck is optional and supplies the original 2540 valid-card input.
The FAA profile and the formatter checks apply guarded changes in memory.
"""

load("//scripts/inspect:s370_diag.star", "LATE_EOT_DRIVES", "check_d405e1_late_eot", "check_d40604_creep_loop", "check_d40604_negative_creep", "check_d40604_protected_reel", "check_d40604_velocity", "check_d63534_dualing", "check_d63564_reset", "check_d635f2_device_end", "check_d66542_operator", "check_d805e4_background", "check_d80683_retry", "check_d806a5_mdm_allocation", "check_formatter", "check_ipl_headers", "check_mdm_tape_id", "check_model50_cpu", "check_model65_channel", "check_storage_channel", "check_storage_ioce", "check_storage_ioce_psa", "check_storage_keys", "check_storage_live", "check_storage_output", "check_storage_stop", "library_reel", "read_raw_deck", "source")
load("//scripts/smoke:s370_diag.star", "run_original")
load("//scripts/smoke:s370_diag_faa.star", "run_faa")
load("//scripts/inspect:s370_diag.star", "check_9020_configuration", "check_9020_configuration_links", "check_9020_control_configuration", "check_9020a_formatter_storage", "check_9020e_display_logout", "check_9020e_display_storage", "check_9020e_rcu", "check_mdm_storage_data_check", "check_storage_2314_data_chain", "check_storage_data_check", "check_storage_ioce_command_chain", "check_storage_ioce_data_chain", "check_storage_ioce_data_check", "check_storage_ioce_key_parity", "check_storage_output_chain", "check_storage_output_parity")
load("//scripts/inspect:s370_diag.star", "check_9020_count_logout", "check_9020_diag_timer", "check_9020_ioce_defeat_interleave", "check_9020_mark_parity", "check_9020_scan_address_parity", "check_9020_sum_parity", "check_9020e_defeat_interleave")
load("//scripts/inspect:s370_diag.star", "check_9020e_dau_configuration", "check_9020e_display_contention", "check_9020e_display_wrap", "check_9020e_rcu_outboard", "check_9020e_rkm")

def main(args):
    if len(args) > 1:
        fail("usage: s370_diag_all.star [raw-card-deck]")
    tape = source()
    valid_cards = read_raw_deck(open(args[0])) if args else None

    print("Running the original IPL and diagnostic jobs with D11792's FAA storage-key checks restored")
    check_ipl_headers(tape)
    run_original(tape, valid_cards = valid_cards)

    print("Running the FAA-restored jobs")
    library = library_reel(tape)
    run_faa(library)
    for inline in [False, True]:
        check_mdm_tape_id(library, inline)

    print("Checking tape motion and end-of-tape on the supported test profiles")
    check_d40604_protected_reel(tape)
    for tracks, converter in [(9, True), (7, True), (7, False)]:
        check_d40604_creep_loop(tape, 4, tracks, converter, reuse_mark = True)
    check_d40604_negative_creep(tape)
    check_d40604_velocity(tape)
    for drive in LATE_EOT_DRIVES:
        check_d405e1_late_eot(tape, drive)

    print("Checking printer dualing, restart, and chain cleaning")
    check_d63534_dualing(tape)
    check_d63564_reset(tape, "late-restored")
    check_d63564_reset(tape, "card-early-restored")
    check_d635f2_device_end(tape)

    print("Checking 1052 cancellation and console fault reports")
    for mode in ["cancel", "keyboard-parity", "not-ready"]:
        check_d66542_operator(tape, mode)

    print("Checking disk motion and operator retry under SDM and MDM")
    for mdm in [False, True]:
        check_d805e4_background(tape, mdm = mdm)
        check_d80683_retry(tape, mdm = mdm)
    check_d806a5_mdm_allocation(tape)

    print("Checking the 128 KiB Model 50 CPU suite")
    for system in ["A", "D", "E"]:
        check_model50_cpu(tape, system)

    print("Checking the Model 65 channels")
    check_model65_channel(tape)

    print("Checking the short and long machine-check formatters")
    for element in [0, 1, 2, 3]:
        for mode in ["short-restored", "long-restored"]:
            check_formatter(library, element, mode)
    check_formatter(library, 1, "storage-mcw")
    check_9020a_formatter_storage(tape)
    check_storage_stop()
    check_storage_data_check()
    check_9020_configuration()
    check_9020_configuration_links()
    for control in ["TCU", "SCU"]:
        check_9020_control_configuration(control)
    check_9020e_rcu()
    check_9020e_rcu_outboard()
    check_9020e_dau_configuration()
    check_9020e_rkm()
    check_9020e_display_storage()
    check_9020e_display_logout()
    check_9020e_display_wrap()
    check_9020e_display_contention()
    check_9020e_defeat_interleave()
    check_9020_ioce_defeat_interleave()
    check_9020_diag_timer()
    check_9020_count_logout()
    check_9020_mark_parity()
    check_9020_scan_address_parity()
    check_9020_sum_parity()
    check_mdm_storage_data_check(library)
    check_storage_ioce_data_check()
    check_storage_ioce_key_parity()
    check_storage_ioce_command_chain()
    check_storage_ioce_data_chain()
    check_storage_2314_data_chain()
    check_mdm_storage_data_check(library, ioce = True)
    check_storage_live()
    check_storage_ioce()
    check_storage_ioce_psa()
    check_storage_channel(tape)
    check_storage_output()
    check_storage_output_parity()
    check_storage_output_chain()
    check_storage_keys()
    print("Full diagnostic tape smoke passed")
