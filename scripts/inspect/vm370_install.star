"""Steps the VM/370 Release 6 DDR-tape installation on emulator.s390 (S/370).

Run: go run ./cmd/trex scripts/inspect/vm370_install.star ESSENTIALS.tar.gz VMREL6.ddr.aws.bz2 CPR6L0.ddr.aws.bz2 STEP...
Steps: see scripts/inspect/s370_steps.star.
"""

load("//scripts/inspect:vm370_lib.star", "machine")
load("//scripts/inspect:s370_steps.star", "run_steps")

def main(args):
    if len(args) < 3:
        fail("usage: vm370_install.star ESSENTIALS.tar.gz VMREL6.ddr.aws.bz2 CPR6L0.ddr.aws.bz2 STEP...")
    m = machine(open(args[0]), open(args[1]), open(args[2]))
    run_steps(m, args[3:])
