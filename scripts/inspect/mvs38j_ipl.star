"""Steps an MVS 3.8j Turnkey 3 IPL on emulator.s390 (System/370).

Run: go run ./cmd/trex scripts/inspect/mvs38j_ipl.star STEP...
Steps: see scripts/inspect/s370_steps.star.
"""

load("//scripts/inspect:mvs38j_lib.star", "machine")
load("//scripts/inspect:s370_steps.star", "run_steps")

def main(args):
    run_steps(machine(), args)
