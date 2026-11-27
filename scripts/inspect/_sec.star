load("//scripts/inspect:s370_diag.star", "machine", "source", "operator")
load("//scripts/inspect:s370_steps.star", "run_steps")
# _sec.star SECTION LOADMSG [STEPS...]: run SDM until SECTION starts, then run steps.
def main(args):
    m = machine(source())
    m.ipl(0x130)
    m.run(instructions = 200000000)
    m.cards(0x00c, [args[1]])
    m.interrupt_key()
    seen = 0
    for _ in range(200000):
        m.run(instructions = 50000)
        lines = m.screens(0x01f)
        for line in lines[seen:]:
            operator(m, line, None)
        seen = len(lines)
        if ("S   " + args[0]) in m.screen(0x01f):
            break
    run_steps(m, args[2:])
