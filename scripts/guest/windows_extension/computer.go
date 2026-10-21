//go:build renvo && win16 && computer_use

package main

const manifest = "API\t1\t1024\nABOUT\tsWindows 1.01 native journal playback; complete bounded gestures; host captures display; no file APIs\nFN\tping\tstr\tsReadiness\nEND\nFN\tlaunch\tmap\tsLaunch native Windows application\nARG\tpath\tstr\ts\nARG\ttail\tstr\ts\nEND\nFN\tinput_events\tnone\ts1..40 hex records: LE16 message,paramL,paramH; mouse pixels or key vk,scan; release all buttons/keys within batch\nARG\tevents\tstr\ts\nEND\nDONE\n"

// renvo:linkstatic USER,GetSystemMetrics
func getSystemMetrics(index uint16) uint16 { return 0 }

// renvo:linkstatic USER,GetTickCount
func getTicks() uint16 { return 0 }

// renvo:linkstatic TREX,JournalBegin
func journalBegin(event *uint16) uint16 { return 0 }

// renvo:linkstatic TREX,JournalPending
func journalPending() uint16 { return 0 }

// renvo:linkstatic TREX,JournalEnd
func journalEnd() {}

var journal [2]uint16

func inputEvents() {
	n := hexArg(2)
	if fields != 3 || n < 0 || !validInputEvents(transfer[:n], getSystemMetrics(0), getSystemMetrics(1)) {
		bad()
		return
	}
	journal[0], journal[1] = uint16(n/6), pointer(&transfer[0])
	if journalBegin(&journal[0]) == 0 {
		journalEnd()
		send("ERR\tsinput_busy\tsCannot install journal playback hook\n")
		return
	}
	start := getTicks()
	for journalPending() != 0 && !stopped {
		pump()
		if uint16(getTicks()-start) > 2000 {
			break
		}
	}
	done := journalPending() == 0
	journalEnd()
	if done {
		send("OK\tn\n")
	} else {
		send("ERR\tsinput_timeout\tsInput outcome uncertain; do not replay\n")
	}
}

func dispatchCall() {
	if fields == 1 && equalField(0, "?") {
		send(manifest)
		return
	}
	if fields < 2 || !equalField(0, "CALL") {
		bad()
		return
	}
	if fields == 2 && equalField(1, "ping") {
		send(pingReply)
	} else if equalField(1, "launch") {
		runProgram()
	} else if equalField(1, "input_events") {
		inputEvents()
	} else {
		bad()
	}
}
