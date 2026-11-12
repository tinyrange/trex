package cc

// Fixed-size owner-loop observations, not guest-memory snapshots. The final
// 64 serviced frames survive PCI disable, so driver liveness failures can be
// distinguished from an empty schedule, NAKs, and missed interrupt delivery.
type uhciFrameTrace struct {
	frame                                uint16
	frames                               uint64
	link                                 uint32
	statusBefore, statusAfter, interrupt uint16
	tds, active, ioc                     uint32
	qh, td, tdStatus, token              uint32
}

func (u *uhci) frameHistory() []any {
	n := min(u.frameTraceCount, uint64(len(u.frameTrace)))
	out := make([]any, 0, n)
	for i := u.frameTraceCount - n; i < u.frameTraceCount; i++ {
		r := u.frameTrace[i%uint64(len(u.frameTrace))]
		out = append(out, map[string]any{
			"frame": int(r.frame), "frames": int64(r.frames), "link": int64(r.link),
			"status_before": int(r.statusBefore), "status_after": int(r.statusAfter), "interrupt": int(r.interrupt),
			"tds": int64(r.tds), "active": int64(r.active), "ioc": int64(r.ioc),
			"last_qh": int64(r.qh), "last_td": int64(r.td), "last_td_status": int64(r.tdStatus), "last_token": int64(r.token),
		})
	}
	return out
}
