package agent

import "github.com/prometheus/client_golang/prometheus"

// collector exports the agent's own counters: event socket, spool and
// pusher.
type collector struct{ a *Agent }

func desc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc("strata_agent_"+name, help, nil, nil)
}

var (
	dReceived  = desc("events_received_total", "Datagrams read from the event socket.")
	dInvalid   = desc("events_invalid_total", "Datagrams that did not decode or lacked a Block ID.")
	dTruncated = desc("events_truncated_total", "Datagrams above 8 KB.")
	dSpoolB    = desc("spool_bytes", "Bytes held in the spool.")
	dUnacked   = desc("spool_unacked_batches", "Batches spooled but not acked by the control plane.")
	dLastSeq   = desc("spool_last_seq", "Seq of the newest spooled batch.")
	dAckedSeq  = desc("acked_seq", "Highest seq acked by the control plane.")
	dDropB     = desc("spool_dropped_batches_total", "Unacked batches dropped because the spool was full.")
	dDropE     = desc("spool_dropped_events_total", "Events in those batches.")
	dSent      = desc("push_batches_sent_total", "Batches sent on PushEvents, resends included.")
	dReconn    = desc("push_reconnects_total", "PushEvents streams that ended and were retried.")
	dThrottle  = desc("push_throttled_total", "Streams the control plane refused with RESOURCE_EXHAUSTED.")
	dWindow    = desc("push_window", "Batches allowed in flight.")
)

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dReceived, dInvalid, dTruncated, dSpoolB, dUnacked, dLastSeq,
		dAckedSeq, dDropB, dDropE, dSent, dReconn, dThrottle, dWindow} {
		ch <- d
	}
}

func (c collector) Collect(ch chan<- prometheus.Metric) {
	counter := func(d *prometheus.Desc, v uint64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v))
	}
	gauge := func(d *prometheus.Desc, v float64) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v)
	}
	sc, pc, st := &c.a.Socket.C, &c.a.Pusher.C, c.a.Spool.Stats()
	counter(dReceived, sc.Received.Load())
	counter(dInvalid, sc.Invalid.Load())
	counter(dTruncated, sc.Truncated.Load())
	gauge(dSpoolB, float64(st.Bytes))
	gauge(dUnacked, float64(st.LastSeq-st.AckedSeq))
	gauge(dLastSeq, float64(st.LastSeq))
	gauge(dAckedSeq, float64(st.AckedSeq))
	counter(dDropB, st.DroppedBatches)
	counter(dDropE, st.DroppedEvents)
	counter(dSent, pc.BatchesSent.Load())
	counter(dReconn, pc.Reconnects.Load())
	counter(dThrottle, pc.Throttled.Load())
	gauge(dWindow, float64(pc.Window.Load()))
}
