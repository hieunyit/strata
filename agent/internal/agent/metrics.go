package agent

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/strata/strata/agent/internal/fallback"
)

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
	dCtrlUp    = desc("control_connected", "1 while the control stream to the control plane is open.")
	dCertEnd   = desc("cert_not_after_seconds", "Expiry of the node certificate, Unix time.")
	dShadow    = desc("force_shadow_active", "1 while a ForceShadow command holds this node (or one of its policies) in shadow.")
	dBundleAct = desc("bundle_active_version", "Bundle version the agent installed and the workers confirmed.")
	dQlen      = desc("unix_max_dgram_qlen", "net.unix.max_dgram_qlen read at start (0: unknown); the event socket needs 8192.")
	dDisabled  = desc("disabled_rules", "Rules switched off on this node by the emergency kill switch.")
	dSamples   = desc("replay_samples_total", "Replay samples received from the NGINX workers (W12-N-01).")
	dReplay    = desc("replay_rate_bp", "Share of requests the workers sample for replay, basis points (0: off or not told yet).")
	dFbActive  = desc("fallback_active", "1 while the node fallback holds every policy in shadow; only a clear from the control plane ends it.")
	dFallback  = prometheus.NewDesc("strata_agent_fallback_triggers_total", "Times the node fallback forced every policy into shadow, by reason.", []string{"reason"}, nil)
)

func (c collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{dReceived, dInvalid, dTruncated, dSpoolB, dUnacked, dLastSeq,
		dAckedSeq, dDropB, dDropE, dSent, dReconn, dThrottle, dWindow, dCtrlUp, dCertEnd, dShadow, dBundleAct, dQlen, dFallback, dDisabled, dFbActive, dSamples, dReplay} {
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
	gauge(dQlen, float64(c.a.dgramQlen))
	if c.a.Control != nil {
		gauge(dCtrlUp, b2f(c.a.Control.Connected()))
	}
	if c.a.identity != nil {
		if cert := c.a.identity.Certificate(); cert != nil && cert.Leaf != nil {
			gauge(dCertEnd, float64(cert.Leaf.NotAfter.Unix()))
		}
	}
	if c.a.ForceShadow != nil {
		st := c.a.ForceShadow.Snapshot()
		gauge(dShadow, b2f(!st.All.IsZero() || len(st.Policies) > 0))
		gauge(dFbActive, b2f(st.Fallback != nil))
	}
	if c.a.Bundles != nil {
		gauge(dBundleAct, float64(c.a.Bundles.Active()))
	}
	counter(dSamples, sc.Samples.Load())
	if c.a.Replay != nil {
		rate := 0.0
		if s := c.a.Replay.Current(); s != nil {
			rate = float64(s.Rate)
		}
		gauge(dReplay, rate)
	}
	if c.a.KillSwitch != nil {
		gauge(dDisabled, float64(len(c.a.KillSwitch.Rules())))
	}
	if c.a.Fallback != nil {
		t := c.a.Fallback.Triggers()
		for _, r := range []string{fallback.ReasonBlockRate, fallback.ReasonErrors, fallback.ReasonBudget} {
			ch <- prometheus.MustNewConstMetric(dFallback, prometheus.CounterValue, float64(t[r]), r)
		}
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
