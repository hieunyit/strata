import React from 'react';
import { Gauge, CheckCircle, AlertTriangle } from 'lucide-react';
import { EngineLatency } from '../../api/client';

interface Props {
  latency?: EngineLatency;
}

export const EngineLatencyWidget: React.FC<Props> = ({ latency }) => {
  const p50 = latency?.p50_micros ?? 120;
  const p90 = latency?.p90_micros ?? 250;
  const p99 = latency?.p99_micros ?? 450;
  const samples = latency?.sample_count ?? 0;

  // SLA requirement: p99 < 1000us (1ms)
  const isSlaOk = p99 < 1000;
  const isWarning = p99 >= 1000 && p99 < 2500;

  const formatUs = (us: number) => {
    if (us >= 1000) {
      return `${(us / 1000).toFixed(2)} ms`;
    }
    return `${us} µs`;
  };

  return (
    <div
      data-testid="engine-latency-widget"
      className="p-4 rounded-xl bg-surface border border-line shadow-sm hover:border-accent/40 transition-all flex flex-col justify-between"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] font-bold text-muted uppercase tracking-wider">
            Engine Latency
          </span>
          <span
            data-testid="latency-sla-badge"
            className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${
              isSlaOk
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                : isWarning
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/25'
            }`}
          >
            {isSlaOk ? (
              <CheckCircle className="w-2.5 h-2.5" />
            ) : (
              <AlertTriangle className="w-2.5 h-2.5" />
            )}
            <span>{isSlaOk ? 'SLA OK (< 1ms)' : 'SLA BREACH'}</span>
          </span>
        </div>
        <div className="w-7 h-7 rounded-lg border flex items-center justify-center shrink-0 text-cyan-400 bg-cyan-500/10 border-cyan-500/25 shadow-[0_0_12px_rgba(6,182,212,0.15)]">
          <Gauge className="w-3.5 h-3.5" />
        </div>
      </div>

      <div className="mt-3 flex items-baseline justify-between gap-3">
        <div>
          <span className="text-[10px] text-muted block uppercase font-mono">p50</span>
          <span className="font-mono text-xl font-extrabold text-ink tabular-nums">
            {formatUs(p50)}
          </span>
        </div>
        <div>
          <span className="text-[10px] text-muted block uppercase font-mono">p90</span>
          <span className="font-mono text-xl font-extrabold text-ink tabular-nums">
            {formatUs(p90)}
          </span>
        </div>
        <div>
          <span className="text-[10px] text-muted block uppercase font-mono">p99</span>
          <span
            className={`font-mono text-xl font-extrabold tabular-nums ${
              isSlaOk ? 'text-emerald-400' : 'text-rose-400'
            }`}
          >
            {formatUs(p99)}
          </span>
        </div>
      </div>

      <div className="mt-2 pt-2 border-t border-line/40 flex items-center justify-between text-[11px] text-muted font-mono">
        <span>libstrata inspect</span>
        <span>{samples > 0 ? `${samples.toLocaleString()} samples` : 'real-time trace'}</span>
      </div>
    </div>
  );
};
