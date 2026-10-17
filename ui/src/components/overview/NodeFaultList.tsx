import React from 'react';
import { Server, AlertTriangle, ArrowRight, ShieldX } from 'lucide-react';
import { FleetNode } from '../../api/client';
import { href } from '../../router';
import { relativeTime } from '../ui';

interface Props {
  nodes?: FleetNode[];
  locale?: string;
}

export const NodeFaultList: React.FC<Props> = ({ nodes, locale = 'vi' }) => {
  if (!nodes || nodes.length === 0) {
    return null;
  }

  // Faulty nodes: offline or bundle state FAILED
  const faultyNodes = nodes.filter(
    (n) => !n.revoked && (!n.online || n.bundle_state === 'FAILED')
  );

  if (faultyNodes.length === 0) {
    return null;
  }

  return (
    <div
      data-testid="node-fault-panel"
      className="mb-6 p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 shadow-sm"
    >
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
          <AlertTriangle className="w-4 h-4" />
          <span>Cảnh báo Sự cố Node ({faultyNodes.length})</span>
        </div>
        <a
          href={href({ page: 'fleet' })}
          className="text-xs text-rose-300 hover:text-rose-200 font-medium flex items-center gap-1"
        >
          <span>Xem tất cả trên Fleet</span>
          <ArrowRight className="w-3 h-3" />
        </a>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {faultyNodes.map((n) => {
          const isFailedBundle = n.bundle_state === 'FAILED';
          const isOffline = !n.online;

          return (
            <div
              key={n.id}
              data-testid={`faulty-node-${n.id}`}
              className="p-3 rounded-lg bg-surface/90 border border-line flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs font-bold text-ink truncate flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-muted" />
                  <span title={n.hostname || n.id}>{n.hostname || n.id}</span>
                </span>
                <span
                  className={`font-mono text-[10px] px-1.5 py-0.5 rounded border uppercase font-semibold ${
                    isFailedBundle
                      ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                  }`}
                >
                  {isFailedBundle ? 'Bundle Failed' : 'Offline'}
                </span>
              </div>

              <div className="mt-2 text-[11px] text-muted flex items-center justify-between">
                <span>
                  {isOffline ? (
                    `Mất tín hiệu: ${n.last_seen_time ? relativeTime(n.last_seen_time, locale) : 'chưa từng'}`
                  ) : (
                    <span className="flex items-center gap-1 text-rose-400">
                      <ShieldX className="w-3 h-3" />
                      Lỗi nạp bundle
                    </span>
                  )}
                </span>
                <span className="font-mono text-[10px] text-faint">
                  v{n.bundle_version ?? '—'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
