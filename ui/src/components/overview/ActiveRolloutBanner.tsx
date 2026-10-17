import React from 'react';
import { Layers, ArrowRight, AlertCircle, PlayCircle, PauseCircle } from 'lucide-react';
import { Rollout } from '../../api/client';
import { href } from '../../router';

interface Props {
  rollout?: Rollout;
}

export const ActiveRolloutBanner: React.FC<Props> = ({ rollout }) => {
  if (!rollout || !['RUNNING', 'PAUSED', 'FAILED'].includes(rollout.state ?? '')) {
    return null;
  }

  const isFailed = rollout.state === 'FAILED';
  const isPaused = rollout.state === 'PAUSED';

  const stateColors = isFailed
    ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
    : isPaused
    ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
    : 'bg-accent/10 border-accent/30 text-accent';

  return (
    <div
      data-testid="active-rollout-banner"
      className={`mb-6 p-4 rounded-xl border flex flex-wrap items-center justify-between gap-4 transition-all shadow-sm ${stateColors}`}
    >
      <div className="flex items-center gap-3 min-w-0">
        <div className="w-8 h-8 rounded-lg bg-surface/80 border border-line flex items-center justify-center shrink-0">
          {isFailed ? (
            <AlertCircle className="w-4 h-4 text-rose-400" />
          ) : isPaused ? (
            <PauseCircle className="w-4 h-4 text-amber-400" />
          ) : (
            <PlayCircle className="w-4 h-4 text-accent animate-pulse" />
          )}
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-bold text-sm text-ink flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5" />
              <span>Rollout Đang Chạy: #{rollout.id}</span>
            </span>
            <span className="font-mono text-xs px-2 py-0.5 rounded bg-surface border border-line text-ink font-semibold">
              Bundle v{rollout.bundle_version ?? '0.0.0'}
            </span>
            <span
              className={`font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${
                isFailed
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                  : isPaused
                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                  : 'bg-accent/20 text-accent border-accent/30'
              }`}
            >
              {rollout.state}
            </span>
          </div>
          <p className="text-xs text-muted mt-0.5">
            Đợt cập nhật chính sách đang được triển khai trên cụm proxy nodes
            {rollout.current_wave !== undefined && rollout.waves ? ` (Làn sóng: ${rollout.current_wave + 1}/${rollout.waves.length})` : ''}.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <a
          href={href({ page: 'fleet' })}
          className="btn btn-sm text-xs font-semibold flex items-center gap-1 bg-surface hover:bg-sunken border border-line text-ink shadow-sm"
        >
          <span>Quản lý Fleet</span>
          <ArrowRight className="w-3 h-3" />
        </a>
      </div>
    </div>
  );
};
