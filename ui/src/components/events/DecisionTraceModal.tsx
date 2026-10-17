import React, { useEffect, useState } from 'react';
import { X, ShieldAlert, Zap, ExternalLink, Globe, Server } from 'lucide-react';
import { apiClient, Event, GetEventResponse } from '../../api/client';
import { EventTrace } from './EventTrace';
import { href } from '../../router';

interface DecisionTraceModalProps {
  event: Event | null;
  onClose: () => void;
  onQuickAction?: (type: 'geo' | 'asn', target: string, action?: 'block' | 'challenge') => void;
}

export const DecisionTraceModal: React.FC<DecisionTraceModalProps> = ({
  event,
  onClose,
  onQuickAction,
}) => {
  const [details, setDetails] = useState<GetEventResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!event) {
      setDetails(null);
      setError(null);
      return;
    }

    let active = true;
    setError(null);

    apiClient
      .getEvent(event.block_id)
      .then((res) => {
        if (active) {
          setDetails(res);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err instanceof Error ? err.message : String(err));
        }
      });

    return () => {
      active = false;
    };
  }, [event]);

  if (!event) return null;

  const currentEvent = details?.event ?? event;
  const rules = details?.rules;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-labelledby="trace-modal-title"
    >
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-[#0b0f19] border border-line rounded-2xl shadow-2xl overflow-hidden flex flex-col text-ink">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-line bg-surface/60 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 id="trace-modal-title" className="text-sm font-bold tracking-wide">
                  Decision Trace — Block ID
                </h2>
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-sunken border border-line text-accent font-bold">
                  {event.block_id}
                </span>
              </div>
              <p className="text-[11px] text-muted">
                Chi tiết phân tích phát hiện tấn công, rule vi phạm và đoạn dữ liệu vi phạm
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <a
              href={href({ page: 'events', query: { client_ip: event.client_ip } })}
              target="_blank"
              rel="noreferrer"
              className="btn btn-sm text-xs font-mono"
              title="Mở toàn bộ sự kiện của IP này"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Events Page</span>
            </a>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted hover:text-ink hover:bg-sunken transition-colors"
              aria-label="Đóng"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Quick Mitigation Action Bar */}
        {onQuickAction && (event.country_iso || event.asn) && (
          <div className="px-6 py-2.5 bg-rose-950/20 border-b border-rose-900/30 flex flex-wrap items-center justify-between gap-2 text-xs">
            <div className="flex items-center gap-2 text-rose-300 font-medium">
              <Zap className="w-3.5 h-3.5 text-rose-400" />
              <span>Hành động phòng vệ nhanh từ sự kiện này:</span>
            </div>
            <div className="flex items-center gap-2">
              {event.country_iso && (
                <button
                  type="button"
                  data-testid="trace-quick-block-country"
                  onClick={() => onQuickAction('geo', event.country_iso ?? '', 'block')}
                  className="px-2.5 py-1 rounded-lg bg-rose-500/20 text-rose-300 border border-rose-500/35 hover:bg-rose-500/30 font-mono text-[11px] flex items-center gap-1.5 transition-colors"
                >
                  <Globe className="w-3 h-3" />
                  <span>Chặn Quốc gia: {event.country_iso}</span>
                </button>
              )}
              {event.asn && (
                <button
                  type="button"
                  data-testid="trace-quick-block-asn"
                  onClick={() => onQuickAction('asn', String(event.asn), 'block')}
                  className="px-2.5 py-1 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/35 hover:bg-amber-500/30 font-mono text-[11px] flex items-center gap-1.5 transition-colors"
                >
                  <Server className="w-3 h-3" />
                  <span>Chặn ASN: AS{event.asn}</span>
                </button>
              )}
            </div>
          </div>
        )}

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-4">
          {error && (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 text-amber-400 text-xs">
              Lưu ý: Không tải được đầy đủ catalog rule từ máy chủ ({error}). Hiển thị thông tin cơ sở của sự kiện:
            </div>
          )}

          <EventTrace event={currentEvent} rules={rules} />
        </div>
      </div>
    </div>
  );
};
