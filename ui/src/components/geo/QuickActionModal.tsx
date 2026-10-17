import React, { useState, useEffect } from 'react';
import { X, ShieldAlert, ShieldCheck, Zap, AlertCircle, CheckCircle2, ArrowRight } from 'lucide-react';
import { apiClient, Policy, QuickRuleRequest, QuickRuleResponse, ApiError } from '../../api/client';
import { href } from '../../router';

interface QuickActionModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialType?: 'geo' | 'asn';
  initialTarget?: string;
  initialAction?: 'block' | 'challenge';
  policies: Policy[];
  currentPolicyId?: string;
  onSuccess?: (resp: QuickRuleResponse) => void;
}

export const QuickActionModal: React.FC<QuickActionModalProps> = ({
  isOpen,
  onClose,
  initialType = 'geo',
  initialTarget = '',
  initialAction = 'block',
  policies,
  currentPolicyId = '',
  onSuccess,
}) => {
  const [type, setType] = useState<'geo' | 'asn'>(initialType);
  const [target, setTarget] = useState<string>(initialTarget);
  const [action, setAction] = useState<'block' | 'challenge'>(initialAction);
  const [policyId, setPolicyId] = useState<string>(currentPolicyId || (policies[0]?.id ?? ''));
  const [reason, setReason] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QuickRuleResponse | null>(null);

  useEffect(() => {
    if (isOpen) {
      setType(initialType);
      setTarget(initialTarget);
      setAction(initialAction);
      setPolicyId(currentPolicyId || (policies[0]?.id ?? ''));
      setReason(initialTarget ? `SOC mitigation for ${initialType.toUpperCase()}: ${initialTarget}` : '');
      setError(null);
      setResult(null);
      setLoading(false);
    }
  }, [isOpen, initialType, initialTarget, initialAction, currentPolicyId, policies]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      setError(type === 'geo' ? 'Vui lòng nhập mã quốc gia (ISO 2 ký tự)' : 'Vui lòng nhập ASN');
      return;
    }
    if (!policyId) {
      setError('Vui lòng chọn Policy cần áp dụng');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const req: QuickRuleRequest = {
        type,
        target: target.trim(),
        action,
        reason: reason.trim() || undefined,
      };

      const resp = await apiClient.quickRule(policyId, req);
      setResult(resp);
      if (onSuccess) {
        onSuccess(resp);
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`${err.message} (HTTP ${err.code})`);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Không thể tạo rule nhanh');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-labelledby="quick-action-title"
    >
      <div className="relative w-full max-w-lg bg-[#0b0f19] border border-line rounded-2xl shadow-2xl overflow-hidden text-ink">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-line bg-surface/50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <Zap className="w-4 h-4" />
            </div>
            <div>
              <h2 id="quick-action-title" className="text-sm font-bold tracking-wide">
                Tạo Rule Chặn / Thử Thách Nhanh
              </h2>
              <p className="text-[11px] text-muted">
                Tự động tạo bản nháp (Draft Policy) cho luồng kiểm duyệt 4 mắt
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted hover:text-ink hover:bg-sunken transition-colors"
            aria-label="Đóng"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4">
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/25 text-rose-400 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {result ? (
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/25 space-y-3">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold">
                <CheckCircle2 className="w-5 h-5 shrink-0" />
                <span>Tạo bản nháp thành công!</span>
              </div>
              <p className="text-xs text-muted leading-relaxed">
                {result.message}
              </p>
              <div className="pt-2 flex items-center justify-between">
                <a
                  href={href({ page: 'policies', query: { policy_id: result.policy_id } })}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-accent hover:underline font-mono"
                >
                  Xem chính sách {result.policy_id} (v{result.version})
                  <ArrowRight className="w-3.5 h-3.5" />
                </a>
                <button
                  type="button"
                  onClick={onClose}
                  className="btn btn-sm"
                >
                  Hoàn tất
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4 text-xs">
              {/* Type Switcher */}
              <div>
                <label className="block text-[11px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                  Đối tượng kiểm soát
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setType('geo');
                      if (type !== 'geo') setTarget('');
                    }}
                    className={`py-2 px-3 rounded-lg border text-center font-medium transition-all ${
                      type === 'geo'
                        ? 'bg-accent/15 border-accent text-accent font-semibold shadow-sm'
                        : 'bg-sunken border-line text-muted hover:border-slate-600'
                    }`}
                  >
                    Quốc gia (Geo Country)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setType('asn');
                      if (type !== 'asn') setTarget('');
                    }}
                    className={`py-2 px-3 rounded-lg border text-center font-medium transition-all ${
                      type === 'asn'
                        ? 'bg-accent/15 border-accent text-accent font-semibold shadow-sm'
                        : 'bg-sunken border-line text-muted hover:border-slate-600'
                    }`}
                  >
                    Mạng ASN (Autonomous System)
                  </button>
                </div>
              </div>

              {/* Target Input */}
              <div>
                <label htmlFor="quick-target-input" className="block text-[11px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                  {type === 'geo' ? 'Mã Quốc gia ISO (2 chữ cái hoa)' : 'Số hiệu mạng ASN'}
                </label>
                <input
                  id="quick-target-input"
                  data-testid="quick-target-input"
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value.toUpperCase())}
                  placeholder={type === 'geo' ? 'Ví dụ: KP, CN, RU, US...' : 'Ví dụ: 13335 hoặc AS7552'}
                  className="field w-full font-mono text-sm uppercase tracking-wider"
                  required
                />
              </div>

              {/* Action Selection */}
              <div>
                <label className="block text-[11px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                  Mức độ hành vi (Action)
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    data-testid="action-block-btn"
                    onClick={() => setAction('block')}
                    className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl border text-center font-medium transition-all ${
                      action === 'block'
                        ? 'bg-rose-500/15 border-rose-500 text-rose-400 font-bold shadow-[0_0_10px_rgba(244,63,94,0.2)]'
                        : 'bg-sunken border-line text-muted hover:border-slate-600'
                    }`}
                  >
                    <ShieldAlert className="w-4 h-4" />
                    <span>Chặn (Block 403)</span>
                  </button>
                  <button
                    type="button"
                    data-testid="action-challenge-btn"
                    onClick={() => setAction('challenge')}
                    className={`flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl border text-center font-medium transition-all ${
                      action === 'challenge'
                        ? 'bg-amber-500/15 border-amber-500 text-amber-400 font-bold shadow-[0_0_10px_rgba(245,158,11,0.2)]'
                        : 'bg-sunken border-line text-muted hover:border-slate-600'
                    }`}
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>Thử thách (Challenge)</span>
                  </button>
                </div>
              </div>

              {/* Target Policy */}
              <div>
                <label htmlFor="quick-policy-select" className="block text-[11px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                  Chính sách áp dụng (Policy)
                </label>
                <select
                  id="quick-policy-select"
                  data-testid="quick-policy-select"
                  value={policyId}
                  onChange={(e) => setPolicyId(e.target.value)}
                  className="field w-full font-mono"
                  required
                >
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name ? `${p.name} (${p.id})` : p.id}
                    </option>
                  ))}
                </select>
              </div>

              {/* Reason / Note */}
              <div>
                <label htmlFor="quick-reason-input" className="block text-[11px] font-semibold text-muted uppercase tracking-wider mb-1.5">
                  Lý do điều chỉnh (Audit Trail Note)
                </label>
                <input
                  id="quick-reason-input"
                  data-testid="quick-reason-input"
                  type="text"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Ghi chú cho bộ phận phê duyệt (VD: DDoS surge từ ASN này)"
                  className="field w-full text-xs"
                />
              </div>

              {/* Action Buttons */}
              <div className="pt-2 flex items-center justify-end gap-2.5">
                <button
                  type="button"
                  onClick={onClose}
                  className="btn"
                  disabled={loading}
                >
                  Hủy
                </button>
                <button
                  type="submit"
                  data-testid="quick-submit-btn"
                  className="btn bg-rose-600 hover:bg-rose-500 text-white font-semibold flex items-center gap-1.5 shadow-md shadow-rose-950/40"
                  disabled={loading}
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>{loading ? 'Đang tạo bản nháp...' : 'Tạo Bản Nháp (Draft)'}</span>
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
