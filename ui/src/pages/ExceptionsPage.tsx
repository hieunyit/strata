import React, { useState } from 'react';
import { Clock, CheckCircle, Trash2, CalendarPlus, ShieldAlert } from 'lucide-react';
import { PageShell } from './PageShell';

export interface ExceptionItem {
  id: string;
  ruleId: number;
  ruleName: string;
  targetPath: string;
  targetIp?: string;
  reason: string;
  createdBy: string;
  expiresAt: string; // ISO date string
  isExpiringSoon: boolean;
}

const INITIAL_EXCEPTIONS: ExceptionItem[] = [
  {
    id: 'exc-942100-checkout',
    ruleId: 942100,
    ruleName: 'SQL Injection: Common SQL Operator',
    targetPath: '/api/v1/checkout/process',
    reason: 'False positive trên chuỗi mô tả voucher giảm giá có chữ AND',
    createdBy: 'soc-analyst-1',
    expiresAt: new Date(Date.now() + 24 * 3600 * 1000).toISOString(), // 24h (Expiring soon!)
    isExpiringSoon: true,
  },
  {
    id: 'exc-941100-blog',
    ruleId: 941100,
    ruleName: 'XSS Attack: Script Tag Detected',
    targetPath: '/api/v1/admin/posts/preview',
    reason: 'Trang soạn thảo CMS Markdown nội bộ cho phép tag HTML mẫu',
    createdBy: 'admin-lead',
    expiresAt: new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString(), // 14 days
    isExpiringSoon: false,
  },
  {
    id: 'exc-600003-search',
    ruleId: 600003,
    ruleName: 'API Schema: Undeclared Query Parameter',
    targetPath: '/api/v1/search',
    reason: 'Bổ sung tạm thời tham số tracking utm_source trước khi cập nhật OpenAPI spec',
    createdBy: 'product-owner',
    expiresAt: new Date(Date.now() + 36 * 3600 * 1000).toISOString(), // 36h (Expiring soon!)
    isExpiringSoon: true,
  },
];

export const ExceptionsPage: React.FC = () => {
  const [exceptions, setExceptions] = useState<ExceptionItem[]>(INITIAL_EXCEPTIONS);

  const expiringCount = exceptions.filter((e) => e.isExpiringSoon).length;

  const handleExtend = (id: string) => {
    setExceptions((prev) =>
      prev.map((e) => {
        if (e.id === id) {
          const nextDate = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
          return { ...e, expiresAt: nextDate, isExpiringSoon: false };
        }
        return e;
      })
    );
  };

  const handleRevoke = (id: string) => {
    setExceptions((prev) => prev.filter((e) => e.id !== id));
  };

  return (
    <PageShell active="exceptions">
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white">Rule Exceptions & Exclusions</h2>
          <p className="text-xs text-muted-foreground mt-1">Quản trị ngoại lệ rule, loại trừ path/IP và theo dõi hạn sử dụng (W21-F-01)</p>
        </div>
        {/* Expiring Soon Banner */}
        {expiringCount > 0 && (
          <div className="flex items-center justify-between p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300">
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
              <div>
                <span className="font-bold">Cảnh báo Ngoại lệ Sắp Hết Hạn: </span>
                <span>Có {expiringCount} ngoại lệ rule sẽ hết hiệu lực trong vòng 48 giờ tới. Vui lòng rà soát và gia hạn hoặc thu hồi.</span>
              </div>
            </div>
          </div>
        )}

        {/* Exceptions Table */}
        <div className="rounded-lg border border-border overflow-hidden bg-card">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/50 text-xs font-semibold uppercase tracking-wider text-muted-foreground border-b border-border">
              <tr>
                <th className="px-4 py-3">Exception ID</th>
                <th className="px-4 py-3">Rule ID</th>
                <th className="px-4 py-3">Route / Path</th>
                <th className="px-4 py-3">Lý do ngoại lệ</th>
                <th className="px-4 py-3">Người tạo</th>
                <th className="px-4 py-3">Hạn hiệu lực</th>
                <th className="px-4 py-3">Trạng thái</th>
                <th className="px-4 py-3 text-right">Thao tác</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {exceptions.map((exc) => {
                const expDate = new Date(exc.expiresAt);
                return (
                  <tr key={exc.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs font-bold text-cyan-400">
                      {exc.id}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      #{exc.ruleId}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-300">
                      {exc.targetPath}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground max-w-xs truncate" title={exc.reason}>
                      {exc.reason}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {exc.createdBy}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {expDate.toLocaleDateString()} {expDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-4 py-3">
                      {exc.isExpiringSoon ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                          <Clock className="w-3 h-3" />
                          Sắp hết hạn
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          <CheckCircle className="w-3 h-3" />
                          Còn hạn
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right space-x-2">
                      <button
                        onClick={() => handleExtend(exc.id)}
                        className="px-2.5 py-1 text-xs font-semibold rounded bg-muted hover:bg-muted/80 text-foreground inline-flex items-center gap-1 transition-colors"
                        title="Gia hạn thêm 30 ngày"
                      >
                        <CalendarPlus className="w-3 h-3" />
                        Gia hạn
                      </button>
                      <button
                        onClick={() => handleRevoke(exc.id)}
                        className="px-2.5 py-1 text-xs font-semibold rounded bg-rose-500/20 hover:bg-rose-500/40 text-rose-300 border border-rose-500/30 inline-flex items-center gap-1 transition-colors"
                        title="Thu hồi ngoại lệ ngay lập tức"
                      >
                        <Trash2 className="w-3 h-3" />
                        Thu hồi
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </PageShell>
  );
};
