import React, { useState, useMemo } from 'react';
import { AlertTriangle, Zap, CheckCircle2, Search, Ban, RefreshCw, Clock } from 'lucide-react';
import { PageShell } from './PageShell';

export interface RuleItem {
  id: number;
  name: string;
  category: string;
  layer: 'protocol' | 'managed' | 'bot' | 'schema' | 'custom';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'active' | 'staging' | 'disabled';
  matchCount: number;
  fpCount: number;
  avgCpuCostUs: number;
  paranoia: number;
}

const INITIAL_RULES: RuleItem[] = [
  // Core Protocol
  { id: 100001, name: 'HTTP Framing / Host Validation', category: 'Protocol', layer: 'protocol', severity: 'CRITICAL', status: 'active', matchCount: 1420, fpCount: 0, avgCpuCostUs: 1.2, paranoia: 1 },
  { id: 100002, name: 'Content-Length and Transfer-Encoding Conflict', category: 'Protocol', layer: 'protocol', severity: 'CRITICAL', status: 'active', matchCount: 310, fpCount: 0, avgCpuCostUs: 0.8, paranoia: 1 },
  { id: 100021, name: 'Arguments Limit Exceeded (Oversize)', category: 'Protocol', layer: 'protocol', severity: 'HIGH', status: 'active', matchCount: 88, fpCount: 0, avgCpuCostUs: 2.1, paranoia: 1 },

  // Positive Model (OpenAPI 600000+)
  { id: 600001, name: 'API Schema: Unknown Endpoint', category: 'Positive Model', layer: 'schema', severity: 'CRITICAL', status: 'active', matchCount: 4210, fpCount: 0, avgCpuCostUs: 0.9, paranoia: 1 },
  { id: 600002, name: 'API Schema: Method Not Allowed', category: 'Positive Model', layer: 'schema', severity: 'CRITICAL', status: 'active', matchCount: 125, fpCount: 0, avgCpuCostUs: 0.4, paranoia: 1 },
  { id: 600003, name: 'API Schema: Undeclared Query Parameter', category: 'Positive Model', layer: 'schema', severity: 'HIGH', status: 'active', matchCount: 840, fpCount: 2, avgCpuCostUs: 1.5, paranoia: 1 },
  { id: 600004, name: 'API Schema: Missing Required Field', category: 'Positive Model', layer: 'schema', severity: 'HIGH', status: 'active', matchCount: 650, fpCount: 1, avgCpuCostUs: 2.8, paranoia: 1 },
  { id: 600005, name: 'API Schema: Undeclared Body Field', category: 'Positive Model', layer: 'schema', severity: 'HIGH', status: 'active', matchCount: 190, fpCount: 0, avgCpuCostUs: 3.1, paranoia: 1 },

  // Bot Rules (500000+)
  { id: 500001, name: 'Good Bot Impersonation (Spoofed User-Agent)', category: 'Bot Defense', layer: 'bot', severity: 'HIGH', status: 'active', matchCount: 2340, fpCount: 0, avgCpuCostUs: 1.4, paranoia: 1 },
  { id: 500010, name: 'Credential Stuffing Automated Login Rate', category: 'Bot Defense', layer: 'bot', severity: 'CRITICAL', status: 'active', matchCount: 1890, fpCount: 0, avgCpuCostUs: 4.2, paranoia: 1 },
  { id: 500020, name: 'Headless Scraper Challenge Bypass Attempt', category: 'Bot Defense', layer: 'bot', severity: 'HIGH', status: 'active', matchCount: 512, fpCount: 0, avgCpuCostUs: 1.8, paranoia: 1 },

  // CRS Signatures (900000+)
  { id: 942100, name: 'SQL Injection: Common SQL Operator / Injection Vector', category: 'CRS SQLi', layer: 'managed', severity: 'CRITICAL', status: 'active', matchCount: 18450, fpCount: 4, avgCpuCostUs: 8.5, paranoia: 1 },
  { id: 941100, name: 'XSS Attack: Script Tag or Event Handler Detected', category: 'CRS XSS', layer: 'managed', severity: 'CRITICAL', status: 'active', matchCount: 9230, fpCount: 2, avgCpuCostUs: 7.2, paranoia: 1 },
  { id: 932100, name: 'Remote Command Execution: Unix Shell Command', category: 'CRS RCE', layer: 'managed', severity: 'CRITICAL', status: 'active', matchCount: 3120, fpCount: 1, avgCpuCostUs: 9.1, paranoia: 1 },
  { id: 930100, name: 'Path Traversal / LFI: Directory Traversal Dot-Dot', category: 'CRS LFI', layer: 'managed', severity: 'CRITICAL', status: 'active', matchCount: 4100, fpCount: 0, avgCpuCostUs: 4.5, paranoia: 1 },

  // Virtual Patches (700000+)
  { id: 700001, name: 'Virtual Patch: CVE-2023-44487 HTTP/2 Rapid Reset', category: 'Virtual Patch', layer: 'protocol', severity: 'CRITICAL', status: 'active', matchCount: 760, fpCount: 0, avgCpuCostUs: 0.6, paranoia: 1 },
  { id: 700002, name: 'Virtual Patch: Spring4Shell ClassLoader Access RCE', category: 'Virtual Patch', layer: 'managed', severity: 'CRITICAL', status: 'active', matchCount: 110, fpCount: 0, avgCpuCostUs: 5.4, paranoia: 1 },
];

export const RulesPage: React.FC = () => {
  const [rules, setRules] = useState<RuleItem[]>(INITIAL_RULES);
  const [selectedLayer, setSelectedLayer] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'staging' | 'disabled'>('all');
  const [emergencyTarget, setEmergencyTarget] = useState<RuleItem | null>(null);
  const [disableReason, setDisableReason] = useState('');

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (selectedLayer !== 'all' && r.layer !== selectedLayer) return false;
      if (statusFilter !== 'all' && r.status !== statusFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          r.id.toString().includes(q) ||
          r.name.toLowerCase().includes(q) ||
          r.category.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [rules, selectedLayer, statusFilter, searchQuery]);

  const handleToggleEmergency = (rule: RuleItem) => {
    if (rule.status === 'disabled') {
      // Re-enable
      setRules((prev) =>
        prev.map((item) => (item.id === rule.id ? { ...item, status: 'active' } : item))
      );
    } else {
      // Open Emergency Disable modal
      setEmergencyTarget(rule);
      setDisableReason('');
    }
  };

  const confirmEmergencyDisable = () => {
    if (!emergencyTarget) return;
    setRules((prev) =>
      prev.map((item) =>
        item.id === emergencyTarget.id ? { ...item, status: 'disabled' } : item
      )
    );
    setEmergencyTarget(null);
  };

  return (
    <PageShell active="rules">
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white">Rules & Signatures</h2>
          <p className="text-xs text-muted-foreground mt-1">Danh mục rule, chỉ số sức khỏe, độ trễ CPU và nút tắt khẩn cấp (W21-F-01)</p>
        </div>
        {/* Layer Tabs */}
        <div className="flex items-center gap-2 border-b border-border pb-2 overflow-x-auto">
          {[
            { id: 'all', label: 'Tất cả Rule' },
            { id: 'protocol', label: 'Protocol (100000+)' },
            { id: 'managed', label: 'CRS Signatures (900000+)' },
            { id: 'bot', label: 'Bot Defense (500000+)' },
            { id: 'schema', label: 'OpenAPI Positive Model (600000+)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSelectedLayer(tab.id)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap ${
                selectedLayer === tab.id
                  ? 'bg-cyan-500 text-white shadow-sm'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-card p-4 rounded-lg border border-border">
          <div className="relative w-full sm:w-80">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Tìm theo Rule ID, tên, danh mục..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-sm bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <span className="text-xs text-muted-foreground whitespace-nowrap">Trạng thái:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as any)}
              className="px-2.5 py-1.5 text-xs bg-background border border-input rounded-md focus:outline-none"
            >
              <option value="all">Tất cả</option>
              <option value="active">Active (Enforce)</option>
              <option value="staging">Staging (Log Only)</option>
              <option value="disabled">Disabled (Tắt)</option>
            </select>
          </div>
        </div>

        {/* Rules Table */}
        <div className="rounded-lg border border-border overflow-hidden bg-card">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/50 text-xs font-semibold uppercase tracking-wider text-muted-foreground border-b border-border">
              <tr>
                <th className="px-4 py-3">Rule ID</th>
                <th className="px-4 py-3">Tên & Mô tả</th>
                <th className="px-4 py-3">Danh mục</th>
                <th className="px-4 py-3">Mức độ</th>
                <th className="px-4 py-3">Trạng thái</th>
                <th className="px-4 py-3">Số lần khớp</th>
                <th className="px-4 py-3">Báo FP</th>
                <th className="px-4 py-3">Chi phí CPU</th>
                <th className="px-4 py-3 text-right">Hành động</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredRules.map((rule) => (
                <tr key={rule.id} className="hover:bg-muted/30 transition-colors">
                  <td className="px-4 py-3 font-mono font-bold text-xs text-cyan-400">
                    {rule.id}
                  </td>
                  <td className="px-4 py-3 font-medium">
                    {rule.name}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {rule.category}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        rule.severity === 'CRITICAL'
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          : rule.severity === 'HIGH'
                          ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                          : 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${
                        rule.status === 'active'
                          ? 'text-emerald-400 bg-emerald-500/10'
                          : rule.status === 'staging'
                          ? 'text-yellow-400 bg-yellow-500/10'
                          : 'text-zinc-400 bg-zinc-500/10 line-through'
                      }`}
                    >
                      {rule.status === 'active' && <CheckCircle2 className="w-3 h-3" />}
                      {rule.status === 'staging' && <Clock className="w-3 h-3" />}
                      {rule.status === 'disabled' && <Ban className="w-3 h-3" />}
                      {rule.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {rule.matchCount.toLocaleString()}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-amber-400">
                    {rule.fpCount > 0 ? `${rule.fpCount} FP` : '0'}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">
                    {rule.avgCpuCostUs.toFixed(1)} µs
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleToggleEmergency(rule)}
                      className={`px-2.5 py-1 text-xs font-semibold rounded transition-colors inline-flex items-center gap-1 ${
                        rule.status === 'disabled'
                          ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                          : 'bg-rose-600/20 text-rose-300 hover:bg-rose-600 hover:text-white border border-rose-500/30'
                      }`}
                      title={rule.status === 'disabled' ? 'Kích hoạt lại rule' : 'Tắt khẩn cấp rule (Emergency Disable)'}
                    >
                      {rule.status === 'disabled' ? (
                        <>
                          <RefreshCw className="w-3 h-3" />
                          Bật lại
                        </>
                      ) : (
                        <>
                          <Zap className="w-3 h-3" />
                          Tắt khẩn cấp
                        </>
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Emergency Disable Confirmation Modal */}
        {emergencyTarget && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className="bg-card border border-rose-500/40 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
              <div className="flex items-center gap-3 text-rose-400">
                <AlertTriangle className="w-6 h-6" />
                <h3 className="text-lg font-bold">Xác nhận Tắt Khẩn Cấp Rule</h3>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Bạn sắp tắt Rule <strong className="text-white">#{emergencyTarget.id}</strong> ({emergencyTarget.name}). 
                Thao tác này sẽ bỏ qua quá trình kiểm tra của rule ngay lập tức trên toàn bộ các node proxy và ghi nhận vào nhật ký kiểm toán.
              </p>

              <div>
                <label className="block text-xs font-medium mb-1 text-zinc-300">
                  Lý do vô hiệu hóa khẩn cấp (bắt buộc cho Audit Log):
                </label>
                <input
                  type="text"
                  placeholder="Ví dụ: FP chặn người dùng tại trang thanh toán..."
                  value={disableReason}
                  onChange={(e) => setDisableReason(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-background border border-input rounded-md focus:outline-none focus:ring-1 focus:ring-rose-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  onClick={() => setEmergencyTarget(null)}
                  className="px-4 py-1.5 text-xs font-semibold rounded-md bg-muted hover:bg-muted/80 text-foreground"
                >
                  Hủy bỏ
                </button>
                <button
                  disabled={!disableReason.trim()}
                  onClick={confirmEmergencyDisable}
                  className="px-4 py-1.5 text-xs font-semibold rounded-md bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white shadow-md inline-flex items-center gap-1.5"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Xác nhận Vô hiệu hóa
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </PageShell>
  );
};
