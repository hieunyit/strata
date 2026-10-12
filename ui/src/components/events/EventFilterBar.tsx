import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Filter, Download, Pause, Play, RefreshCw, RotateCcw } from 'lucide-react';
import { SearchEventsRequest } from '../../api/client';
import { useAuth } from '../../context/AuthContext';

interface FilterBarProps {
  initialFilters: SearchEventsRequest;
  onApplyFilters: (filters: SearchEventsRequest) => void;
  onExportCsv: () => void;
  isAutoRefresh: boolean;
  onToggleAutoRefresh: () => void;
  isRefreshing: boolean;
  onManualRefresh: () => void;
}

export const EventFilterBar: React.FC<FilterBarProps> = ({
  initialFilters,
  onApplyFilters,
  onExportCsv,
  isAutoRefresh,
  onToggleAutoRefresh,
  isRefreshing,
  onManualRefresh,
}) => {
  const { t } = useTranslation();
  const { isViewer } = useAuth();

  const [action, setAction] = useState<string>(initialFilters.action || '');
  const [clientIp, setClientIp] = useState<string>(initialFilters.client_ip || '');
  const [ruleId, setRuleId] = useState<string>(initialFilters.rule_id ? String(initialFilters.rule_id) : '');
  const [httpMethod, setHttpMethod] = useState<string>(initialFilters.http_method || '');
  const [nodeId, setNodeId] = useState<string>(initialFilters.node_id || '');
  const [timePreset, setTimePreset] = useState<'15m' | '1h' | '24h'>('24h');

  const handleApply = (e: React.FormEvent) => {
    e.preventDefault();
    const now = new Date();
    let fromDate = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24h default

    if (timePreset === '15m') {
      fromDate = new Date(now.getTime() - 15 * 60 * 1000);
    } else if (timePreset === '1h') {
      fromDate = new Date(now.getTime() - 60 * 60 * 1000);
    }

    const filters: SearchEventsRequest = {
      from: fromDate.toISOString(),
      to: now.toISOString(),
      action: action ? (action as 'block' | 'shadow' | 'allow') : undefined,
      client_ip: clientIp.trim() || undefined,
      rule_id: ruleId ? parseInt(ruleId, 10) : undefined,
      http_method: httpMethod ? httpMethod : undefined,
      node_id: nodeId.trim() || undefined,
    };

    onApplyFilters(filters);
  };

  const handleReset = () => {
    setAction('');
    setClientIp('');
    setRuleId('');
    setHttpMethod('');
    setNodeId('');
    setTimePreset('24h');
    const now = new Date();
    onApplyFilters({
      from: new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString(),
      to: now.toISOString(),
    });
  };

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm mb-6 transition-colors">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-3 border-b border-slate-100 dark:border-slate-800">
        <div className="flex items-center gap-2 font-semibold text-slate-800 dark:text-slate-200 text-sm">
          <Filter className="w-4 h-4 text-sky-600" />
          <span>{t('events.filter.title')}</span>
        </div>

        {/* Toolbar actions */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            data-testid="auto-refresh-toggle-btn"
            onClick={onToggleAutoRefresh}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              isAutoRefresh
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800'
                : 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800'
            }`}
          >
            {isAutoRefresh ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>{t('events.toolbar.pause')}</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>{t('events.toolbar.resume')}</span>
              </>
            )}
          </button>

          <button
            type="button"
            data-testid="manual-refresh-btn"
            onClick={onManualRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>{isRefreshing ? t('events.table.loading') : t('events.toolbar.autoRefresh')}</span>
          </button>

          {/* Bulk CSV export is an operator+ action; hidden for viewer. */}
          {!isViewer && (
            <button
              type="button"
              data-testid="export-csv-btn"
              onClick={onExportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{t('events.toolbar.exportCsv')}</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter Form */}
      <form onSubmit={handleApply} className="pt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
        {/* Time Preset */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('events.filter.timeRange')}
          </label>
          <select
            value={timePreset}
            data-testid="time-preset-select"
            onChange={(e) => setTimePreset(e.target.value as '15m' | '1h' | '24h')}
            className="w-full text-xs px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-sky-500"
          >
            <option value="15m">{t('events.filter.last15m')}</option>
            <option value="1h">{t('events.filter.last1h')}</option>
            <option value="24h">{t('events.filter.last24h')}</option>
          </select>
        </div>

        {/* Action */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('events.filter.action')}
          </label>
          <select
            value={action}
            data-testid="action-filter-select"
            onChange={(e) => setAction(e.target.value)}
            className="w-full text-xs px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-sky-500"
          >
            <option value="">{t('events.filter.allActions')}</option>
            <option value="block">{t('events.actions.block')}</option>
            <option value="shadow">{t('events.actions.shadow')}</option>
            <option value="allow">{t('events.actions.allow')}</option>
          </select>
        </div>

        {/* Client IP */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('events.filter.clientIp')}
          </label>
          <input
            type="text"
            data-testid="client-ip-filter-input"
            value={clientIp}
            onChange={(e) => setClientIp(e.target.value)}
            placeholder="e.g. 198.51.100.42"
            className="w-full text-xs px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        {/* Rule ID */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('events.filter.ruleId')}
          </label>
          <input
            type="number"
            data-testid="rule-id-filter-input"
            value={ruleId}
            onChange={(e) => setRuleId(e.target.value)}
            placeholder="e.g. 942100"
            className="w-full text-xs px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        {/* Method */}
        <div>
          <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1">
            {t('events.filter.httpMethod')}
          </label>
          <select
            value={httpMethod}
            data-testid="http-method-select"
            onChange={(e) => setHttpMethod(e.target.value)}
            className="w-full text-xs px-2.5 py-1.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-sky-500"
          >
            <option value="">{t('events.filter.allMethods')}</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>

        {/* Buttons */}
        <div className="flex items-end gap-2">
          <button
            type="submit"
            data-testid="apply-filters-btn"
            className="flex-1 py-1.5 px-3 bg-sky-600 hover:bg-sky-700 text-white font-medium text-xs rounded-lg transition-colors shadow-sm"
          >
            {t('events.filter.apply')}
          </button>
          <button
            type="button"
            data-testid="reset-filters-btn"
            onClick={handleReset}
            className="py-1.5 px-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 text-xs rounded-lg border border-slate-200 dark:border-slate-700 transition-colors"
            title={t('events.filter.reset')}
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </div>
  );
};
