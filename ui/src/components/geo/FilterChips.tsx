import React from 'react';
import { Clock, ShieldAlert, Cpu, Globe2, Network, RotateCcw } from 'lucide-react';

export interface FilterState {
  timeRange: '1h' | '24h' | '7d' | '30d';
  action: 'all' | 'block' | 'monitor';
  category: string;
  selectedCountry: string | null;
  selectedASN: number | null;
  selectedASOrg?: string;
}

interface FilterChipsProps {
  filters: FilterState;
  onChange: (updated: FilterState) => void;
  liveStreaming: boolean;
  onToggleLive: () => void;
}

export const FilterChips: React.FC<FilterChipsProps> = ({
  filters,
  onChange,
  liveStreaming,
  onToggleLive,
}) => {
  const hasActiveFilters =
    filters.timeRange !== '24h' ||
    filters.action !== 'all' ||
    filters.category !== 'all' ||
    filters.selectedCountry !== null ||
    filters.selectedASN !== null;

  const handleReset = () => {
    onChange({
      timeRange: '24h',
      action: 'all',
      category: 'all',
      selectedCountry: null,
      selectedASN: null,
    });
  };

  return (
    <div className="bg-[#0f172a]/95 border border-slate-800/80 rounded-xl p-3 shadow-xl backdrop-blur-md flex flex-wrap items-center justify-between gap-3 text-xs">
      {/* Left group: Selectors */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Time range pills */}
        <div className="flex items-center bg-slate-900/90 border border-slate-800 rounded-lg p-0.5" role="group" aria-label="Time Window">
          <Clock className="w-3.5 h-3.5 text-slate-400 ml-2 mr-1" />
          {(['1h', '24h', '7d', '30d'] as const).map((t) => (
            <button
              key={t}
              onClick={() => onChange({ ...filters, timeRange: t })}
              className={`px-2.5 py-1 rounded-md font-mono font-medium transition-all ${
                filters.timeRange === t
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Action filter pills */}
        <div className="flex items-center bg-slate-900/90 border border-slate-800 rounded-lg p-0.5" role="group" aria-label="Action Filter">
          <ShieldAlert className="w-3.5 h-3.5 text-slate-400 ml-2 mr-1" />
          {[
            { id: 'all', label: 'All Actions' },
            { id: 'block', label: 'Blocked' },
            { id: 'monitor', label: 'Monitored' },
          ].map((act) => (
            <button
              key={act.id}
              onClick={() => onChange({ ...filters, action: act.id as 'all' | 'block' | 'monitor' })}
              className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                filters.action === act.id
                  ? act.id === 'block'
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                    : act.id === 'monitor'
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                    : 'bg-slate-700/60 text-slate-200'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {act.label}
            </button>
          ))}
        </div>

        {/* Category selector */}
        <div className="flex items-center bg-slate-900/90 border border-slate-800 rounded-lg p-0.5">
          <Cpu className="w-3.5 h-3.5 text-slate-400 ml-2 mr-1" />
          {[
            { id: 'all', label: 'All Threats' },
            { id: 'sqli', label: 'SQLi' },
            { id: 'xss', label: 'XSS' },
            { id: 'bot', label: 'Bot' },
            { id: 'protocol', label: 'Protocol' },
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => onChange({ ...filters, category: cat.id })}
              className={`px-2.5 py-1 rounded-md font-medium transition-all ${
                filters.category === cat.id
                  ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Active entity filters (Country, ASN) */}
        {filters.selectedCountry && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-950/60 border border-cyan-500/50 text-cyan-300 font-mono">
            <Globe2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Country: {filters.selectedCountry}</span>
            <button
              onClick={() => onChange({ ...filters, selectedCountry: null })}
              className="ml-1 text-cyan-400 hover:text-white font-bold"
              title="Remove country filter"
            >
              ✕
            </button>
          </div>
        )}

        {filters.selectedASN && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-950/60 border border-amber-500/50 text-amber-300 font-mono">
            <Network className="w-3.5 h-3.5 text-amber-400" />
            <span>AS{filters.selectedASN} {filters.selectedASOrg ? `(${filters.selectedASOrg})` : ''}</span>
            <button
              onClick={() => onChange({ ...filters, selectedASN: null, selectedASOrg: undefined })}
              className="ml-1 text-amber-400 hover:text-white font-bold"
              title="Remove ASN filter"
            >
              ✕
            </button>
          </div>
        )}

        {hasActiveFilters && (
          <button
            onClick={handleReset}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 transition-colors"
            title="Reset all filters to defaults"
          >
            <RotateCcw className="w-3 h-3 text-slate-400" />
            Reset
          </button>
        )}
      </div>

      {/* Right group: Live streaming toggle */}
      <div className="flex items-center gap-2">
        <button
          onClick={onToggleLive}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg font-mono font-semibold transition-all ${
            liveStreaming
              ? 'bg-emerald-500/10 border border-emerald-500/40 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
              : 'bg-slate-800/60 border border-slate-700 text-slate-400 hover:text-slate-200'
          }`}
        >
          <span className={`w-2 h-2 rounded-full ${liveStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
          {liveStreaming ? 'LIVE (SSE 3s)' : 'PAUSED (Inspect)'}
        </button>
      </div>
    </div>
  );
};
