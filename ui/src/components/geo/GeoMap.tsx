import React, { useState, useEffect, useCallback } from 'react';
import { Globe, Shield, RefreshCw, Layers } from 'lucide-react';
import { apiClient, GeoStatsResponse } from '../../api/client';

export interface GeoMapProps {
  onSelectCountry?: (countryIso: string) => void;
  onSelectASN?: (asn: number) => void;
  policyId?: string;
}

export const GeoMap: React.FC<GeoMapProps> = ({ onSelectCountry, onSelectASN, policyId }) => {
  const [data, setData] = useState<GeoStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [windowDays, setWindowDays] = useState<number>(1); // 1 = 24h, 7 = 7d, 30 = 30d
  const [groupBy, setGroupBy] = useState<'all' | 'country' | 'city' | 'asn'>('all');
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const to = new Date().toISOString();
      const from = new Date(Date.now() - windowDays * 24 * 3600 * 1000).toISOString();
      const res = await apiClient.getGeoStats({
        from,
        to,
        groupBy,
        policy_id: policyId,
      });
      setData(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch geo statistics');
    } finally {
      setLoading(false);
    }
  }, [windowDays, groupBy, policyId]);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  const handleCountryClick = (iso: string) => {
    setSelectedCountry(iso);
    if (onSelectCountry) {
      onSelectCountry(iso);
    }
  };

  const countries = data?.countries ?? [];
  const asns = data?.asns ?? [];
  const grid = data?.grid ?? [];
  const maxEvents = Math.max(...countries.map((c) => c.events), 1);

  return (
    <div className="panel p-4 space-y-4" data-testid="geomap-container">
      {/* Header controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-accent" />
          <h2 className="text-sm font-semibold tracking-wide">Threat Intelligence Map & GeoIP</h2>
          <span className="text-xs px-2 py-0.5 rounded bg-accent/10 text-accent font-mono">Air-Gapped / PMTiles</span>
          {grid.length > 0 && (
            <span className="text-xs px-2 py-0.5 rounded bg-sunken border border-line text-muted font-mono">
              {grid.length} clusters
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Time range */}
          <div className="flex rounded border border-line overflow-hidden bg-sunken">
            {[
              { label: '24 Hours', val: 1 },
              { label: '7 Days', val: 7 },
              { label: '30 Days', val: 30 },
            ].map((w) => (
              <button
                key={w.val}
                type="button"
                data-testid={`time-window-${w.val}d`}
                onClick={() => setWindowDays(w.val)}
                className={`px-2.5 py-1 transition-colors ${
                  windowDays === w.val ? 'bg-ink text-paper font-medium' : 'text-muted hover:text-ink'
                }`}
              >
                {w.label}
              </button>
            ))}
          </div>

          {/* GroupBy */}
          <select
            data-testid="groupby-select"
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as any)}
            className="field text-xs py-1"
          >
            <option value="all">Layers: All (Country + Cities + ASN)</option>
            <option value="country">Layer: Country Choropleth</option>
            <option value="city">Layer: City Clusters (Geohash)</option>
            <option value="asn">Layer: Autonomous Systems (ASN)</option>
          </select>

          <button
            type="button"
            data-testid="refresh-geomap"
            onClick={() => void fetchData()}
            disabled={loading}
            className="btn inline-flex items-center gap-1.5"
            title="Refresh statistics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-block/10 text-block border border-block/30 rounded text-xs">
          {error}
        </div>
      )}

      {/* Main Map Visualizer & Side Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Interactive Map Visualizer */}
        <div className="lg:col-span-3 bg-[#0B0F19] rounded-lg border border-line relative overflow-hidden min-h-[360px] flex flex-col justify-between p-4">
          {/* Map canvas / SVG interactive projection */}
          <div className="relative w-full h-[280px] flex items-center justify-center">
            <svg
              viewBox="0 0 800 400"
              className="w-full h-full object-contain"
              data-testid="world-map-svg"
            >
              {/* Minimalist World Outline Polygons for offline rendering */}
              <rect width="800" height="400" fill="#0B0F19" />
              <g fill="#1E293B" stroke="#334155" strokeWidth="0.75">
                {/* North America */}
                <path d="M120 70 L250 50 L270 120 L220 180 L180 160 L140 180 L100 120 Z" />
                {/* South America */}
                <path d="M220 200 L280 210 L300 280 L250 360 L230 310 L210 230 Z" />
                {/* Europe */}
                <path d="M410 70 L480 60 L500 110 L440 130 L400 100 Z" />
                {/* Africa */}
                <path d="M410 150 L490 150 L520 230 L460 320 L420 280 L390 200 Z" />
                {/* Asia / Eurasia */}
                <path d="M510 50 L710 60 L730 150 L640 180 L550 160 L490 120 Z" />
                {/* Southeast Asia & Vietnam */}
                <path d="M620 180 L650 190 L645 230 L630 220 Z" />
                {/* Australia */}
                <path d="M650 260 L740 250 L750 320 L670 340 Z" />
              </g>

              {/* Vietnam Sovereignty Markers: Hoàng Sa & Trường Sa Islands */}
              <g data-testid="vietnam-islands" className="cursor-pointer">
                {/* Hoàng Sa (Paracel Islands): ~ 16°32'N, 111°36'E -> Projected roughly at x=642, y=198 */}
                <circle cx="642" cy="198" r="3.5" fill="#38BDF8" stroke="#0B0F19" strokeWidth="1" />
                <text x="648" y="196" fill="#38BDF8" fontSize="8" fontWeight="600">Hoàng Sa (VN)</text>

                {/* Trường Sa (Spratly Islands): ~ 8°38'N, 111°55'E -> Projected roughly at x=644, y=225 */}
                <circle cx="644" cy="225" r="3.5" fill="#38BDF8" stroke="#0B0F19" strokeWidth="1" />
                <text x="650" y="228" fill="#38BDF8" fontSize="8" fontWeight="600">Trường Sa (VN)</text>
              </g>

              {/* Dynamic Threat Density Points based on Country data */}
              {countries.slice(0, 15).map((c, idx) => {
                const isSelected = selectedCountry === c.country_iso;
                // Simple coordinate lookup for key attack origins
                let cx = 640;
                let cy = 180;
                if (c.country_iso === 'VN') { cx = 638; cy = 205; }
                else if (c.country_iso === 'US') { cx = 190; cy = 120; }
                else if (c.country_iso === 'SG') { cx = 632; cy = 230; }
                else if (c.country_iso === 'DE') { cx = 445; cy = 95; }
                else if (c.country_iso === 'JP') { cx = 710; cy = 125; }
                else { cx = 300 + (idx * 27) % 400; cy = 100 + (idx * 19) % 200; }

                const radius = Math.min(Math.max((c.events / maxEvents) * 16, 4), 18);

                return (
                  <g
                    key={c.country_iso}
                    onClick={() => handleCountryClick(c.country_iso)}
                    className="cursor-pointer transition-transform hover:scale-125"
                    data-testid={`map-country-point-${c.country_iso}`}
                  >
                    <circle
                      cx={cx}
                      cy={cy}
                      r={radius}
                      fill={c.blocked > 0 ? '#EF4444' : '#38BDF8'}
                      fillOpacity={isSelected ? 0.9 : 0.6}
                      stroke={isSelected ? '#FFFFFF' : '#0B0F19'}
                      strokeWidth={isSelected ? 2 : 1}
                    />
                    <title>
                      {`${c.country_iso}: ${c.events} events (${c.blocked} blocked) - Top: ${c.top_attack_type}`}
                    </title>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Map Footer & Legal Sovereignty Compliance Note */}
          <div className="flex flex-wrap items-center justify-between text-[11px] text-muted border-t border-line/40 pt-2 mt-2">
            <span className="flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-accent" />
              <span>Bản đồ tự host PMTiles tuân thủ chủ quyền lãnh thổ Việt Nam (Nghị định 18/2020/NĐ-CP)</span>
            </span>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-block inline-block" /> Blocked Attack
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2.5 h-2.5 rounded-full bg-accent inline-block" /> Inspected Traffic
              </span>
            </div>
          </div>
        </div>

        {/* Right Sidebar: Top Attacking Countries & ASNs */}
        <div className="space-y-4">
          {/* Top Countries Panel */}
          <div className="bg-sunken/40 rounded-lg border border-line p-3 space-y-2">
            <div className="flex items-center justify-between border-b border-line/60 pb-1.5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-accent" />
                Top Countries
              </h3>
              <span className="text-[11px] text-muted">{countries.length} detected</span>
            </div>

            {countries.length === 0 && !loading && (
              <p className="text-xs text-muted py-3 text-center">No geo data in selected window.</p>
            )}

            <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
              {countries.map((c) => {
                const pct = Math.round((c.events / maxEvents) * 100);
                const blockRate = c.events > 0 ? Math.round((c.blocked / c.events) * 100) : 0;
                const active = selectedCountry === c.country_iso;

                return (
                  <div
                    key={c.country_iso}
                    onClick={() => handleCountryClick(c.country_iso)}
                    className={`p-1.5 rounded cursor-pointer transition-colors text-xs ${
                      active ? 'bg-accent/20 border border-accent/40' : 'hover:bg-line/40'
                    }`}
                    data-testid={`country-row-${c.country_iso}`}
                  >
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-semibold text-ink flex items-center gap-1.5">
                        <span className="px-1 py-0.2 bg-line rounded text-[10px]">{c.country_iso}</span>
                      </span>
                      <span className="text-muted">
                        {c.events.toLocaleString()} <span className="text-block">({blockRate}% blk)</span>
                      </span>
                    </div>
                    {/* Mini progress bar */}
                    <div className="w-full h-1 bg-line rounded-full mt-1 overflow-hidden">
                      <div className="h-full bg-accent rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top ASN Panel */}
          <div className="bg-sunken/40 rounded-lg border border-line p-3 space-y-2">
            <div className="flex items-center justify-between border-b border-line/60 pb-1.5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-accent" />
                Top Networks (ASN)
              </h3>
              <span className="text-[11px] text-muted">{asns.length} ASNs</span>
            </div>

            {asns.length === 0 && !loading && (
              <p className="text-xs text-muted py-3 text-center">No ASN telemetry.</p>
            )}

            <div className="space-y-1.5 max-h-[140px] overflow-y-auto pr-1">
              {asns.map((a) => (
                <div
                  key={a.asn}
                  onClick={() => onSelectASN && onSelectASN(a.asn)}
                  className="p-1.5 rounded hover:bg-line/40 cursor-pointer text-xs flex items-center justify-between"
                  data-testid={`asn-row-${a.asn}`}
                >
                  <div className="truncate pr-2">
                    <span className="font-mono font-semibold text-ink">AS{a.asn}</span>
                    <span className="text-muted text-[11px] ml-1.5 truncate">{a.as_org || 'Unknown Org'}</span>
                  </div>
                  <span className="font-mono text-muted whitespace-nowrap">{a.events.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
