import React, { useState, useEffect, useCallback } from 'react';
import { Globe, RefreshCw, Radio, Zap } from 'lucide-react';
import { apiClient, GeoStatsResponse } from '../../api/client';
import { WORLD_COUNTRIES, GEO_CENTERS } from './worldData';

export interface GeoMapProps {
  onSelectCountry?: (countryIso: string) => void;
  onSelectASN?: (asn: number) => void;
  onQuickAction?: (type: 'geo' | 'asn', target: string, action?: 'block' | 'challenge') => void;
  policyId?: string;
  selectedCountry?: string | null;
  selectedASN?: number | null;
  timeRangeDays?: number;
  actionFilter?: string;
  categoryFilter?: string;
}

function getLogChoropleth(events: number): string {
  if (events <= 0) return '#0f172a';
  if (events < 100) return '#1e3a8a';
  if (events < 1000) return '#0284c7';
  if (events < 10000) return '#d97706';
  if (events < 50000) return '#ea580c';
  return '#dc2626';
}

export const GeoMap: React.FC<GeoMapProps> = ({
  onSelectCountry,
  onSelectASN,
  onQuickAction,
  policyId,
  selectedCountry: externalSelectedCountry,
  selectedASN: externalSelectedASN,
  timeRangeDays,
  actionFilter,
}) => {
  const [data, setData] = useState<GeoStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalWindowDays, setInternalWindowDays] = useState<number>(1); // 1 = 24h, 7 = 7d, 30 = 30d
  const [groupBy, setGroupBy] = useState<'all' | 'country' | 'city' | 'asn'>('all');
  const [internalSelectedCountry, setInternalSelectedCountry] = useState<string | null>(null);
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);

  const windowDays = timeRangeDays !== undefined ? timeRangeDays : internalWindowDays;
  const activeSelectedCountry = externalSelectedCountry !== undefined ? externalSelectedCountry : internalSelectedCountry;

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
        action: actionFilter && actionFilter !== 'all' ? actionFilter : undefined,
      });
      setData(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch geo statistics');
    } finally {
      setLoading(false);
    }
  }, [windowDays, groupBy, policyId, actionFilter]);

  useEffect(() => {
    void fetchData();
  }, [fetchData]);

  const handleCountryClick = (iso: string) => {
    const next = activeSelectedCountry === iso ? null : iso;
    setInternalSelectedCountry(next);
    if (onSelectCountry) {
      onSelectCountry(next ?? '');
    }
  };

  const countries = data?.countries ?? [];
  const asns = data?.asns ?? [];
  const grid = data?.grid ?? [];
  const maxEvents = Math.max(...countries.map((c) => c.events), 1);

  // Map country name or ISO to attack record
  const attackMap = new Map<string, typeof countries[0]>();
  for (const c of countries) {
    attackMap.set(c.country_iso.toUpperCase(), c);
    const center = GEO_CENTERS[c.country_iso];
    if (center) {
      attackMap.set(center.name.toLowerCase(), c);
    }
  }

  // Vietnam Target Node coordinates (Strata Edge Gateway)
  const TARGET_X = 794;
  const TARGET_Y = 205;

  return (
    <div className="panel p-5 space-y-4" data-testid="geomap-container">
      {/* Header controls: Enterprise Security Command Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line/80 pb-3.5">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent/10 border border-accent/25 flex items-center justify-center text-accent shadow-[0_0_12px_rgba(6,182,212,0.15)]">
            <Globe className="w-4.5 h-4.5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold tracking-wide text-ink">Threat Intelligence Map & GeoIP</h2>
              <span className="inline-flex items-center gap-1 text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-accent/10 text-accent border border-accent/30 font-mono">
                <Radio className="w-2.5 h-2.5 animate-pulse text-accent" />
                Air-Gapped / PMTiles
              </span>
              {grid.length > 0 && (
                <span className="text-[10px] px-2 py-0.5 rounded bg-sunken border border-line text-muted font-mono">
                  {grid.length} active clusters
                </span>
              )}
            </div>
            <p className="text-[11px] text-muted">
              Global origin detection & live attack telemetry with high-precision territorial borders
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          {/* Time range selector */}
          <div className="flex rounded-md border border-line overflow-hidden bg-sunken p-0.5 shadow-inner">
            {[
              { label: '24 Hours', val: 1 },
              { label: '7 Days', val: 7 },
              { label: '30 Days', val: 30 },
            ].map((w) => (
              <button
                key={w.val}
                type="button"
                data-testid={`time-window-${w.val}d`}
                onClick={() => setInternalWindowDays(w.val)}
                className={`px-3 py-1 rounded text-[11px] font-medium transition-all ${
                  windowDays === w.val
                    ? 'bg-accent/20 text-accent font-semibold shadow-sm border border-accent/40'
                    : 'text-muted hover:text-ink'
                }`}
              >
                {w.label}
              </button>
            ))}
          </div>

          {/* Layer switcher */}
          <select
            data-testid="groupby-select"
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value as any)}
            className="field text-xs py-1 px-2.5 bg-sunken border-line rounded-md"
          >
            <option value="all">Layers: All (Country + Cities + ASN)</option>
            <option value="country">Layer: Country Boundaries</option>
            <option value="city">Layer: City Clusters</option>
            <option value="asn">Layer: Autonomous Systems (ASN)</option>
          </select>

          <button
            type="button"
            data-testid="refresh-geomap"
            onClick={() => void fetchData()}
            disabled={loading}
            className="btn px-2.5 py-1 inline-flex items-center gap-1.5"
            title="Refresh statistics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-block/10 text-block border border-block/30 rounded-lg text-xs">
          {error}
        </div>
      )}

      {/* Main Map Visualizer & Side Telemetry Panels */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {/* Real Vector World Map (8 Cols) */}
        <div className="xl:col-span-8 bg-[#070b14] rounded-xl border border-line/90 relative overflow-hidden min-h-[420px] flex flex-col justify-between p-4 shadow-[inset_0_0_24px_rgba(0,0,0,0.5)]">
          {/* Map Status Bar Overlay */}
          <div className="flex items-center justify-between text-[11px] font-mono text-muted border-b border-line/40 pb-2 mb-2">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_#10b981] animate-pulse" />
              <span className="text-ink font-semibold">PROTECTED REGION: VIETNAM EDGE GATEWAY</span>
            </span>
            <span>
              {hoveredCountry ? (
                <span className="text-accent font-semibold">{hoveredCountry}</span>
              ) : activeSelectedCountry ? (
                <span className="text-rose-400 font-semibold">FILTER: {activeSelectedCountry}</span>
              ) : (
                <span>INTERACTIVE GEOGRAPHIC TELEMETRY</span>
              )}
            </span>
          </div>

          {/* Map canvas / SVG interactive projection */}
          <div className="relative w-full h-[320px] flex items-center justify-center">
            <svg
              viewBox="0 0 1000 500"
              className="w-full h-full object-contain select-none"
              data-testid="world-map-svg"
            >
              <defs>
                <filter id="cyber-glow-red" x="-30%" y="-30%" width="160%" height="160%">
                  <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#f43f5e" floodOpacity="0.95" />
                </filter>
                <filter id="cyber-glow-cyan" x="-30%" y="-30%" width="160%" height="160%">
                  <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#06b6d4" floodOpacity="0.95" />
                </filter>
                <filter id="cyber-glow-emerald" x="-30%" y="-30%" width="160%" height="160%">
                  <feDropShadow dx="0" dy="0" stdDeviation="5" floodColor="#10b981" floodOpacity="0.9" />
                </filter>
                <pattern id="cyber-grid" width="20" height="20" patternUnits="userSpaceOnUse">
                  <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e293b" strokeWidth="0.4" strokeOpacity="0.3" />
                </pattern>
                <linearGradient id="attack-arc-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.9" />
                  <stop offset="70%" stopColor="#f59e0b" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.2" />
                </linearGradient>
              </defs>

              {/* Background with Cyber Grid */}
              <rect width="1000" height="500" fill="#070b14" />
              <rect width="1000" height="500" fill="url(#cyber-grid)" />

              {/* Latitude and Longitude Graticules */}
              <g stroke="#1e293b" strokeWidth="0.5" strokeDasharray="2 3" opacity="0.4">
                <line x1="0" y1="125" x2="1000" y2="125" />
                <line x1="0" y1="250" x2="1000" y2="250" />
                <line x1="0" y1="375" x2="1000" y2="375" />
                <line x1="250" y1="0" x2="250" y2="500" />
                <line x1="500" y1="0" x2="500" y2="500" />
                <line x1="750" y1="0" x2="750" y2="500" />
              </g>

              {/* REAL WORLD COUNTRY POLYGONS WITH TRUE BOUNDARIES */}
              <g id="world-countries-layer">
                {WORLD_COUNTRIES.map((c, idx) => {
                  const isVN = c.name === 'Vietnam';
                  const attackRecord = attackMap.get(c.name.toLowerCase());
                  const isSel = activeSelectedCountry && (
                    attackRecord?.country_iso === activeSelectedCountry ||
                    (activeSelectedCountry === 'VN' && isVN)
                  );

                  let fillColor = '#0f172a'; // Default dark slate
                  let strokeColor = '#1e293b'; // Country boundary line
                  let strokeW = 0.55;

                  if (isVN) {
                    fillColor = '#062d3e'; // Protected Vietnam Cyan tint
                    strokeColor = '#06b6d4';
                    strokeW = 1.0;
                  } else if (isSel) {
                    fillColor = '#38131e';
                    strokeColor = '#f43f5e';
                    strokeW = 1.3;
                  } else if (attackRecord) {
                    fillColor = getLogChoropleth(attackRecord.events);
                    strokeColor = '#334155';
                  }

                  return (
                    <path
                      key={idx}
                      d={c.path}
                      fill={fillColor}
                      stroke={strokeColor}
                      strokeWidth={strokeW}
                      onMouseEnter={() => setHoveredCountry(c.name)}
                      onMouseLeave={() => setHoveredCountry(null)}
                      onClick={() => {
                        if (attackRecord) {
                          handleCountryClick(attackRecord.country_iso);
                        } else if (isVN) {
                          handleCountryClick('VN');
                        }
                      }}
                      className="transition-colors duration-150 hover:stroke-cyan-400 cursor-pointer"
                    >
                      <title>{c.name}</title>
                    </path>
                  );
                })}
              </g>

              {/* LIVE CURVED ATTACK TRAJECTORIES (Animated Bezier Arcs to Vietnam) */}
              <g id="attack-trajectories">
                {countries
                  .filter((c) => c.country_iso !== 'VN')
                  .map((c) => {
                    const center = GEO_CENTERS[c.country_iso];
                    if (!center) return null;
                    const startX = center.x;
                    const startY = center.y;
                    const midX = (startX + TARGET_X) / 2;
                    const midY = Math.min(startY, TARGET_Y) - 45;

                    return (
                      <g key={`arc-group-${c.country_iso}`}>
                        <path
                          d={`M ${startX} ${startY} Q ${midX} ${midY} ${TARGET_X} ${TARGET_Y}`}
                          fill="none"
                          stroke="url(#attack-arc-grad)"
                          strokeWidth={c.blocked > 0 ? 1.6 : 1.0}
                          strokeDasharray="4 3"
                          opacity={c.blocked > 0 ? 0.85 : 0.45}
                          className="animate-pulse"
                        />
                      </g>
                    );
                  })}
              </g>

              {/* VIETNAM SOVEREIGNTY MARKERS: Hoàng Sa & Trường Sa Islands */}
              <g data-testid="vietnam-islands" className="cursor-pointer">
                {/* Hoàng Sa (Paracel Islands): ~ 16°32'N, 111°36'E -> projected x=810, y=204 */}
                <circle cx="810" cy="204" r="9" fill="none" stroke="#06b6d4" strokeWidth="0.75" opacity="0.6" className="animate-ping" />
                <circle cx="810" cy="204" r="3.5" fill="#06b6d4" stroke="#080c14" strokeWidth="1" filter="url(#cyber-glow-cyan)" />
                <text x="817" y="202" fill="#22d3ee" fontSize="9" fontWeight="700" letterSpacing="0.2">
                  Hoàng Sa (VN)
                </text>

                {/* Trường Sa (Spratly Islands): ~ 8°38'N, 111°55'E -> projected x=811, y=226 */}
                <circle cx="811" cy="226" r="9" fill="none" stroke="#06b6d4" strokeWidth="0.75" opacity="0.6" className="animate-ping" />
                <circle cx="811" cy="226" r="3.5" fill="#06b6d4" stroke="#080c14" strokeWidth="1" filter="url(#cyber-glow-cyan)" />
                <text x="818" y="229" fill="#22d3ee" fontSize="9" fontWeight="700" letterSpacing="0.2">
                  Trường Sa (VN)
                </text>
              </g>

              {/* PROTECTED STRATA EDGE NODE BEACON (Ho Chi Minh / Hanoi) */}
              <g id="target-edge-cluster">
                <circle cx={TARGET_X} cy={TARGET_Y} r="14" fill="none" stroke="#10b981" strokeWidth="1" opacity="0.75" className="animate-ping" />
                <circle cx={TARGET_X} cy={TARGET_Y} r="5" fill="#10b981" stroke="#080c14" strokeWidth="1.5" filter="url(#cyber-glow-emerald)" />
                <text x={TARGET_X - 65} y={TARGET_Y + 18} fill="#34d399" fontSize="8.5" fontWeight="700" letterSpacing="0.3">
                  🛡️ Strata Protected Node
                </text>
              </g>

              {/* CITY GEOHASH GRID LAYER */}
              {(groupBy === 'all' || groupBy === 'city') &&
                grid.map((pt, i) => {
                  const cx = ((pt.lon + 180) * 1000) / 360;
                  const cy = ((90 - pt.lat) * 500) / 180;
                  const r = Math.max(4, Math.min(14, Math.sqrt(pt.events) / 10));
                  const threatColor =
                    pt.top_attack_type === 'sqli'
                      ? '#ef4444'
                      : pt.top_attack_type === 'xss'
                      ? '#a855f7'
                      : pt.top_attack_type === 'bot'
                      ? '#f59e0b'
                      : '#06b6d4';

                  return (
                    <g
                      key={`grid-${pt.geohash || i}`}
                      className="cursor-pointer"
                      data-testid={`grid-point-${pt.geohash || i}`}
                    >
                      <circle
                        cx={cx}
                        cy={cy}
                        r={r}
                        fill={threatColor}
                        fillOpacity={0.85}
                        stroke="#ffffff"
                        strokeWidth={0.8}
                      />
                      <title>{`${pt.city || pt.geohash} (${pt.country_iso}): ${pt.events.toLocaleString()} events (${pt.blocked.toLocaleString()} blocked) - Top Attack: ${pt.top_attack_type}`}</title>
                    </g>
                  );
                })}

              {/* DYNAMIC ATTACK ORIGIN PULSES */}
              {(groupBy === 'all' || groupBy === 'country') &&
                countries.map((c, idx) => {
                  const isSelected = activeSelectedCountry === c.country_iso;
                  const center = GEO_CENTERS[c.country_iso];
                  let cx = center ? center.x : 300 + ((idx * 37) % 400);
                  let cy = center ? center.y : 100 + ((idx * 29) % 200);

                  if (c.country_iso === 'VN') {
                    cx = 794;
                    cy = 205;
                  }

                  const radius = Math.min(Math.max((c.events / maxEvents) * 16, 5), 18);

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
                        fill={c.blocked > 0 ? '#f43f5e' : '#06b6d4'}
                        fillOpacity={isSelected ? 0.95 : 0.75}
                        stroke={isSelected ? '#ffffff' : '#080c14'}
                        strokeWidth={isSelected ? 2 : 1}
                        filter={c.blocked > 0 ? 'url(#cyber-glow-red)' : 'url(#cyber-glow-cyan)'}
                      />
                      <title>
                        {`${c.country_iso}: ${c.events.toLocaleString()} events (${c.blocked.toLocaleString()} blocked) - Top Attack: ${c.top_attack_type}`}
                      </title>
                    </g>
                  );
                })}
            </svg>
          </div>

          {/* Choropleth scale & Legal compliance banner */}
          <div className="flex flex-wrap items-center justify-between text-[10px] text-muted font-mono pt-2 border-t border-line/40 gap-2">
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-medium">Choropleth Threat Level:</span>
              <div className="flex items-center gap-1">
                <span className="w-3 h-2 rounded-sm bg-[#0f172a] border border-slate-700" title="0 attacks" />
                <span className="w-3 h-2 rounded-sm bg-[#1e3a8a]" title="1-100" />
                <span className="w-3 h-2 rounded-sm bg-[#0284c7]" title="100-1K" />
                <span className="w-3 h-2 rounded-sm bg-[#d97706]" title="1K-10K" />
                <span className="w-3 h-2 rounded-sm bg-[#dc2626]" title=">10K" />
                <span className="text-[9px] text-slate-500 ml-1">Logarithmic (Zero → Critical)</span>
              </div>
            </div>

            <div className="flex items-center gap-1.5 text-accent/90">
              <span>Bản đồ tự host PMTiles tuân thủ chủ quyền lãnh thổ Việt Nam (Nghị định 18/2020/NĐ-CP)</span>
            </div>
          </div>
        </div>

        {/* Right Telemetry Column: Origin Ranking & ASN Breakdown (4 Cols) */}
        <div className="xl:col-span-4 flex flex-col gap-4">
          {/* Top Attack Origins */}
          <div className="bg-[#070b14] rounded-xl border border-line/90 p-3.5 flex flex-col justify-between shadow-lg">
            <div className="flex items-center justify-between border-b border-line/50 pb-2 mb-2.5">
              <span className="text-xs font-bold uppercase tracking-wider text-ink font-mono flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                Top Attack Origins
              </span>
              {activeSelectedCountry && (
                <button
                  type="button"
                  data-testid="clear-country-filter"
                  onClick={() => handleCountryClick(activeSelectedCountry)}
                  className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 hover:bg-rose-500/30 font-mono transition-colors"
                >
                  Clear ({activeSelectedCountry})
                </button>
              )}
            </div>

            <div className="space-y-2 max-h-[175px] overflow-y-auto pr-1">
              {countries.length === 0 ? (
                <div className="text-center py-6 text-xs text-muted font-mono">No attack origins detected</div>
              ) : (
                countries.slice(0, 5).map((c) => {
                  const isSelected = activeSelectedCountry === c.country_iso;
                  const blkRate = c.events > 0 ? ((c.blocked / c.events) * 100).toFixed(1) : '0';
                  const center = GEO_CENTERS[c.country_iso];
                  const fullName = center ? center.name : c.country_iso;

                  return (
                    <div
                      key={c.country_iso}
                      data-testid={`country-row-${c.country_iso}`}
                      onClick={() => handleCountryClick(c.country_iso)}
                      className={`p-2 rounded-lg border text-xs cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-rose-500/15 border-rose-500/50 shadow-[0_0_8px_rgba(244,63,94,0.2)]'
                          : 'bg-sunken/60 border-line/60 hover:border-slate-600 hover:bg-sunken'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono font-bold text-accent px-1.5 py-0.2 rounded bg-accent/10 border border-accent/20 text-[10px]">
                            {c.country_iso}
                          </span>
                          <span className="text-ink font-medium truncate max-w-[110px]" title={fullName}>
                            {fullName}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-muted text-[11px]">
                            {c.events.toLocaleString()} reqs
                          </span>
                          {onQuickAction && (
                            <button
                              type="button"
                              data-testid={`quick-rule-country-${c.country_iso}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                onQuickAction('geo', c.country_iso, 'block');
                              }}
                              title={`Tạo rule chặn quốc gia ${c.country_iso}`}
                              className="p-1 rounded bg-rose-500/15 text-rose-400 hover:bg-rose-500/30 transition-colors"
                            >
                              <Zap className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-muted font-mono">
                        <span>Top: <span className="text-rose-400 font-semibold">{c.top_attack_type}</span></span>
                        <span className="text-rose-400 font-semibold">{blkRate}% blk</span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1 mt-1.5 overflow-hidden">
                        <div
                          className="bg-rose-500 h-1 rounded-full transition-all duration-300"
                          style={{ width: `${Math.min(100, Math.max(8, (c.events / maxEvents) * 100))}%` }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Threat Autonomous Systems (ASNs) */}
          <div className="bg-[#070b14] rounded-xl border border-line/90 p-3.5 flex flex-col justify-between shadow-lg">
            <div className="flex items-center justify-between border-b border-line/50 pb-2 mb-2.5">
              <span className="text-xs font-bold uppercase tracking-wider text-ink font-mono flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500" />
                Threat Networks (ASNs)
              </span>
              <span className="text-[10px] text-muted font-mono">{asns.length} tracked</span>
            </div>

            <div className="space-y-2 max-h-[175px] overflow-y-auto pr-1">
              {asns.length === 0 ? (
                <div className="text-center py-6 text-xs text-muted font-mono">No threat ASN activity</div>
              ) : (
                asns.slice(0, 5).map((a) => {
                  const isSelected = externalSelectedASN === a.asn;
                  const blkRate = a.events > 0 ? ((a.blocked / a.events) * 100).toFixed(1) : '0';

                  return (
                    <div
                      key={a.asn}
                      data-testid={`asn-row-${a.asn}`}
                      onClick={() => onSelectASN?.(a.asn)}
                      className={`p-2 rounded-lg border text-xs cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-amber-500/15 border-amber-500/50 shadow-[0_0_8px_rgba(245,158,11,0.2)]'
                          : 'bg-sunken/60 border-line/60 hover:border-slate-600 hover:bg-sunken'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono font-bold text-amber-400 bg-amber-500/10 px-1.5 py-0.2 rounded border border-amber-500/20 text-[10px]">
                          AS{a.asn}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-muted text-[11px]">
                            {a.events.toLocaleString()} reqs
                          </span>
                          {onQuickAction && (
                            <button
                              type="button"
                              data-testid={`quick-rule-asn-${a.asn}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                onQuickAction('asn', String(a.asn), 'block');
                              }}
                              title={`Tạo rule chặn ASN ${a.asn}`}
                              className="p-1 rounded bg-amber-500/15 text-amber-400 hover:bg-amber-500/30 transition-colors"
                            >
                              <Zap className="w-3 h-3" />
                            </button>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-mono">
                        <span className="text-slate-300 truncate max-w-[130px]" title={a.as_org}>
                          {a.as_org || 'Unknown Provider'}
                        </span>
                        <span className="text-rose-400 font-semibold">{blkRate}% blk</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
