import React, { useState, useEffect, useCallback } from 'react';
import { Globe, Shield, RefreshCw, Layers, Radio } from 'lucide-react';
import { apiClient, GeoStatsResponse } from '../../api/client';
import { WORLD_COUNTRIES, GEO_CENTERS } from './worldData';

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
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);

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
    setSelectedCountry((prev) => {
      const next = prev === iso ? null : iso;
      if (onSelectCountry) {
        onSelectCountry(next ?? '');
      }
      return next;
    });
  };

  const countries = data?.countries ?? [];
  const asns = data?.asns ?? [];
  const grid = data?.grid ?? [];
  const maxEvents = Math.max(...countries.map((c) => c.events), 1);

  // Map country name or ISO to attack record
  const attackMap = new Map<string, typeof countries[0]>();
  for (const c of countries) {
    attackMap.set(c.country_iso, c);
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
                onClick={() => setWindowDays(w.val)}
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
              ) : selectedCountry ? (
                <span className="text-rose-400 font-semibold">FILTER: {selectedCountry}</span>
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
                  const isAttacker = attackMap.has(c.name.toLowerCase());
                  const isSel = selectedCountry && (attackMap.get(selectedCountry)?.country_iso === c.name || selectedCountry === 'VN' && isVN);

                  let fillColor = '#0f172a'; // Default slate
                  let strokeColor = '#1e293b'; // Country boundary separation line
                  let strokeW = 0.55;

                  if (isVN) {
                    fillColor = '#062d3e'; // Protected Vietnam Cyan tint
                    strokeColor = '#06b6d4';
                    strokeW = 1.0;
                  } else if (isSel) {
                    fillColor = '#38131e';
                    strokeColor = '#f43f5e';
                    strokeW = 1.2;
                  } else if (isAttacker) {
                    fillColor = '#171c2f';
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
                      className="transition-colors duration-150 hover:fill-[#1e293b] hover:stroke-cyan-400 cursor-pointer"
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
                        {/* Curved flight path */}
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

              {/* DYNAMIC ATTACK ORIGIN PULSES */}
              {countries.map((c, idx) => {
                const isSelected = selectedCountry === c.country_iso;
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

          {/* Map Footer: Legal Compliance & Legend */}
          <div className="flex flex-wrap items-center justify-between text-[11px] text-muted border-t border-line/60 pt-2.5 mt-2">
            <span className="flex items-center gap-1.5 font-sans">
              <Shield className="w-3.5 h-3.5 text-accent" />
              <span>Bản đồ tự host PMTiles tuân thủ chủ quyền lãnh thổ Việt Nam (Nghị định 18/2020/NĐ-CP)</span>
            </span>
            <div className="flex items-center gap-4 font-mono text-[11px]">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_6px_#f43f5e] inline-block" />
                <span>Blocked Attack</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_6px_#06b6d4] inline-block" />
                <span>Inspected Traffic</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981] inline-block" />
                <span>Protected Node</span>
              </span>
            </div>
          </div>
        </div>

        {/* Right Telemetry Panels: Top Threat Countries & ASNs (4 Cols) */}
        <div className="xl:col-span-4 space-y-3.5 flex flex-col justify-between">
          {/* Top Attacking Countries Panel */}
          <div className="bg-[#0b0f19] rounded-xl border border-line/90 p-4 space-y-3 shadow-sm">
            <div className="flex items-center justify-between border-b border-line/60 pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-ink flex items-center gap-2">
                <Globe className="w-3.5 h-3.5 text-accent" />
                Top Attack Origins
              </h3>
              <div className="flex items-center gap-2">
                {selectedCountry && (
                  <button
                    type="button"
                    onClick={() => handleCountryClick(selectedCountry)}
                    className="text-[10px] text-accent font-semibold hover:underline bg-accent/10 px-1.5 py-0.5 rounded border border-accent/25"
                    data-testid="clear-country-filter"
                  >
                    Clear Filter ({selectedCountry})
                  </button>
                )}
                <span className="text-[11px] font-mono text-muted">{countries.length} detected</span>
              </div>
            </div>

            {countries.length === 0 && !loading && (
              <p className="text-xs text-muted py-4 text-center font-mono">No geo data in selected window.</p>
            )}

            <div className="space-y-2 max-h-[175px] overflow-y-auto pr-1">
              {countries.map((c) => {
                const pctVal = Math.round((c.events / maxEvents) * 100);
                const blockRate = c.events > 0 ? Math.round((c.blocked / c.events) * 100) : 0;
                const active = selectedCountry === c.country_iso;

                return (
                  <div
                    key={c.country_iso}
                    onClick={() => handleCountryClick(c.country_iso)}
                    className={`p-2 rounded-lg cursor-pointer transition-all border ${
                      active
                        ? 'bg-accent/15 border-accent/50 shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                        : 'bg-surface/50 border-line/60 hover:bg-surface hover:border-line'
                    }`}
                    data-testid={`country-row-${c.country_iso}`}
                  >
                    <div className="flex items-center justify-between font-mono text-xs">
                      <span className="font-semibold text-ink flex items-center gap-2">
                        <span className="px-1.5 py-0.5 bg-sunken rounded text-[10px] font-bold border border-line text-accent">
                          {c.country_iso}
                        </span>
                        <span className="text-muted text-[11px] font-sans truncate max-w-[120px]">
                          {GEO_CENTERS[c.country_iso]?.name || c.country_iso}
                        </span>
                      </span>
                      <span className="text-ink font-semibold">
                        {c.events.toLocaleString()}{' '}
                        <span className="text-rose-400 font-bold">({blockRate}% blk)</span>
                      </span>
                    </div>
                    {/* Glowing progress bar */}
                    <div className="w-full h-1.5 bg-sunken rounded-full mt-1.5 overflow-hidden border border-line/50">
                      <div
                        className="h-full bg-gradient-to-r from-cyan-500 to-rose-500 rounded-full transition-all duration-300"
                        style={{ width: `${pctVal}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Top ASN Threat Networks Panel */}
          <div className="bg-[#0b0f19] rounded-xl border border-line/90 p-4 space-y-3 shadow-sm">
            <div className="flex items-center justify-between border-b border-line/60 pb-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-ink flex items-center gap-2">
                <Layers className="w-3.5 h-3.5 text-accent" />
                Top Threat Networks (ASN)
              </h3>
              <span className="text-[11px] font-mono text-muted">{asns.length} ASNs</span>
            </div>

            {asns.length === 0 && !loading && (
              <p className="text-xs text-muted py-3 text-center font-mono">No ASN telemetry.</p>
            )}

            <div className="space-y-1.5 max-h-[145px] overflow-y-auto pr-1">
              {asns.map((a) => (
                <div
                  key={a.asn}
                  onClick={() => onSelectASN && onSelectASN(a.asn)}
                  className="p-2 rounded-lg hover:bg-surface border border-transparent hover:border-line/70 cursor-pointer text-xs flex items-center justify-between transition-all"
                  data-testid={`asn-row-${a.asn}`}
                >
                  <div className="truncate pr-2">
                    <span className="font-mono font-bold text-accent px-1.5 py-0.5 rounded bg-accent/10 border border-accent/20">
                      AS{a.asn}
                    </span>
                    <span className="text-ink font-medium text-[11px] ml-2 truncate">
                      {a.as_org || 'Unknown Org'}
                    </span>
                  </div>
                  <span className="font-mono text-muted text-[11px] whitespace-nowrap tabular-nums">
                    {a.events.toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
