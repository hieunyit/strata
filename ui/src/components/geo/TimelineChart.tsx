import React, { useEffect, useRef } from 'react';
import * as echarts from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';
import { TimelineBucket } from '../../api/client';
import { TrendingUp, ShieldAlert, ShieldCheck } from 'lucide-react';

echarts.use([BarChart, GridComponent, TooltipComponent, LegendComponent, SVGRenderer]);

interface TimelineChartProps {
  buckets: TimelineBucket[];
  step?: string;
  activeFilter?: string;
}

export const TimelineChart: React.FC<TimelineChartProps> = ({
  buckets,
  step = '1h',
  activeFilter,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartInstance = useRef<echarts.ECharts | null>(null);

  const total = buckets.reduce((acc, b) => acc + b.total, 0);
  const blocked = buckets.reduce((acc, b) => acc + b.blocked, 0);
  const monitored = buckets.reduce((acc, b) => acc + b.monitored, 0);
  const passed = buckets.reduce((acc, b) => acc + b.passed, 0);
  const blockRate = total > 0 ? ((blocked / total) * 100).toFixed(1) : '0.0';

  useEffect(() => {
    if (!containerRef.current) return;
    try {
      chartInstance.current = echarts.init(containerRef.current, undefined, { renderer: 'svg' });
    } catch {
      chartInstance.current = null;
    }

    const ro = typeof ResizeObserver !== 'undefined'
      ? new ResizeObserver(() => chartInstance.current?.resize())
      : null;
    ro?.observe(containerRef.current);

    return () => {
      ro?.disconnect();
      chartInstance.current?.dispose();
      chartInstance.current = null;
    };
  }, []);

  useEffect(() => {
    const c = chartInstance.current;
    if (!c || buckets.length === 0) return;

    const timestamps = buckets.map((b) => {
      const d = new Date(b.timestamp);
      if (step === '24h' || step === '6h') {
        return d.toLocaleDateString(undefined, {
          month: 'numeric',
          day: 'numeric',
          ...(step === '6h' ? { hour: '2-digit' } : {}),
        });
      }
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    });

    const blockedData = buckets.map((b) => b.blocked);
    const monitoredData = buckets.map((b) => b.monitored);
    const passedData = buckets.map((b) => b.passed);

    c.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis',
        axisPointer: { type: 'shadow' },
        backgroundColor: '#0f172a',
        borderColor: '#334155',
        textStyle: { color: '#f8fafc', fontSize: 11 },
      },
      legend: {
        data: ['Blocked', 'Monitored', 'Passed'],
        textStyle: { color: '#94a3b8', fontSize: 11 },
        top: 0,
        right: 10,
      },
      grid: {
        top: 35,
        left: 45,
        right: 15,
        bottom: 25,
      },
      xAxis: {
        type: 'category',
        data: timestamps,
        axisLine: { lineStyle: { color: '#334155' } },
        axisLabel: { color: '#64748b', fontSize: 10 },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: '#1e293b', type: 'dashed' } },
        axisLabel: { color: '#64748b', fontSize: 10 },
      },
      series: [
        {
          name: 'Blocked',
          type: 'bar',
          stack: 'traffic',
          itemStyle: { color: '#f43f5e' },
          data: blockedData,
        },
        {
          name: 'Monitored',
          type: 'bar',
          stack: 'traffic',
          itemStyle: { color: '#f59e0b' },
          data: monitoredData,
        },
        {
          name: 'Passed',
          type: 'bar',
          stack: 'traffic',
          itemStyle: { color: '#0ea5e9' },
          data: passedData,
        },
      ],
    });
  }, [buckets]);

  return (
    <div className="bg-[#0b1120] border border-slate-800/80 rounded-xl p-4 shadow-xl flex flex-col justify-between space-y-3" data-testid="timeline-container">
      {/* Title & Aggregated KPI Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/60 pb-3">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-200 tracking-wide">
            Traffic & Threat Mitigation Timeline
          </h3>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-400">
            Granularity: {step}
          </span>
          {activeFilter && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300">
              {activeFilter}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3.5 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Total:</span>
            <span className="text-slate-100 font-bold">{total.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-slate-400">Blocked:</span>
            <span className="text-rose-400 font-bold">{blocked.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Monitored:</span>
            <span className="text-amber-400 font-bold">{monitored.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Passed:</span>
            <span className="text-cyan-400 font-bold">{passed.toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-slate-400">Block Rate:</span>
            <span className="text-emerald-400 font-bold">{blockRate}%</span>
          </div>
        </div>
      </div>

      {/* Chart Canvas */}
      <div ref={containerRef} className="w-full h-[180px]" data-testid="timeline-chart" />

      {/* Fallback data listing for headless/test environments */}
      {buckets.length === 0 && (
        <div className="text-center py-8 text-xs text-slate-500 font-mono">
          No traffic samples recorded in this window
        </div>
      )}
    </div>
  );
};
