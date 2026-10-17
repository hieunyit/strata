import React, { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import * as echarts from 'echarts/core';
import { BarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent } from 'echarts/components';
import { SVGRenderer } from 'echarts/renderers';
import { OverviewBucket } from '../../api/client';
import { useTheme } from '../../lib/theme';

echarts.use([BarChart, GridComponent, TooltipComponent, SVGRenderer]);

const css = (name: string) => `rgb(${getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim().replace(/ /g, ',')})`;

function label(start: string, stepSeconds: number, locale: string): string {
  const d = new Date(start);
  if (stepSeconds >= 86400) return d.toLocaleDateString(locale, { month: 'short', day: 'numeric' });
  if (stepSeconds >= 6 * 3600) return d.toLocaleString(locale, { month: 'short', day: 'numeric', hour: '2-digit' });
  return d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' });
}

// The events of the window as layers: blocked at the bottom, shadow (would
// have been blocked) above it, then fail mode (not inspected), then passed,
// one column per bucket.
export const StrataChart: React.FC<{ series: OverviewBucket[]; stepSeconds: number; height?: number }> = ({
  series,
  stepSeconds,
  height = 260,
}) => {
  const { t, i18n } = useTranslation();
  const [theme] = useTheme();
  const el = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    if (!el.current) return;
    try {
      chart.current = echarts.init(el.current, undefined, { renderer: 'svg' });
    } catch {
      chart.current = null; // no layout (tests): the table below still lists the numbers
    }
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(() => chart.current?.resize()) : null;
    ro?.observe(el.current);
    return () => {
      ro?.disconnect();
      chart.current?.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    const c = chart.current;
    if (!c) return;
    const locale = i18n.language;
    const layer = (color: string, name: string, data: number[], isTop = false) => ({
      name,
      type: 'bar' as const,
      stack: 'events',
      barCategoryGap: '22%',
      itemStyle: {
        color: css(color),
        borderRadius: isTop ? [4, 4, 0, 0] : [0, 0, 0, 0],
      },
      emphasis: { focus: 'series' as const },
      data,
    });
    c.setOption(
      {
        animationDuration: 400,
        grid: { left: 10, right: 10, top: 16, bottom: 6, containLabel: true },
        tooltip: {
          trigger: 'axis',
          axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(6, 182, 212, 0.06)' } },
          backgroundColor: 'rgb(var(--surface))',
          borderColor: 'rgb(var(--line))',
          borderWidth: 1,
          padding: [10, 14],
          extraCssText: 'box-shadow: 0 12px 30px rgba(0,0,0,0.5); border-radius: 8px; backdrop-filter: blur(8px);',
          textStyle: { color: 'rgb(var(--ink))', fontFamily: 'IBM Plex Sans', fontSize: 12 },
        },
        xAxis: {
          type: 'category',
          data: series.map((b) => label(b.start, stepSeconds, locale)),
          axisLine: { lineStyle: { color: 'rgb(var(--line))' } },
          axisTick: { show: false },
          axisLabel: { color: 'rgb(var(--muted))', fontFamily: 'IBM Plex Sans', fontSize: 11, hideOverlap: true },
        },
        yAxis: {
          type: 'value',
          minInterval: 1,
          splitLine: { lineStyle: { color: 'rgb(var(--line))', type: 'dashed' } },
          axisLabel: { color: 'rgb(var(--muted))', fontFamily: 'IBM Plex Sans', fontSize: 11 },
        },
        series: [
          layer('block', t('verdict.block'), series.map((b) => b.block)),
          layer('shadow', t('verdict.shadow'), series.map((b) => b.shadow)),
          layer('unchecked', t('verdict.unchecked'), series.map((b) => b.error ?? 0)),
          layer('other', t('verdict.pass'), series.map((b) => Math.max(0, b.other - (b.error ?? 0))), true),
        ],
      },
      true,
    );
  }, [series, stepSeconds, theme, i18n.language, t]);

  return <div ref={el} data-testid="strata-chart" role="img" aria-label={t('overview.chartLabel')} style={{ height }} className="w-full" />;
};
