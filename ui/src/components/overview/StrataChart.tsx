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
// have been blocked) above it, the rest on top, one column per bucket.
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
    const layer = (key: 'block' | 'shadow' | 'other', name: string) => ({
      name,
      type: 'bar' as const,
      stack: 'events',
      barCategoryGap: '18%',
      itemStyle: { color: css(key) },
      emphasis: { focus: 'series' as const },
      data: series.map((b) => b[key]),
    });
    c.setOption(
      {
        animationDuration: 400,
        grid: { left: 8, right: 8, top: 12, bottom: 4, containLabel: true },
        tooltip: {
          trigger: 'axis',
          axisPointer: { type: 'shadow' },
          backgroundColor: css('surface'),
          borderColor: css('line'),
          textStyle: { color: css('ink'), fontFamily: 'IBM Plex Sans', fontSize: 12 },
        },
        xAxis: {
          type: 'category',
          data: series.map((b) => label(b.start, stepSeconds, locale)),
          axisLine: { lineStyle: { color: css('line') } },
          axisTick: { show: false },
          axisLabel: { color: css('muted'), fontFamily: 'IBM Plex Sans', fontSize: 11, hideOverlap: true },
        },
        yAxis: {
          type: 'value',
          minInterval: 1,
          splitLine: { lineStyle: { color: css('line'), type: 'dashed' } },
          axisLabel: { color: css('muted'), fontFamily: 'IBM Plex Sans', fontSize: 11 },
        },
        series: [
          layer('block', t('verdict.block')),
          layer('shadow', t('verdict.shadow')),
          layer('other', t('verdict.other')),
        ],
      },
      true,
    );
  }, [series, stepSeconds, theme, i18n.language, t]);

  return <div ref={el} data-testid="strata-chart" role="img" aria-label={t('overview.chartLabel')} style={{ height }} className="w-full" />;
};
