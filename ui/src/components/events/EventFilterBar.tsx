import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { RotateCcw } from 'lucide-react';
import { RangeSwitch } from '../ui';
import { RangeKey, eventRanges } from '../../lib/timeRange';
import { apiClient, Policy, FleetNode } from '../../api/client';

// The Events filters, kept as text (they round-trip through the URL);
// EventsPage turns them into a search request.
export interface EventFilters {
  range: RangeKey;
  action: string;
  client_ip: string;
  rule_id: string;
  http_method: string;
  policy_id: string;
  node_id: string;
}

export const emptyFilters: EventFilters = {
  range: '24h',
  action: '',
  client_ip: '',
  rule_id: '',
  http_method: '',
  policy_id: '',
  node_id: '',
};

interface FilterBarProps {
  initial: EventFilters;
  onApply: (f: EventFilters) => void;
}

export const EventFilterBar: React.FC<FilterBarProps> = ({ initial, onApply }) => {
  const { t } = useTranslation();
  const [f, setF] = useState<EventFilters>(initial);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [nodes, setNodes] = useState<FleetNode[]>([]);

  useEffect(() => {
    let alive = true;
    apiClient.listPolicies().then((res) => alive && setPolicies(res || [])).catch(() => {});
    apiClient.listNodes().then((res) => alive && setNodes(res || [])).catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  const set = (k: keyof EventFilters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onApply({ ...f, client_ip: f.client_ip.trim(), node_id: f.node_id.trim(), policy_id: f.policy_id.trim() });
  };

  return (
    <form onSubmit={submit} className="panel mb-4 p-4" data-testid="event-filters">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <RangeSwitch
          value={f.range}
          options={eventRanges}
          testId="time-preset-select"
          onChange={(range) => {
            const next = { ...f, range };
            setF(next);
            onApply(next); // the window applies at once
          }}
        />
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <div>
          <label className="label" htmlFor="f-action">{t('events.filter.action')}</label>
          <select id="f-action" className="field" data-testid="action-filter-select" value={f.action} onChange={set('action')}>
            <option value="">{t('events.filter.allActions')}</option>
            <option value="block">{t('verdict.block')}</option>
            <option value="shadow">{t('verdict.shadow')}</option>
            <option value="pass">{t('verdict.pass')}</option>
            <option value="error">{t('verdict.error')}</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="f-ip">{t('events.filter.clientIp')}</label>
          <input id="f-ip" className="field font-mono" data-testid="client-ip-filter-input" value={f.client_ip} onChange={set('client_ip')} placeholder="198.51.100.42" spellCheck={false} />
        </div>
        <div>
          <label className="label" htmlFor="f-rule">{t('events.filter.ruleId')}</label>
          <input
            id="f-rule"
            className="field font-mono"
            data-testid="rule-id-filter-input"
            value={f.rule_id}
            onChange={(e) => setF({ ...f, rule_id: e.target.value.replace(/[^0-9,\s]/g, '') })}
            placeholder="942100, 941100"
          />
        </div>
        <div>
          <label className="label" htmlFor="f-method">{t('events.filter.httpMethod')}</label>
          <select id="f-method" className="field" data-testid="http-method-select" value={f.http_method} onChange={set('http_method')}>
            <option value="">{t('events.filter.allMethods')}</option>
            {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="f-policy">{t('events.filter.policy')}</label>
          {policies.length > 0 ? (
            <select
              id="f-policy"
              className="field"
              data-testid="policy-filter-input"
              value={f.policy_id}
              onChange={set('policy_id')}
            >
              <option value="">{t('events.filter.allPolicies', 'All policies')}</option>
              {policies.map((p) => (
                <option key={p.id} value={p.id ?? ''}>
                  {p.name || p.id}
                </option>
              ))}
            </select>
          ) : (
            <input
              id="f-policy"
              className="field"
              data-testid="policy-filter-input"
              value={f.policy_id}
              onChange={set('policy_id')}
              placeholder="example-api"
              spellCheck={false}
            />
          )}
        </div>
        <div>
          <label className="label" htmlFor="f-node">{t('events.filter.nodeId')}</label>
          {nodes.length > 0 ? (
            <select
              id="f-node"
              className="field font-mono"
              data-testid="node-filter-input"
              value={f.node_id}
              onChange={set('node_id')}
            >
              <option value="">{t('events.filter.allNodes', 'All nodes')}</option>
              {nodes.map((n) => (
                <option key={n.id} value={n.id ?? ''}>
                  {n.hostname || n.id}
                </option>
              ))}
            </select>
          ) : (
            <input
              id="f-node"
              className="field font-mono"
              data-testid="node-filter-input"
              value={f.node_id}
              onChange={set('node_id')}
              placeholder="node-edge-01"
              spellCheck={false}
            />
          )}
        </div>
        <div className="flex items-end gap-2 col-span-2 md:col-span-1">
          <button type="submit" className="btn-primary flex-1" data-testid="apply-filters-btn">
            {t('events.filter.apply')}
          </button>
          <button
            type="button"
            className="btn px-2"
            data-testid="reset-filters-btn"
            title={t('events.filter.reset')}
            aria-label={t('events.filter.reset')}
            onClick={() => {
              setF(emptyFilters);
              onApply(emptyFilters);
            }}
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </form>
  );
};
