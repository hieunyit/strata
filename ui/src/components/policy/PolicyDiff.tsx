import React, { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { X } from 'lucide-react';
import type { PolicyVersion } from '../../api/client';
import { diffSpecs } from '../../lib/policyDiff';
import { SectionTitle } from '../ui';

// Diff between two versions of a policy, block by block (W12-F-01): pick
// two versions, see each field of each block side by side, the changed
// ones marked. The versions come from listPolicyVersions, which carries
// every version's spec.
export const PolicyDiff: React.FC<{ name: string; versions: PolicyVersion[]; onClose: () => void }> = ({
  name,
  versions,
  onClose,
}) => {
  const { t } = useTranslation();
  const nums = useMemo(() => versions.map((v) => v.version ?? 0).sort((a, b) => b - a), [versions]);
  const [to, setTo] = useState(nums[0] ?? 0);
  const [from, setFrom] = useState(nums[1] ?? nums[0] ?? 0);
  const spec = (n: number) => versions.find((v) => v.version === n)?.spec ?? {};
  const blocks = diffSpecs(spec(from), spec(to));
  const changed = blocks.reduce((n, b) => n + b.changed, 0);

  const pick = (id: string, value: number, set: (n: number) => void, testId: string) => (
    <label className="flex items-center gap-2 text-[13px]">
      <span className="label">{t(`diff.${id}`)}</span>
      <select className="field" value={value} onChange={(e) => set(Number(e.target.value))} data-testid={testId}>
        {nums.map((n) => (
          <option key={n} value={n}>
            v{n}
          </option>
        ))}
      </select>
    </label>
  );

  return (
    <section className="panel" data-testid="policy-diff">
      <SectionTitle
        aside={
          <button type="button" className="btn" onClick={onClose} data-testid="diff-close">
            <X className="w-3.5 h-3.5" />
            {t('diff.close')}
          </button>
        }
      >
        {t('diff.title', { name })}
      </SectionTitle>
      <div className="flex flex-wrap items-center gap-4 px-4 pt-3">
        {pick('from', from, setFrom, 'diff-from')}
        {pick('to', to, setTo, 'diff-to')}
        <span className="text-[13px] text-muted" role="status" data-testid="diff-summary">
          {from === to ? t('diff.same') : changed === 0 ? t('diff.none') : t('diff.changed', { count: changed })}
        </span>
      </div>
      <div className="overflow-x-auto px-4 py-3">
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-line bg-sunken/50">
              <th className="th">{t('diff.field')}</th>
              <th className="th">v{from}</th>
              <th className="th">v{to}</th>
            </tr>
          </thead>
          {blocks.map((b) => (
            <tbody key={b.block} data-testid={`diff-block-${b.block}`}>
              <tr className="border-b border-line">
                <th colSpan={3} className="th text-left">
                  {t(`diff.block.${b.block}`)}
                  <span className="ml-2 font-normal text-muted" data-testid="diff-block-count">
                    {b.changed === 0 ? t('diff.blockSame') : t('diff.changed', { count: b.changed })}
                  </span>
                </th>
              </tr>
              {b.fields.map((f) => (
                <tr
                  key={f.key}
                  data-testid="diff-field"
                  data-changed={f.changed ? 'true' : 'false'}
                  className={`border-b border-line last:border-0 ${f.changed ? 'bg-shadow/10' : ''}`}
                >
                  <td className="td">
                    {f.changed && <span className="sr-only">{t('diff.changedField')} </span>}
                    <span className={f.changed ? 'font-medium' : 'text-muted'}>{t(`diff.key.${f.key}`)}</span>
                    <code className="ml-2 text-xs text-muted">{f.key}</code>
                  </td>
                  <td className="td font-mono text-xs">{f.from}</td>
                  <td className="td font-mono text-xs">
                    {f.to}
                    {(f.added ?? []).map((g) => (
                      <span key={`+${g}`} className="ml-2 text-ok" data-testid="diff-added">
                        +{g}
                      </span>
                    ))}
                    {(f.removed ?? []).map((g) => (
                      <span key={`-${g}`} className="ml-2 text-block" data-testid="diff-removed">
                        −{g}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          ))}
        </table>
      </div>
    </section>
  );
};
