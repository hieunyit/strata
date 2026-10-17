import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QuickActionModal } from '../components/geo/QuickActionModal';
import { DecisionTraceModal } from '../components/events/DecisionTraceModal';
import { GeoMap } from '../components/geo/GeoMap';
import { StaticAuthProvider } from '../context/AuthContext';
import { apiClient, Event, Policy } from '../api/client';

describe('Drill-down & Quick Action (W19-F-01)', () => {
  const mockPolicies: Policy[] = [
    { id: 'default-api', name: 'Default API Policy', version: 1 },
    { id: 'checkout-api', name: 'Checkout Payment Policy', version: 2 },
  ];

  const mockEvent: Event = {
    block_id: 'STR-TEST-1234-5678-ABCD',
    timestamp: '2026-10-17T12:00:00Z',
    node_id: 'node-01',
    connector_type: 'nginx',
    policy_id: 'default-api',
    policy_version: 1,
    client_ip: '198.51.100.42',
    http_host: 'api.example.test',
    http_method: 'POST',
    http_path: '/api/v1/checkout',
    status_code: 403,
    action: 'block',
    country_iso: 'KP',
    city: 'Pyongyang',
    asn: 13335,
    as_org: 'Cloudflare',
    violations: [
      { rule_id: 942100, layer: 'sqli', field: 'body.card_num', snippet: "' OR 1=1--" },
    ],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('QuickActionModal Component', () => {
    it('renders with initial values and submits quick rule draft', async () => {
      const onSuccess = vi.fn();
      const onClose = vi.fn();
      vi.spyOn(apiClient, 'quickRule').mockResolvedValue({
        policy_id: 'default-api',
        version: 2,
        etag: 'new-etag-2',
        message: 'Quick rule created draft version 2 for policy default-api',
      });

      render(
        <QuickActionModal
          isOpen={true}
          onClose={onClose}
          initialType="geo"
          initialTarget="KP"
          initialAction="block"
          policies={mockPolicies}
          currentPolicyId="default-api"
          onSuccess={onSuccess}
        />
      );

      expect(screen.getByText('Tạo Rule Chặn / Thử Thách Nhanh')).toBeInTheDocument();
      const input = screen.getByTestId('quick-target-input') as HTMLInputElement;
      expect(input.value).toBe('KP');

      // Submit form
      const submitBtn = screen.getByTestId('quick-submit-btn');
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(apiClient.quickRule).toHaveBeenCalledWith('default-api', {
          type: 'geo',
          target: 'KP',
          action: 'block',
          reason: 'SOC mitigation for GEO: KP',
        });
        expect(onSuccess).toHaveBeenCalled();
        expect(screen.getByText('Tạo bản nháp thành công!')).toBeInTheDocument();
      });
    });

    it('allows switching to challenge action and ASN target', async () => {
      vi.spyOn(apiClient, 'quickRule').mockResolvedValue({
        policy_id: 'checkout-api',
        version: 3,
        etag: 'new-etag-3',
        message: 'Draft created',
      });

      render(
        <QuickActionModal
          isOpen={true}
          onClose={vi.fn()}
          policies={mockPolicies}
          currentPolicyId="checkout-api"
        />
      );

      // Switch to ASN
      const asnBtn = screen.getByText('Mạng ASN (Autonomous System)');
      fireEvent.click(asnBtn);

      // Type ASN target
      const input = screen.getByTestId('quick-target-input');
      fireEvent.change(input, { target: { value: '7552' } });

      // Click challenge button
      const challengeBtn = screen.getByTestId('action-challenge-btn');
      fireEvent.click(challengeBtn);

      // Submit
      const submitBtn = screen.getByTestId('quick-submit-btn');
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(apiClient.quickRule).toHaveBeenCalledWith('checkout-api', {
          type: 'asn',
          target: '7552',
          action: 'challenge',
          reason: undefined,
        });
      });
    });

    it('displays error banner when API returns error', async () => {
      vi.spyOn(apiClient, 'quickRule').mockRejectedValue(new Error('Policy locked for review'));

      render(
        <QuickActionModal
          isOpen={true}
          onClose={vi.fn()}
          initialType="geo"
          initialTarget="RU"
          policies={mockPolicies}
        />
      );

      const submitBtn = screen.getByTestId('quick-submit-btn');
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByText('Policy locked for review')).toBeInTheDocument();
      });
    });
  });

  describe('DecisionTraceModal Component', () => {
    it('renders event trace and triggers quick action from modal', async () => {
      vi.spyOn(apiClient, 'getEvent').mockResolvedValue({
        event: mockEvent,
        rules: {
          '942100': {
            name: 'SQL Injection Attack Detected via libinjection',
            severity: 'critical',
            author: 'OWASP CRS',
            source: 'crs',
          },
        },
      });

      const onQuickAction = vi.fn();
      render(
        <StaticAuthProvider roles={['operator']}>
          <DecisionTraceModal
            event={mockEvent}
            onClose={vi.fn()}
            onQuickAction={onQuickAction}
          />
        </StaticAuthProvider>
      );

      expect(screen.getByText('Decision Trace — Block ID')).toBeInTheDocument();
      expect(screen.getByText('STR-TEST-1234-5678-ABCD')).toBeInTheDocument();

      await waitFor(() => {
        expect(screen.getByTestId('trace-quick-block-country')).toBeInTheDocument();
        expect(screen.getByTestId('trace-quick-block-asn')).toBeInTheDocument();
      });

      // Click quick block country
      fireEvent.click(screen.getByTestId('trace-quick-block-country'));
      expect(onQuickAction).toHaveBeenCalledWith('geo', 'KP', 'block');

      // Click quick block ASN
      fireEvent.click(screen.getByTestId('trace-quick-block-asn'));
      expect(onQuickAction).toHaveBeenCalledWith('asn', '13335', 'block');
    });
  });

  describe('GeoMap Quick Action Integration', () => {
    it('invokes onQuickAction when clicking quick action icon in country or ASN card', async () => {
      vi.spyOn(apiClient, 'getGeoStats').mockResolvedValue({
        from: '2026-10-16T00:00:00Z',
        to: '2026-10-17T00:00:00Z',
        countries: [
          { country_iso: 'VN', events: 1000, blocked: 100, top_attack_type: 'sqli' },
        ],
        asns: [
          { asn: 7552, as_org: 'Viettel', events: 800, blocked: 80 },
        ],
      });

      const onQuickAction = vi.fn();
      render(<GeoMap onQuickAction={onQuickAction} />);

      await waitFor(() => {
        expect(screen.getByTestId('quick-rule-country-VN')).toBeInTheDocument();
        expect(screen.getByTestId('quick-rule-asn-7552')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByTestId('quick-rule-country-VN'));
      expect(onQuickAction).toHaveBeenCalledWith('geo', 'VN', 'block');

      fireEvent.click(screen.getByTestId('quick-rule-asn-7552'));
      expect(onQuickAction).toHaveBeenCalledWith('asn', '7552', 'block');
    });
  });
});
