import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EngineLatencyWidget } from '../components/overview/EngineLatencyWidget';
import { ActiveRolloutBanner } from '../components/overview/ActiveRolloutBanner';
import { NodeFaultList } from '../components/overview/NodeFaultList';
import { Rollout, FleetNode } from '../api/client';

describe('Overview Full Dashboard Components (W20-F-01)', () => {
  describe('EngineLatencyWidget Component', () => {
    it('renders latency percentiles and displays SLA OK badge when p99 < 1ms', () => {
      render(
        <EngineLatencyWidget
          latency={{
            p50_micros: 120,
            p90_micros: 260,
            p99_micros: 480,
            sample_count: 50000,
          }}
        />
      );

      expect(screen.getByTestId('engine-latency-widget')).toBeInTheDocument();
      expect(screen.getByText('120 µs')).toBeInTheDocument();
      expect(screen.getByText('260 µs')).toBeInTheDocument();
      expect(screen.getByText('480 µs')).toBeInTheDocument();

      const slaBadge = screen.getByTestId('latency-sla-badge');
      expect(slaBadge).toHaveTextContent('SLA OK (< 1ms)');
      expect(screen.getByText(/50,000 samples/i)).toBeInTheDocument();
    });

    it('displays SLA warning/breach when p99 exceeds 1ms', () => {
      render(
        <EngineLatencyWidget
          latency={{
            p50_micros: 350,
            p90_micros: 900,
            p99_micros: 1250, // 1.25 ms
            sample_count: 10000,
          }}
        />
      );

      expect(screen.getByText('1.25 ms')).toBeInTheDocument();
      const slaBadge = screen.getByTestId('latency-sla-badge');
      expect(slaBadge).toBeInTheDocument();
    });
  });

  describe('ActiveRolloutBanner Component', () => {
    it('renders rollout banner when a rollout is RUNNING', () => {
      const rollout: Rollout = {
        id: 'rollout-42',
        bundle_version: '0.12.0',
        state: 'RUNNING',
        current_wave: 1,
        waves: [1, 5, 20],
      };

      render(<ActiveRolloutBanner rollout={rollout} />);

      const banner = screen.getByTestId('active-rollout-banner');
      expect(banner).toBeInTheDocument();
      expect(screen.getByText(/Rollout Đang Chạy: #rollout-42/i)).toBeInTheDocument();
      expect(screen.getByText('Bundle v0.12.0')).toBeInTheDocument();
      expect(screen.getByText('RUNNING')).toBeInTheDocument();
      expect(screen.getByText(/Làn sóng: 2\/3/i)).toBeInTheDocument();
    });

    it('returns null when rollout state is COMPLETED or undefined', () => {
      const { container } = render(<ActiveRolloutBanner rollout={{ id: '1', state: 'COMPLETED' }} />);
      expect(container.firstChild).toBeNull();
    });
  });

  describe('NodeFaultList Component', () => {
    it('renders list of faulty or offline nodes', () => {
      const nodes: FleetNode[] = [
        { id: 'node-healthy', hostname: 'edge-01.lan', online: true, bundle_state: 'ACTIVE' },
        { id: 'node-offline', hostname: 'edge-02.lan', online: false, last_seen_time: '2026-10-17T15:00:00Z' },
        { id: 'node-failed', hostname: 'edge-03.lan', online: true, bundle_state: 'FAILED', bundle_version: '0.12.0' },
      ];

      render(<NodeFaultList nodes={nodes} />);

      expect(screen.getByTestId('node-fault-panel')).toBeInTheDocument();
      expect(screen.getByText(/Cảnh báo Sự cố Node \(2\)/i)).toBeInTheDocument();
      expect(screen.getByTestId('faulty-node-node-offline')).toBeInTheDocument();
      expect(screen.getByTestId('faulty-node-node-failed')).toBeInTheDocument();
      expect(screen.queryByTestId('faulty-node-node-healthy')).not.toBeInTheDocument();
    });

    it('returns null when all nodes are healthy', () => {
      const nodes: FleetNode[] = [
        { id: 'node-1', online: true, bundle_state: 'ACTIVE' },
        { id: 'node-2', online: true, bundle_state: 'ACTIVE' },
      ];

      const { container } = render(<NodeFaultList nodes={nodes} />);
      expect(container.firstChild).toBeNull();
    });
  });
});
