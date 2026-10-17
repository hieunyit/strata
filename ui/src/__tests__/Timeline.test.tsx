import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { TimelineChart } from '../components/geo/TimelineChart';
import { TimelineBucket } from '../api/client';

describe('TimelineChart Component (W18-F-01)', () => {
  const mockBuckets: TimelineBucket[] = [
    {
      timestamp: '2026-10-17T10:00:00Z',
      total: 1000,
      blocked: 150,
      monitored: 50,
      passed: 800,
      attack_types: { sqli: 100, xss: 50 },
    },
    {
      timestamp: '2026-10-17T11:00:00Z',
      total: 2000,
      blocked: 400,
      monitored: 100,
      passed: 1500,
      attack_types: { sqli: 300, rce: 100 },
    },
  ];

  it('renders timeline container and aggregated KPI summary metrics', () => {
    render(<TimelineChart buckets={mockBuckets} step="1h" />);

    expect(screen.getByTestId('timeline-container')).toBeInTheDocument();
    expect(screen.getByText(/Traffic & Threat Mitigation Timeline/i)).toBeInTheDocument();
    expect(screen.getByText('Granularity: 1h')).toBeInTheDocument();

    // Total = 3000
    expect(screen.getByText('3,000')).toBeInTheDocument();
    // Blocked = 550
    expect(screen.getByText('550')).toBeInTheDocument();
    // Block rate = 550/3000 = 18.3%
    expect(screen.getByText('18.3%')).toBeInTheDocument();
  });

  it('renders active filter tag when filtered by country or ASN', () => {
    render(<TimelineChart buckets={mockBuckets} step="5m" activeFilter="Country: VN" />);

    expect(screen.getByText('Granularity: 5m')).toBeInTheDocument();
    expect(screen.getByText('Country: VN')).toBeInTheDocument();
  });

  it('shows empty message when no traffic samples exist', () => {
    render(<TimelineChart buckets={[]} step="1h" />);
    expect(screen.getByText(/No traffic samples recorded in this window/i)).toBeInTheDocument();
  });
});
