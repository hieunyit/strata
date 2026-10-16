import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GeoMap } from '../components/geo/GeoMap';
import { apiClient } from '../api/client';

describe('GeoMap Component (W17-F-01)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(apiClient, 'getGeoStats').mockResolvedValue({
      from: '2026-10-16T00:00:00Z',
      to: '2026-10-17T00:00:00Z',
      countries: [
        { country_iso: 'VN', events: 1500, blocked: 200, top_attack_type: 'sqli' },
        { country_iso: 'US', events: 800, blocked: 120, top_attack_type: 'xss' },
      ],
      asns: [
        { asn: 7552, as_org: 'Viettel Group', events: 1200, blocked: 150 },
        { asn: 14618, as_org: 'Amazon.com', events: 600, blocked: 90 },
      ],
      grid: [
        { geohash: 'w7_hanoi', lat: 21.02, lon: 105.85, city: 'Hanoi', country_iso: 'VN', events: 1000, blocked: 100, top_attack_type: 'sqli' },
      ],
    });
  });

  it('renders threat map container and header indicators', async () => {
    render(<GeoMap />);
    expect(screen.getByTestId('geomap-container')).toBeInTheDocument();
    expect(screen.getByText(/Threat Intelligence Map & GeoIP/i)).toBeInTheDocument();
    expect(screen.getByText(/Air-Gapped \/ PMTiles/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('VN')).toBeInTheDocument();
      expect(screen.getByText('AS7552')).toBeInTheDocument();
    });
  });

  it('strictly affirms Vietnamese sovereignty over Hoàng Sa and Trường Sa islands (Nghị định 18/2020/NĐ-CP)', async () => {
    render(<GeoMap />);
    // Check legal notice in footer
    expect(screen.getByText(/Bản đồ tự host PMTiles tuân thủ chủ quyền lãnh thổ Việt Nam/i)).toBeInTheDocument();

    // Check SVG sovereignty nodes
    const islandsGroup = screen.getByTestId('vietnam-islands');
    expect(islandsGroup).toBeInTheDocument();
    expect(screen.getByText(/Hoàng Sa \(VN\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Trường Sa \(VN\)/i)).toBeInTheDocument();
  });

  it('supports time-window switching and triggers api reload', async () => {
    render(<GeoMap />);

    const btn7d = screen.getByTestId('time-window-7d');
    fireEvent.click(btn7d);

    await waitFor(() => {
      expect(apiClient.getGeoStats).toHaveBeenCalledTimes(2);
    });
  });

  it('fires onSelectCountry callback when clicking on country row or map point', async () => {
    const handleSelectCountry = vi.fn();
    render(<GeoMap onSelectCountry={handleSelectCountry} />);

    await waitFor(() => {
      expect(screen.getByTestId('country-row-VN')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('country-row-VN'));
    expect(handleSelectCountry).toHaveBeenCalledWith('VN');

    // Deselect by clicking again
    fireEvent.click(screen.getByTestId('country-row-VN'));
    expect(handleSelectCountry).toHaveBeenCalledWith('');

    // Select again and clear via clear button
    fireEvent.click(screen.getByTestId('country-row-VN'));
    expect(screen.getByTestId('clear-country-filter')).toBeInTheDocument();
    fireEvent.click(screen.getByTestId('clear-country-filter'));
    expect(handleSelectCountry).toHaveBeenCalledWith('');
  });

  it('fires onSelectASN callback when clicking on an ASN entry', async () => {
    const handleSelectASN = vi.fn();
    render(<GeoMap onSelectASN={handleSelectASN} />);

    await waitFor(() => {
      expect(screen.getByTestId('asn-row-7552')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('asn-row-7552'));
    expect(handleSelectASN).toHaveBeenCalledWith(7552);
  });
});
