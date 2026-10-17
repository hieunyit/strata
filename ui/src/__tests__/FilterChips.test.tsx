import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { FilterChips, FilterState } from '../components/geo/FilterChips';

describe('FilterChips Component (W18-F-01)', () => {
  const initialFilters: FilterState = {
    timeRange: '24h',
    action: 'all',
    category: 'all',
    selectedCountry: null,
    selectedASN: null,
  };

  it('renders time ranges, actions, and threat categories', () => {
    const handleChange = vi.fn();
    const handleToggleLive = vi.fn();

    render(
      <FilterChips
        filters={initialFilters}
        onChange={handleChange}
        liveStreaming={true}
        onToggleLive={handleToggleLive}
      />
    );

    expect(screen.getByText('24h')).toBeInTheDocument();
    expect(screen.getByText('7d')).toBeInTheDocument();
    expect(screen.getByText('Blocked')).toBeInTheDocument();
    expect(screen.getByText('SQLi')).toBeInTheDocument();
    expect(screen.getByText('LIVE (SSE 3s)')).toBeInTheDocument();
  });

  it('triggers onChange when switching time range or action', () => {
    const handleChange = vi.fn();
    const handleToggleLive = vi.fn();

    render(
      <FilterChips
        filters={initialFilters}
        onChange={handleChange}
        liveStreaming={true}
        onToggleLive={handleToggleLive}
      />
    );

    fireEvent.click(screen.getByText('7d'));
    expect(handleChange).toHaveBeenCalledWith(expect.objectContaining({ timeRange: '7d' }));

    fireEvent.click(screen.getByText('Blocked'));
    expect(handleChange).toHaveBeenCalledWith(expect.objectContaining({ action: 'block' }));
  });

  it('renders active country/ASN chips and allows clearing them', () => {
    const handleChange = vi.fn();
    const activeFilters: FilterState = {
      ...initialFilters,
      selectedCountry: 'VN',
      selectedASN: 7552,
      selectedASOrg: 'Viettel',
    };

    render(
      <FilterChips
        filters={activeFilters}
        onChange={handleChange}
        liveStreaming={false}
        onToggleLive={vi.fn()}
      />
    );

    expect(screen.getByText('Country: VN')).toBeInTheDocument();
    expect(screen.getByText(/AS7552 \(Viettel\)/i)).toBeInTheDocument();

    const clearBtns = screen.getAllByText('✕');
    expect(clearBtns.length).toBeGreaterThanOrEqual(2);

    fireEvent.click(clearBtns[0]);
    expect(handleChange).toHaveBeenCalledWith(expect.objectContaining({ selectedCountry: null }));

    // Reset button
    const resetBtn = screen.getByText('Reset');
    fireEvent.click(resetBtn);
    expect(handleChange).toHaveBeenCalledWith(expect.objectContaining({
      timeRange: '24h',
      action: 'all',
      selectedCountry: null,
      selectedASN: null,
    }));
  });

  it('toggles live streaming mode', () => {
    const handleToggleLive = vi.fn();

    render(
      <FilterChips
        filters={initialFilters}
        onChange={vi.fn()}
        liveStreaming={false}
        onToggleLive={handleToggleLive}
      />
    );

    const btn = screen.getByText(/PAUSED/i);
    fireEvent.click(btn);
    expect(handleToggleLive).toHaveBeenCalledTimes(1);
  });
});
