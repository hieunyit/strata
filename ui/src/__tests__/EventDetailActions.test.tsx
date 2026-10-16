import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { StaticAuthProvider } from '../context/AuthContext';
import { EventDetailPage } from '../pages/EventDetailPage';
import { apiClient, Event, Exception } from '../api/client';
import i18n from '../i18n';

const testEvent: Event = {
  block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
  timestamp: new Date().toISOString(),
  node_id: 'edge-worker-01',
  connector_type: 'nginx',
  policy_id: 'example-api',
  policy_version: 1,
  client_ip: '198.51.100.42',
  identity: 'anon-client-1',
  request_id: 'req-001',
  http_method: 'POST',
  http_host: 'api.example.test',
  http_path: '/v1/users/search',
  status_code: 403,
  action: 'block',
  score_protocol: 0,
  score_sqli: 45,
  score_xss: 0,
  score_anomaly: 45,
  matched_rules: [942100],
  violations: [{ rule_id: 942100, layer: 'sqli', field: 'body.query', snippet: "' OR 1=1 --" }],
  received_at: new Date().toISOString(),
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(apiClient, 'getVersion').mockResolvedValue({ version: 'test', commit: '', api_version: 'v1' });
  void i18n.changeLanguage('vi');
  window.location.hash = '';
});

describe('EventDetailPage actions (W14-F-01)', () => {
  it('renders action toolbar on loaded event', async () => {
    vi.spyOn(apiClient, 'getEvent').mockResolvedValue({ event: testEvent, rules: {} });

    render(
      <StaticAuthProvider roles={['operator']} username="operator-alice">
        <EventDetailPage blockId="STR-8F3K-Q2VD-7XNM-A1PC" />
      </StaticAuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('detail-block-id')).toHaveTextContent('STR-8F3K-Q2VD-7XNM-A1PC');
    });

    expect(screen.getByTestId('btn-mark-fp')).toBeInTheDocument();
    expect(screen.getByTestId('btn-create-exception')).toBeInTheDocument();
    expect(screen.getByTestId('btn-block-identity')).toBeInTheDocument();
  });

  it('marks false positive with reason modal', async () => {
    vi.spyOn(apiClient, 'getEvent').mockResolvedValue({ event: testEvent, rules: {} });
    const markFpSpy = vi.spyOn(apiClient, 'markFalsePositive').mockResolvedValue({
      block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
      false_positive: true,
      reason: 'Tham số tìm kiếm hợp lệ',
      marked_by: 'operator-alice',
      marked_at: new Date().toISOString(),
    });

    render(
      <StaticAuthProvider roles={['operator']} username="operator-alice">
        <EventDetailPage blockId="STR-8F3K-Q2VD-7XNM-A1PC" />
      </StaticAuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('btn-mark-fp')).toBeInTheDocument();
    });

    // Click mark FP
    fireEvent.click(screen.getByTestId('btn-mark-fp'));
    expect(screen.getByTestId('modal-mark-fp')).toBeInTheDocument();

    // Type reason
    fireEvent.change(screen.getByTestId('fp-reason-input'), { target: { value: 'Tham số tìm kiếm hợp lệ' } });

    // Submit
    fireEvent.click(screen.getByTestId('submit-mark-fp'));

    await waitFor(() => {
      expect(markFpSpy).toHaveBeenCalledWith('STR-8F3K-Q2VD-7XNM-A1PC', 'Tham số tìm kiếm hợp lệ');
      expect(screen.getByTestId('badge-fp-marked')).toBeInTheDocument();
    });
  });

  it('creates exception with pre-filled scope and enforces 4-Eyes approval', async () => {
    vi.spyOn(apiClient, 'getEvent').mockResolvedValue({ event: testEvent, rules: {} });
    const mockCreatedException: Exception = {
      id: 'exp-12345678',
      block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
      policy_id: 'example-api',
      rule_id: 942100,
      field: 'body.query',
      reason: 'Bỏ qua kiểm tra cho tham số query',
      state: 'SUBMITTED',
      created_by: 'operator-alice',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 14 * 86400 * 1000).toISOString(),
    };

    vi.spyOn(apiClient, 'createExceptionFromBlockId').mockResolvedValue(mockCreatedException);

    render(
      <StaticAuthProvider roles={['operator']} username="operator-alice">
        <EventDetailPage blockId="STR-8F3K-Q2VD-7XNM-A1PC" />
      </StaticAuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('btn-create-exception')).toBeInTheDocument();
    });

    // Open create exception modal
    fireEvent.click(screen.getByTestId('btn-create-exception'));
    expect(screen.getByTestId('modal-create-exception')).toBeInTheDocument();

    // Check pre-filled values
    const modal = screen.getByTestId('modal-create-exception');
    expect(within(modal).getByText('example-api')).toBeInTheDocument();
    expect(within(modal).getByText('942100')).toBeInTheDocument();
    expect(within(modal).getByText('body.query')).toBeInTheDocument();

    // Enter reason
    fireEvent.change(screen.getByTestId('exception-reason-input'), {
      target: { value: 'Bỏ qua kiểm tra cho tham số query' },
    });

    // Submit
    fireEvent.click(screen.getByTestId('submit-create-exception'));

    await waitFor(() => {
      expect(screen.getByTestId('exception-card')).toBeInTheDocument();
      expect(screen.getByText('exp-12345678')).toBeInTheDocument();
    });

    // 4-Eyes rule: Alice is the creator, so Approve button MUST be disabled
    expect(screen.getByTestId('btn-approve-disabled')).toBeInTheDocument();
  });

  it('allows independent approver (bob) to approve exception', async () => {
    vi.spyOn(apiClient, 'getEvent').mockResolvedValue({ event: testEvent, rules: {} });
    const mockCreatedException: Exception = {
      id: 'exp-abcdef',
      block_id: 'STR-8F3K-Q2VD-7XNM-A1PC',
      policy_id: 'example-api',
      rule_id: 942100,
      field: 'body.query',
      reason: 'Drafted by alice',
      state: 'SUBMITTED',
      created_by: 'operator-alice', // created by alice
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 14 * 86400 * 1000).toISOString(),
    };

    vi.spyOn(apiClient, 'createExceptionFromBlockId').mockResolvedValue(mockCreatedException);
    const approveSpy = vi.spyOn(apiClient, 'approveException').mockResolvedValue({
      ...mockCreatedException,
      state: 'APPROVED',
      approved_by: 'approver-bob',
    });

    // Render with bob as current logged-in user
    render(
      <StaticAuthProvider roles={['approver']} username="approver-bob">
        <EventDetailPage blockId="STR-8F3K-Q2VD-7XNM-A1PC" />
      </StaticAuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('btn-create-exception')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('btn-create-exception'));
    fireEvent.change(screen.getByTestId('exception-reason-input'), { target: { value: 'Some reason' } });
    fireEvent.click(screen.getByTestId('submit-create-exception'));

    await waitFor(() => {
      expect(screen.getByTestId('exception-card')).toBeInTheDocument();
    });

    // Bob is NOT creator -> Approve button is ENABLED
    const approveBtn = screen.getByTestId('btn-approve-exception');
    expect(approveBtn).toBeInTheDocument();

    fireEvent.click(approveBtn);

    await waitFor(() => {
      expect(approveSpy).toHaveBeenCalledWith('exp-abcdef');
      expect(screen.getByText('Đã duyệt')).toBeInTheDocument();
    });
  });

  it('blocks IP / identity with confirmation modal', async () => {
    vi.spyOn(apiClient, 'getEvent').mockResolvedValue({ event: testEvent, rules: {} });

    render(
      <StaticAuthProvider roles={['operator']} username="operator-alice">
        <EventDetailPage blockId="STR-8F3K-Q2VD-7XNM-A1PC" />
      </StaticAuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('btn-block-identity')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('btn-block-identity'));
    const blockModal = screen.getByTestId('modal-block-identity');
    expect(within(blockModal).getByText('198.51.100.42')).toBeInTheDocument();

    fireEvent.change(screen.getByTestId('block-reason-input'), { target: { value: 'SQL injection attack detected' } });
    fireEvent.click(screen.getByTestId('submit-block-identity'));

    await waitFor(() => {
      expect(screen.getByTestId('badge-blocked-identity')).toBeInTheDocument();
    });
  });
});
