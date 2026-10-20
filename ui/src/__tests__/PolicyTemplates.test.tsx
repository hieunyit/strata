import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NewPolicy } from '../components/policy/NewPolicy';
import { apiClient, ApiError } from '../api/client';
import i18n from '../i18n';

beforeEach(() => {
  vi.restoreAllMocks();
  void i18n.changeLanguage('en');
});

const templates = [
  { name: 'api', version: 1, description: 'JSON/REST API with an OpenAPI description', spec: { mode: 'MODE_SHADOW' as const, oversize: 'OVERSIZE_BLOCK' as const } },
  { name: 'base', version: 1, description: 'Defaults of the engine', spec: { mode: 'MODE_SHADOW' as const } },
];

// W20-S-01: a new policy from a template.
describe('new policy from a template', () => {
  it('creates a draft from the api template by default', async () => {
    vi.spyOn(apiClient, 'listPolicyTemplates').mockResolvedValue(templates);
    const create = vi.spyOn(apiClient, 'createPolicy').mockResolvedValue({ id: 'example-api', name: 'example-api', version: 1 });
    const created = vi.fn();
    render(<NewPolicy onCreated={created} onCancel={vi.fn()} />);
    expect(await screen.findByTestId('new-policy-description')).toHaveTextContent('OpenAPI');
    expect(screen.getByTestId('new-policy-create')).toBeDisabled();
    fireEvent.change(screen.getByTestId('new-policy-id'), { target: { value: 'Example' } });
    fireEvent.change(screen.getByTestId('new-policy-name'), { target: { value: 'example-api' } });
    expect(screen.getByTestId('new-policy-create')).toBeDisabled(); // id with a capital
    fireEvent.change(screen.getByTestId('new-policy-id'), { target: { value: 'example-api' } });
    fireEvent.change(screen.getByTestId('new-policy-template'), { target: { value: 'base' } });
    expect(screen.getByTestId('new-policy-description')).toHaveTextContent('Defaults');
    fireEvent.change(screen.getByTestId('new-policy-template'), { target: { value: 'api' } });
    fireEvent.click(screen.getByTestId('new-policy-create'));
    await waitFor(() => expect(create).toHaveBeenCalledWith('example-api', 'example-api', 'api'));
    expect(created).toHaveBeenCalledWith({ id: 'example-api', name: 'example-api', version: 1 });
  });

  it('says when the policy exists', async () => {
    vi.spyOn(apiClient, 'listPolicyTemplates').mockResolvedValue(templates);
    vi.spyOn(apiClient, 'createPolicy').mockRejectedValue(new ApiError('exists', 409));
    render(<NewPolicy onCreated={vi.fn()} onCancel={vi.fn()} />);
    await screen.findByTestId('new-policy-description');
    fireEvent.change(screen.getByTestId('new-policy-id'), { target: { value: 'example-api' } });
    fireEvent.change(screen.getByTestId('new-policy-name'), { target: { value: 'example-api' } });
    fireEvent.click(screen.getByTestId('new-policy-create'));
    expect(await screen.findByText('A policy with this id or name exists')).toBeInTheDocument();
  });
});
