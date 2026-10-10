import { components } from './generated/schema';

export type Event = components['schemas']['Event'];
export type Violation = components['schemas']['Violation'];
export type SearchEventsRequest = components['schemas']['SearchEventsRequest'];
export type SearchEventsResponse = components['schemas']['SearchEventsResponse'];
export type GetEventResponse = components['schemas']['GetEventResponse'];
export type ErrorResponse = components['schemas']['ErrorResponse'];

export class ApiError extends Error {
  code: number;
  blockId?: string;

  constructor(message: string, code: number, blockId?: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.blockId = blockId;
  }
}

const API_BASE = '/v1';

export const apiClient = {
  /**
   * Search security events via POST /v1/events:search
   */
  async searchEvents(params: SearchEventsRequest): Promise<SearchEventsResponse> {
    const res = await fetch(`${API_BASE}/events:search`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
    });

    if (!res.ok) {
      let errPayload: ErrorResponse = { error: `Request failed with status ${res.status}` };
      try {
        errPayload = await res.json();
      } catch {
        // use default error
      }
      throw new ApiError(errPayload.error || 'Failed to search events', res.status, errPayload.block_id);
    }

    return res.json();
  },

  /**
   * Retrieve event decision trace via GET /v1/events/{block_id}
   */
  async getEvent(blockId: string): Promise<GetEventResponse> {
    const trimmedId = encodeURIComponent(blockId.trim().toUpperCase());
    const res = await fetch(`${API_BASE}/events/${trimmedId}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      let errPayload: ErrorResponse = { error: `Request failed with status ${res.status}` };
      try {
        errPayload = await res.json();
      } catch {
        // use default error
      }
      throw new ApiError(errPayload.error || 'Failed to get event', res.status, errPayload.block_id);
    }

    return res.json();
  },
};
