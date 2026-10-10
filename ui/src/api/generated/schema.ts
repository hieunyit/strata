/**
 * OpenAPI 3.0 types for Strata Control Plane API.
 * Generated from docs/spec/openapi.yaml.
 */

export interface paths {
  "/v1/events/{block_id}": {
    get: {
      parameters: {
        path: {
          block_id: string;
        };
      };
      responses: {
        200: {
          content: {
            "application/json": components["schemas"]["GetEventResponse"];
          };
        };
        400: {
          content: {
            "application/json": components["schemas"]["ErrorResponse"];
          };
        };
        404: {
          content: {
            "application/json": components["schemas"]["ErrorResponse"];
          };
        };
        500: {
          content: {
            "application/json": components["schemas"]["ErrorResponse"];
          };
        };
      };
    };
  };
  "/v1/events:search": {
    post: {
      requestBody: {
        content: {
          "application/json": components["schemas"]["SearchEventsRequest"];
        };
      };
      responses: {
        200: {
          content: {
            "application/json": components["schemas"]["SearchEventsResponse"];
          };
        };
        400: {
          content: {
            "application/json": components["schemas"]["ErrorResponse"];
          };
        };
        500: {
          content: {
            "application/json": components["schemas"]["ErrorResponse"];
          };
        };
      };
    };
  };
}

export interface components {
  schemas: {
    Violation: {
      rule_id: number;
      layer: string;
      field: string;
      snippet: string;
    };
    Event: {
      block_id: string;
      timestamp: string;
      node_id: string;
      connector_type: string;
      policy_id: string;
      policy_version: number;
      client_ip: string;
      identity?: string;
      request_id?: string;
      http_method: string;
      http_host: string;
      http_path: string;
      status_code: number;
      action: "block" | "shadow" | "allow" | string;
      score_protocol?: number;
      score_sqli?: number;
      score_xss?: number;
      score_anomaly?: number;
      matched_rules?: number[];
      violations?: components["schemas"]["Violation"][];
      received_at?: string;
    };
    GetEventResponse: {
      event: components["schemas"]["Event"];
    };
    SearchEventsRequest: {
      from?: string;
      to?: string;
      policy_id?: string;
      action?: "block" | "shadow" | "allow" | string;
      client_ip?: string;
      rule_id?: number;
      node_id?: string;
      http_method?: string;
      page_size?: number;
      page_token?: string;
    };
    SearchEventsResponse: {
      events: components["schemas"]["Event"][];
      next_page_token?: string;
      total_matched: number;
    };
    ErrorResponse: {
      error: string;
      block_id?: string;
      code?: number;
    };
  };
}
