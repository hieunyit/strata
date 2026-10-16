package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/auth"
	"github.com/strata/strata/control-plane/ingest"
)

type mockAuthWithSubject struct {
	subject string
	roles   []auth.Role
}

func (m mockAuthWithSubject) Authenticate(ctx context.Context, token string) (*auth.Principal, error) {
	return &auth.Principal{
		Subject: m.subject,
		Name:    m.subject,
		Roles:   m.roles,
	}, nil
}

func setupExceptionTestServer(t *testing.T, authHandler auth.Authenticator) (*Server, *ingest.MockEventStore) {
	t.Helper()
	store := ingest.NewMockEventStore()

	now := time.Now().UTC()
	events := []ingest.Event{
		{
			BlockID:       "STR-8F3K-Q2VD-7XNM-A1PC",
			Timestamp:     now.Add(-10 * time.Minute),
			NodeID:        "node-01",
			ConnectorType: "nginx",
			PolicyID:      "default-api",
			PolicyVersion: 1,
			ClientIP:      "192.0.2.42",
			HTTPMethod:    "POST",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/api/v1/auth",
			StatusCode:    403,
			Action:        "block",
			ScoreProtocol: 0,
			ScoreSQLi:     30,
			ScoreXSS:      0,
			ScoreAnomaly:  30,
			MatchedRules:  []uint32{942100},
			Violations: []ingest.Violation{
				{RuleID: 942100, Layer: "sqli", Field: "body.password", Snippet: "' OR '1'='1"},
			},
			UserAgent: "sqlmap/1.8",
		},
		{
			BlockID:       "EVT-0000-0000-0000-0001",
			Timestamp:     now.Add(-5 * time.Minute),
			NodeID:        "node-01",
			ConnectorType: "nginx",
			PolicyID:      "clean-policy",
			PolicyVersion: 1,
			ClientIP:      "192.0.2.55",
			HTTPMethod:    "GET",
			HTTPHost:      "api.example.test",
			HTTPPath:      "/clean",
			StatusCode:    200,
			Action:        "pass",
			MatchedRules:  nil, // No rules matched
			Violations:    nil,
		},
	}
	_ = store.SaveEvents(context.Background(), events)

	if authHandler == nil {
		authHandler = tokenRoles{}
	}

	server := NewServer(ServerConfig{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Auth:         authHandler,
	}, store)

	return server, store
}

func TestMarkFalsePositive(t *testing.T) {
	server, store := setupExceptionTestServer(t, nil)
	handler := server.Handler()

	t.Run("200 OK for valid Block ID and reason", func(t *testing.T) {
		body, _ := json.Marshal(MarkFalsePositiveRequest{Reason: "Legitimate login test"})
		req := httptest.NewRequest(http.MethodPost, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC:markFalsePositive", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var res MarkFalsePositiveResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if !res.FalsePositive || res.Reason != "Legitimate login test" {
			t.Errorf("unexpected response: %+v", res)
		}

		// Verify event in store was updated
		e, err := store.GetEvent(context.Background(), "STR-8F3K-Q2VD-7XNM-A1PC")
		if err != nil {
			t.Fatalf("failed to get event from store: %v", err)
		}
		if !e.FalsePositive || e.FalsePositiveReason != "Legitimate login test" {
			t.Errorf("event in store was not marked false positive: %+v", e)
		}
	})

	t.Run("404 Not Found for non-existent Block ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/events/STR-0000-0000-0000-9999:markFalsePositive", nil)
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("400 Bad Request for malformed Block ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/events/INVALID-ID:markFalsePositive", nil)
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("405 Method Not Allowed for GET on markFalsePositive", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC:markFalsePositive", nil)
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status 405, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestCreateExceptionFromBlockID(t *testing.T) {
	server, _ := setupExceptionTestServer(t, nil)
	handler := server.Handler()

	t.Run("201 Created for valid Block ID with narrowest scope", func(t *testing.T) {
		body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
			BlockID:    "STR-8F3K-Q2VD-7XNM-A1PC",
			TTLSeconds: 86400 * 7, // 7 days
			Reason:     "False positive in password field",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status 201, got %d: %s", rr.Code, rr.Body.String())
		}

		var exp Exception
		if err := json.Unmarshal(rr.Body.Bytes(), &exp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify narrowest scope
		if exp.PolicyID != "default-api" {
			t.Errorf("expected policy_id 'default-api', got %q", exp.PolicyID)
		}
		if exp.RuleID != 942100 {
			t.Errorf("expected rule_id 942100, got %d", exp.RuleID)
		}
		if exp.Field != "body.password" {
			t.Errorf("expected field 'body.password', got %q", exp.Field)
		}
		if exp.State != "SUBMITTED" {
			t.Errorf("expected state 'SUBMITTED', got %q", exp.State)
		}
		if exp.ExpiresAt.Before(time.Now().Add(6 * 86400 * time.Second)) {
			t.Errorf("expires_at not set properly: %v", exp.ExpiresAt)
		}
	})

	t.Run("404 Not Found for non-existent Block ID", func(t *testing.T) {
		body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
			BlockID:    "STR-0000-0000-0000-9999",
			TTLSeconds: 86400,
			Reason:     "Testing missing",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("400 Bad Request when event has no matched rules", func(t *testing.T) {
		body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
			BlockID:    "EVT-0000-0000-0000-0001",
			TTLSeconds: 86400,
			Reason:     "Testing clean event",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("400 Bad Request for excessive TTL (> 30 days)", func(t *testing.T) {
		body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
			BlockID:    "STR-8F3K-Q2VD-7XNM-A1PC",
			TTLSeconds: 86400 * 35, // 35 days
			Reason:     "Too long TTL",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("400 Bad Request for empty reason", func(t *testing.T) {
		body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
			BlockID:    "STR-8F3K-Q2VD-7XNM-A1PC",
			TTLSeconds: 86400,
			Reason:     "   ",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("403 Forbidden for viewer role", func(t *testing.T) {
		body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
			BlockID:    "STR-8F3K-Q2VD-7XNM-A1PC",
			TTLSeconds: 86400,
			Reason:     "Viewer trying to create exception",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer viewer")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestFourEyesApproval(t *testing.T) {
	// Create server with distinct subjects for operator and approver
	authHandler := &mockAuthDynamic{}
	server, _ := setupExceptionTestServer(t, authHandler)
	handler := server.Handler()

	// 1. Operator (alice) creates exception
	authHandler.currentSubject = "alice"
	authHandler.currentRoles = []auth.Role{auth.RoleOperator}

	body, _ := json.Marshal(CreateExceptionFromBlockIDRequest{
		BlockID:    "STR-8F3K-Q2VD-7XNM-A1PC",
		TTLSeconds: 86400 * 14,
		Reason:     "Drafted by alice",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/exceptions:fromBlockId", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token-alice")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("failed to create exception: %d: %s", rr.Code, rr.Body.String())
	}

	var created Exception
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	expID := created.ID

	// 2. Alice attempts to approve her own exception -> MUST FAIL with 403 Forbidden
	authHandler.currentSubject = "alice"
	authHandler.currentRoles = []auth.Role{auth.RoleAdmin} // Even if alice has admin role!

	reqApproveOwn := httptest.NewRequest(http.MethodPost, "/v1/exceptions/"+expID+":approve", nil)
	reqApproveOwn.Header.Set("Authorization", "Bearer token-alice")
	rrApproveOwn := httptest.NewRecorder()
	handler.ServeHTTP(rrApproveOwn, reqApproveOwn)

	if rrApproveOwn.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden when creator approves own exception, got %d: %s",
			rrApproveOwn.Code, rrApproveOwn.Body.String())
	}

	// 3. Different approver (bob) approves exception -> SUCCESS 200 OK
	authHandler.currentSubject = "bob"
	authHandler.currentRoles = []auth.Role{auth.RoleApprover}

	reqApproveBob := httptest.NewRequest(http.MethodPost, "/v1/exceptions/"+expID+":approve", nil)
	reqApproveBob.Header.Set("Authorization", "Bearer token-bob")
	rrApproveBob := httptest.NewRecorder()
	handler.ServeHTTP(rrApproveBob, reqApproveBob)

	if rrApproveBob.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when independent approver approves, got %d: %s",
			rrApproveBob.Code, rrApproveBob.Body.String())
	}

	var approvedRes ApproveExceptionResponse
	_ = json.Unmarshal(rrApproveBob.Body.Bytes(), &approvedRes)
	if approvedRes.Exception.State != "APPROVED" || approvedRes.Exception.ApprovedBy != "bob" {
		t.Errorf("exception not approved properly: %+v", approvedRes.Exception)
	}

	// 4. Cannot re-approve already approved exception -> 400 Bad Request
	authHandler.currentSubject = "charlie"
	authHandler.currentRoles = []auth.Role{auth.RoleApprover}

	reqReApprove := httptest.NewRequest(http.MethodPost, "/v1/exceptions/"+expID+":approve", nil)
	reqReApprove.Header.Set("Authorization", "Bearer token-charlie")
	rrReApprove := httptest.NewRecorder()
	handler.ServeHTTP(rrReApprove, reqReApprove)

	if rrReApprove.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for already approved exception, got %d", rrReApprove.Code)
	}
}

type mockAuthDynamic struct {
	currentSubject string
	currentRoles   []auth.Role
}

func (m *mockAuthDynamic) Authenticate(ctx context.Context, token string) (*auth.Principal, error) {
	return &auth.Principal{
		Subject: m.currentSubject,
		Name:    m.currentSubject,
		Roles:   m.currentRoles,
	}, nil
}

func TestMarkFalsePositivePermissionMatrix(t *testing.T) {
	for _, tc := range []struct {
		role string
		want int
	}{{"viewer", 403}, {"approver", 403}, {"operator", 200}, {"admin", 200}} {
		t.Run(tc.role, func(t *testing.T) {
			server, st := setupExceptionTestServer(t, mockAuthWithSubject{subject: "test-" + tc.role, roles: []auth.Role{auth.Role(tc.role)}})
			r := httptest.NewRequest("POST", "/v1/events/STR-8F3K-Q2VD-7XNM-A1PC:markFalsePositive", bytes.NewBufferString(`{"reason":"legitimate request"}`))
			r.Header.Set("Authorization", "Bearer "+tc.role)
			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("%s: %d %s", tc.role, w.Code, w.Body)
			}
			e, err := st.GetEvent(t.Context(), "STR-8F3K-Q2VD-7XNM-A1PC")
			if err != nil || e.FalsePositive != (tc.want == 200) {
				t.Fatalf("unexpected write: %+v %v", e, err)
			}
		})
	}
}
