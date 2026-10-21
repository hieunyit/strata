package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/strata/strata/control-plane/ingest"
	"github.com/strata/strata/control-plane/localauth"
	"github.com/strata/strata/control-plane/localauth/localauthtest"
)

func TestLocalMFAHTTPLoginAndRevocation(t *testing.T) {
	st := localauth.NewStore(localauthtest.Pool(t))
	svc, err := localauth.NewService(st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfigureMFA(bytes.Repeat([]byte{6}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Bootstrap(t.Context(), "example-admin", "example admin password"); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(ServerConfig{Auth: svc, Local: &localauth.Handler{Service: svc, Store: st}}, ingest.NewMockEventStore()).Handler()
	call := func(path, method, token string, body any) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(data))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		srv.ServeHTTP(response, request)
		return response
	}
	response := call("/v1/auth/login", "POST", "", map[string]string{"username": "example-admin", "password": "example admin password"})
	var session localauth.Session
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &session) != nil {
		t.Fatal("password login", response.Code)
	}
	response = call("/v1/auth/mfa:begin", "POST", session.Token, map[string]string{"password": "example admin password", "request_id": "example-enrollment"})
	var enrollment localauth.MFAEnrollment
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &enrollment) != nil {
		t.Fatal("enrollment", response.Code)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	code := func(step int64) string {
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(step))
		h := hmac.New(sha1.New, seed)
		_, _ = h.Write(counter[:])
		mac := h.Sum(nil)
		offset := mac[len(mac)-1] & 15
		return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(mac[offset:offset+4])&0x7fffffff)%1000000)
	}
	response = call("/v1/auth/mfa:confirm", "POST", session.Token, map[string]string{"etag": enrollment.Etag, "code": code(time.Now().Unix() / 30)})
	if response.Code != 200 {
		t.Fatal("confirmation", response.Code)
	}
	response = call("/v1/auth/login", "POST", "", map[string]string{"username": "example-admin", "password": "example admin password"})
	if response.Code != 401 || !bytes.Contains(response.Body.Bytes(), []byte("MFA_REQUIRED")) {
		t.Fatal("password bypassed MFA", response.Code)
	}
	response = call("/v1/auth/login", "POST", "", map[string]string{"username": "example-admin", "password": "example admin password", "code": code(time.Now().Unix()/30 + 1)})
	if response.Code != 200 {
		t.Fatal("MFA login", response.Code)
	}
	response = call("/v1/auth/sessions", "GET", session.Token, nil)
	var list struct {
		Sessions []localauth.OwnSession `json:"sessions"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &list) != nil {
		t.Fatal("session list", response.Code)
	}
	for _, s := range list.Sessions {
		if s.Current {
			response = call("/v1/auth/sessions/"+s.ID+":revoke", "POST", session.Token, map[string]string{"etag": s.Etag})
			if response.Code != 204 {
				t.Fatal("revoke", response.Code)
			}
		}
	}
	if response := call("/v1/auth/sessions", "GET", session.Token, nil); response.Code != 401 {
		t.Fatal("revoked session authenticated", response.Code)
	}
}
