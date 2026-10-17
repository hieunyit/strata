package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/strata/strata/control-plane/store"
)

type StagingNoticeReader interface {
	StagingNotices(context.Context, *time.Time, string, int) ([]store.StagingNotice, error)
}

type stagingNoticeCursor struct {
	Before time.Time `json:"before"`
	ID     string    `json:"id"`
}
type stagingNoticePage struct {
	Notices    []store.StagingNotice `json:"notices"`
	NextCursor string                `json:"next_cursor"`
}

func (s *Server) handleStagingNotices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, 405, "GET required", "")
		return
	}
	bad := func() { writeError(w, 400, "invalid staging notice page", "") }
	if len(r.URL.RawQuery) > 1024 {
		bad()
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		bad()
		return
	}
	for key, values := range q {
		if (key != "cursor" && key != "limit") || len(values) != 1 {
			bad()
			return
		}
	}
	limit := 20
	if value, ok := q["limit"]; ok {
		limit, err = strconv.Atoi(value[0])
		if err != nil || limit < 1 || limit > 50 {
			bad()
			return
		}
	}
	var before *time.Time
	id := ""
	if value, ok := q["cursor"]; ok {
		if len(value[0]) < 1 || len(value[0]) > 512 {
			bad()
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(value[0])
		if err != nil {
			bad()
			return
		}
		var cursor stagingNoticeCursor
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&cursor); err != nil {
			bad()
			return
		}
		if err = decoder.Decode(new(any)); err != io.EOF || cursor.Before.IsZero() || cursor.ID == "" || len(cursor.ID) > 128 {
			bad()
			return
		}
		before, id = &cursor.Before, cursor.ID
	}
	notices, err := s.cfg.StagingNotices.StagingNotices(r.Context(), before, id, limit+1)
	if err != nil {
		writeError(w, 503, "staging notices unavailable", "")
		return
	}
	page := stagingNoticePage{Notices: make([]store.StagingNotice, 0), NextCursor: ""}
	if len(notices) > limit {
		notices = notices[:limit]
		last := notices[len(notices)-1]
		raw, err := json.Marshal(stagingNoticeCursor{Before: last.CreatedAt, ID: last.ID})
		if err != nil {
			writeError(w, 503, "staging notices unavailable", "")
			return
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	page.Notices = append(page.Notices, notices...)
	writeJSON(w, 200, page)
}
