package thingscloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Histories(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		server := fakeServer(fakeResponse{200, "histories-success.json"})
		defer server.Close()

		c := New(fmt.Sprintf("http://%s", server.Listener.Addr().String()), "martin@example.com", "")
		hs, err := c.Histories()
		if err != nil {
			t.Fatalf("Expected history request to succeed, but didn't: %q", err.Error())
		}
		if len(hs) != 1 {
			t.Errorf("Expected to receive %d histories, but got %d", 1, len(hs))
		}
	})

	t.Run("Error", func(t *testing.T) {
		t.Parallel()
		server := fakeServer(fakeResponse{401, "error.json"})
		defer server.Close()

		c := New(fmt.Sprintf("http://%s", server.Listener.Addr().String()), "unknown@example.com", "")
		_, err := c.Histories()
		if err == nil {
			t.Error("Expected history request to fail, but didn't")
		}
	})
}

type testIdentifiable struct {
	ID string `json:"-"`
	T  int    `json:"t"`
}

func (i testIdentifiable) UUID() string { return i.ID }

func TestHistoryWriteRejectsMalformedCommitResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"server-head-index":`))
	}))
	defer server.Close()

	c := New(server.URL, "test@example.com", "password")
	h := &History{Client: c, ID: "history", LatestServerIndex: 7, LatestSchemaVersion: 301}
	if err := h.Write(testIdentifiable{ID: "task-1", T: 1}); err == nil {
		t.Fatal("expected malformed response error")
	}
	if h.LatestServerIndex != 7 {
		t.Fatalf("LatestServerIndex mutated to %d", h.LatestServerIndex)
	}
}

func TestHistoryWriteRejectsUnsupportedSchema(t *testing.T) {
	t.Parallel()

	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"server-head-index": 9})
	}))
	defer server.Close()

	c := New(server.URL, "test@example.com", "password")
	h := &History{Client: c, ID: "history", LatestServerIndex: 8, LatestSchemaVersion: 302}
	if err := h.Write(testIdentifiable{ID: "task-1", T: 1}); err == nil {
		t.Fatal("expected unsupported schema error")
	}
	if calls != 0 {
		t.Fatalf("commit endpoint called %d times", calls)
	}
}

func TestClient_CreateHistory(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		server := fakeServer(fakeResponse{200, "create-history-success.json"})
		defer server.Close()

		c := New(fmt.Sprintf("http://%s", server.Listener.Addr().String()), "martin@example.com", "")
		h, err := c.CreateHistory()
		if err != nil {
			t.Fatalf("Expected request to succeed, but didn't: %q", err.Error())
		}
		if h.ID != "test-history-key-1" {
			t.Fatalf("Expected key %s but got %s", "test-history-key-1", h.ID)
		}
	})
}

func TestHistory_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		server := fakeServer(fakeResponse{202, "create-history-success.json"})
		defer server.Close()

		c := New(fmt.Sprintf("http://%s", server.Listener.Addr().String()), "martin@example.com", "")
		h := History{Client: c, ID: "test-history-key-1"}
		err := h.Delete()
		if err != nil {
			t.Fatalf("Expected request to succeed, but didn't: %q", err.Error())
		}
	})
}

func TestHistory_Sync(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		server := fakeServer(fakeResponse{200, "history-success.json"})
		defer server.Close()

		c := New(fmt.Sprintf("http://%s", server.Listener.Addr().String()), "martin@example.com", "")
		h := History{Client: c, ID: "test-history-key-1"}
		err := h.Sync()
		if err != nil {
			t.Fatalf("Expected request to succeed, but didn't: %q", err.Error())
		}
		if h.LatestServerIndex != 27 {
			t.Errorf("Expected LatestServerIndex of %d, but got %d", 27, h.LatestServerIndex)
		}
	})
}
