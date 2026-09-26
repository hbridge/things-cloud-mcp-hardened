package thingscloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHistory_Items(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		server := fakeServer(fakeResponse{200, "history-items-success.json"})
		defer server.Close()

		c := New(fmt.Sprintf("http://%s", server.Listener.Addr().String()), "martin@example.com", "")
		h := &History{
			Client: c,
			ID:     "test-history-key-1",
		}
		items, _, err := h.Items(ItemsOptions{})
		if err != nil {
			t.Fatalf("Expected items request to succeed, but didn't: %q", err.Error())
		}

		if len(items) < 1 {
			t.Fatalf("Expected items, but got none: %#v", items)
		}
	})
}

func TestHistoryItemsUsesRequestedCursor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("start-index"); got != "5" {
			t.Fatalf("start-index = %q, want 5", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []any{
				map[string]any{"task-1": map[string]any{"e": "Task6", "t": 0, "p": map[string]any{"tt": "one"}}},
			},
			"current-item-index": 10,
			"schema":             301,
		})
	}))
	defer server.Close()

	c := New(server.URL, "test@example.com", "password")
	h := &History{Client: c, ID: "history", LoadedServerIndex: 100}
	_, hasMore, err := h.Items(ItemsOptions{StartIndex: 5})
	if err != nil {
		t.Fatalf("Items failed: %v", err)
	}
	if got, want := h.LoadedServerIndex, 6; got != want {
		t.Fatalf("LoadedServerIndex = %d, want %d", got, want)
	}
	if !hasMore {
		t.Fatal("expected more items")
	}
}

func TestHistoryItemsRejectsRegressedServerCursor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":              []any{},
			"current-item-index": 4,
			"schema":             301,
		})
	}))
	defer server.Close()

	c := New(server.URL, "test@example.com", "password")
	h := &History{Client: c, ID: "history", LoadedServerIndex: 5, LatestServerIndex: 5}
	if _, _, err := h.Items(ItemsOptions{StartIndex: 5}); err == nil {
		t.Fatal("expected regressed cursor error")
	}
	if h.LoadedServerIndex != 5 || h.LatestServerIndex != 5 {
		t.Fatalf("history mutated after invalid response: loaded=%d latest=%d", h.LoadedServerIndex, h.LatestServerIndex)
	}
}

func TestHistoryItemsRejectsEmptyPageBeforeCurrentCursor(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items":              []any{},
			"current-item-index": 9,
			"schema":             301,
		})
	}))
	defer server.Close()

	c := New(server.URL, "test@example.com", "password")
	h := &History{Client: c, ID: "history", LoadedServerIndex: 5, LatestServerIndex: 9}
	if _, _, err := h.Items(ItemsOptions{StartIndex: 5}); err == nil {
		t.Fatal("expected no-progress error")
	}
	if h.LoadedServerIndex != 5 {
		t.Fatalf("cursor mutated to %d", h.LoadedServerIndex)
	}
}
