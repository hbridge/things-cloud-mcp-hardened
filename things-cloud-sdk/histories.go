package thingscloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

const SupportedSchemaVersion = 301

// History represents a synchronization stream. It's identified with a uuid v4
type History struct {
	mu                     sync.Mutex
	ID                     string
	Client                 *Client
	LatestServerIndex      int
	LoadedServerIndex      int
	LatestSchemaVersion    int
	EndTotalContentSize    int
	LatestTotalContentSize int
}

type historyResponse struct {
	LatestSchemaVersion    int  `json:"latest-schema-version"`
	LatestTotalContentSize int  `json:"latest-total-content-size"`
	IsEmpty                bool `json:"is-empty"`
	LatestServerIndex      int  `json:"latest-server-index"`
}

// Sync ensures the history object is able to write to things
func (h *History) Sync() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	req, err := http.NewRequest("GET", fmt.Sprintf("/version/1/history/%s/items", h.ID), nil)
	if err != nil {
		return err
	}
	query := req.URL.Query()
	query.Add("start-index", strconv.Itoa(h.LatestServerIndex))
	req.URL.RawQuery = query.Encode()
	resp, err := h.Client.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newAPIError(resp)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var v itemsResponse
	if err := json.Unmarshal(bs, &v); err != nil {
		return fmt.Errorf("decode history sync response: %w", err)
	}
	schemaVersion := v.schemaVersion()
	if schemaVersion > SupportedSchemaVersion {
		return fmt.Errorf("unsupported Things Cloud schema %d (maximum supported %d)", schemaVersion, SupportedSchemaVersion)
	}
	h.LatestServerIndex = v.CurrentItemIndex
	h.LatestSchemaVersion = schemaVersion
	h.LatestTotalContentSize = v.LatestTotalContentSize
	return nil
}

// History requests a specific history
func (c *Client) History(id string) (*History, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/version/1/history/%s", id), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnauthorized
		}
		return nil, newAPIError(resp)
	}
	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	h := historyResponse{}
	if err := json.Unmarshal(bs, &h); err != nil {
		return nil, err
	}

	return &History{
		Client:                 c,
		ID:                     id,
		LatestServerIndex:      h.LatestServerIndex,
		LatestSchemaVersion:    h.LatestSchemaVersion,
		LatestTotalContentSize: h.LatestTotalContentSize,
	}, nil
}

type v1historyResponse struct {
	Key                 string `json:"history-key"`
	LatestServerIndex   int    `json:"latest-server-index"`
	IsEmpty             bool   `json:"is-empty"`
	LatestSchemaVersion int    `json:"latest-schema-version"`
}

// OwnHistory returns the clients own history
func (c *Client) OwnHistory() (*History, error) {
	resp, err := c.Verify()
	if err != nil {
		return nil, err
	}

	return &History{
		Client: c,
		ID:     resp.HistoryKey,
	}, nil
}

// HistoryWithID creates a History object with the given ID without making a network call.
// Use this when you already know the history ID (e.g., from a previous sync).
func (c *Client) HistoryWithID(id string) *History {
	return &History{
		Client: c,
		ID:     id,
	}
}

// Histories requests all known history keys
func (c *Client) Histories() ([]*History, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("/version/1/account/%s/own-history-keys", c.EMail), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnauthorized
		}
		return nil, newAPIError(resp)
	}
	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var keys []string
	if err := json.Unmarshal(bs, &keys); err != nil {
		return nil, fmt.Errorf("decode history keys: %w", err)
	}

	var histories = make([]*History, len(keys))
	for i, key := range keys {
		histories[i] = &History{
			Client: c,
			ID:     key,
		}
	}
	return histories, nil
}

type createHistoryResponse struct {
	Key string `json:"new-history-key"`
}

// CreateHistory requests a new history key
func (c *Client) CreateHistory() (*History, error) {
	req, err := http.NewRequest("POST", fmt.Sprintf("/version/1/account/%s/own-history-keys", c.EMail), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnauthorized
		}
		return nil, newAPIError(resp)

	}
	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var v createHistoryResponse
	if err := json.Unmarshal(bs, &v); err != nil {
		return nil, fmt.Errorf("decode create-history response: %w", err)
	}
	return &History{
		Client: c,
		ID:     v.Key,
	}, nil
}

// Delete destroys a history
// Note that thingscloud will always return 202, even if the key is unknown
func (h *History) Delete() error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("/version/1/account/%s/own-history-keys/%s", h.Client.EMail, h.ID), nil)
	if err != nil {
		return err
	}
	resp, err := h.Client.do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return newAPIError(resp)
	}
	return nil
}

type commitResponse struct {
	ServerHeadIndex int `json:"server-head-index"`
}

// CommitUncertainError means the request may have reached Things Cloud, but the
// client could not prove whether the commit was accepted. Callers must reconcile
// by reading history before deciding whether a retry is safe.
type CommitUncertainError struct {
	Err error
}

func (e *CommitUncertainError) Error() string {
	return fmt.Sprintf("commit outcome is uncertain: %v", e.Err)
}

func (e *CommitUncertainError) Unwrap() error { return e.Err }

// Identifiable abstracts different thingscloud write requests. As we need to provide a map
// indexed by UUID, all we care about is the ID of the change, not the change itself
type Identifiable interface {
	UUID() string
}

func (h *History) Write(items ...Identifiable) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(items) == 0 {
		return fmt.Errorf("commit contains no items")
	}
	if h.LatestSchemaVersion > SupportedSchemaVersion {
		return fmt.Errorf("refusing write for unsupported Things Cloud schema %d (maximum supported %d)", h.LatestSchemaVersion, SupportedSchemaVersion)
	}

	m := map[string]interface{}{}
	for _, item := range items {
		if item == nil {
			return fmt.Errorf("commit contains a nil item")
		}
		if item.UUID() == "" {
			return fmt.Errorf("commit contains an item with an empty UUID")
		}
		if _, exists := m[item.UUID()]; exists {
			return fmt.Errorf("commit contains duplicate UUID %q", item.UUID())
		}
		m[item.UUID()] = item
	}
	bs, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("/version/1/history/%s/commit", h.ID), bytes.NewReader(bs))
	if err != nil {
		return err
	}
	req.Header.Add("Schema", "301")
	req.Header.Add("Push-Priority", "5")
	// Full App-Instance-Id matching Things format: {hash}-{bundleId}-{hash}
	req.Header.Add("App-Instance-Id", "000000000000000000000000000000000000000000000000000000000000000-com.culturedcode.ThingsMac-000000000000000000000000000000000000000000000000000000000000000")
	req.Header.Add("App-Id", "com.culturedcode.ThingsMac")
	req.Header.Add("Content-Encoding", "UTF-8")
	req.Header.Add("Host", "cloud.culturedcode.com")
	req.Header.Add("Accept", "application/json")
	query := req.URL.Query()
	query.Add("ancestor-index", strconv.Itoa(h.LatestServerIndex))
	query.Add("_cnt", "1")
	req.URL.RawQuery = query.Encode()
	resp, err := h.Client.do(req)
	if err != nil {
		return &CommitUncertainError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return newAPIError(resp)
	}
	rs, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var w commitResponse
	if err := json.Unmarshal(rs, &w); err != nil {
		return &CommitUncertainError{Err: fmt.Errorf("decode commit response: %w", err)}
	}
	if w.ServerHeadIndex != h.LatestServerIndex+1 {
		return &CommitUncertainError{Err: fmt.Errorf("unexpected server head index %d after ancestor %d", w.ServerHeadIndex, h.LatestServerIndex)}
	}
	h.LatestServerIndex = w.ServerHeadIndex
	return nil
}
