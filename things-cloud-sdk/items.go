package thingscloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// Item is an event in thingscloud. Every action inside things generates an Item.
// Common items are the creation of a task, area or checklist, as well as modifying attributes
// or marking things as done.
type Item struct {
	UUID           string          `json:"-"`
	P              json.RawMessage `json:"p"`
	Kind           ItemKind        `json:"e"`
	Action         ItemAction      `json:"t"`
	ServerIndex    int             `json:"-"`
	HasServerIndex bool            `json:"-"`
}

// IsSettingsItem reports whether an event is account settings metadata rather
// than a task-graph entity. Most settings events use a versioned Settings kind,
// but Things Cloud also emits marker records keyed by the stable "Settings" ID
// with a non-entity kind such as "-".
func IsSettingsItem(item Item) bool {
	return item.UUID == "Settings" || IsSettingsKind(item.Kind)
}

// IsMetadataItem reports whether an event is known account/application
// metadata that does not contribute an entity to the task graph.
func IsMetadataItem(item Item) bool {
	if IsSettingsItem(item) {
		return true
	}
	switch item.Kind {
	case ItemKindCommand, ItemKindCommand3, ItemKindContact2:
		return true
	default:
		return false
	}
}

type itemsResponse struct {
	Items                  []map[string]Item `json:"items"`
	LatestTotalContentSize int               `json:"latest-total-content-size"`
	StartTotalContentSize  int               `json:"start-total-content-size"`
	EndTotalContentSize    int               `json:"end-total-content-size"`
	SchemaVersion          int               `json:"schema"`
	LatestSchemaVersion    int               `json:"latest-schema-version"`
	CurrentItemIndex       int               `json:"current-item-index"`
}

func (r itemsResponse) schemaVersion() int {
	if r.SchemaVersion != 0 {
		return r.SchemaVersion
	}
	return r.LatestSchemaVersion
}

// ItemsOptions allows a client to pickup changes from a specific index
type ItemsOptions struct {
	StartIndex int
}

// Items fetches changes from thingscloud. Every change contains multiple items which have been modified.
// The Items method unwraps these objects and returns a list instead.
//
// Note that if a item was changed multiple times it will be present multiple times in the result too.
func (h *History) Items(opts ItemsOptions) ([]Item, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if opts.StartIndex < 0 {
		return nil, false, fmt.Errorf("start index must be non-negative")
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("/version/1/history/%s/items", h.ID), nil)
	if err != nil {
		return nil, false, err
	}

	values := req.URL.Query()
	values.Set("start-index", strconv.Itoa(opts.StartIndex))
	req.URL.RawQuery = values.Encode()

	resp, err := h.Client.do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, newAPIError(resp)
	}

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	var v itemsResponse
	if err := json.Unmarshal(bs, &v); err != nil {
		return nil, false, err
	}
	schemaVersion := v.schemaVersion()
	if schemaVersion > SupportedSchemaVersion {
		return nil, false, fmt.Errorf("unsupported Things Cloud schema %d (maximum supported %d)", schemaVersion, SupportedSchemaVersion)
	}
	if v.CurrentItemIndex < opts.StartIndex {
		return nil, false, fmt.Errorf("server cursor regressed from requested index %d to %d", opts.StartIndex, v.CurrentItemIndex)
	}
	nextLoadedIndex := opts.StartIndex + len(v.Items)
	if len(v.Items) == 0 && opts.StartIndex < v.CurrentItemIndex {
		return nil, false, fmt.Errorf("server returned no progress at index %d while current index is %d", opts.StartIndex, v.CurrentItemIndex)
	}
	if schemaVersion == SupportedSchemaVersion && nextLoadedIndex > v.CurrentItemIndex {
		return nil, false, fmt.Errorf("server page ends at index %d beyond current index %d", nextLoadedIndex, v.CurrentItemIndex)
	}
	var items = []Item{}
	for offset, m := range v.Items {
		serverIndex := opts.StartIndex + offset
		for id, item := range m {
			item.UUID = id
			item.ServerIndex = serverIndex
			item.HasServerIndex = true
			items = append(items, item)
		}
	}
	h.LoadedServerIndex = nextLoadedIndex
	h.LatestServerIndex = v.CurrentItemIndex
	h.LatestSchemaVersion = schemaVersion
	h.EndTotalContentSize = v.EndTotalContentSize
	h.LatestTotalContentSize = v.LatestTotalContentSize
	hasMoreItems := len(v.Items) > 0 && h.LoadedServerIndex < h.LatestServerIndex
	return items, hasMoreItems, nil
}
