package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	thingscloud "github.com/arthursoares/things-cloud-sdk"
	memory "github.com/arthursoares/things-cloud-sdk/state/memory"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestCachedUserDoesNotAcceptDifferentPassword(t *testing.T) {
	um := NewUserManager()
	cached := &ThingsMCP{credential: credentialDigest("person@example.com", "correct-password")}
	um.users["person@example.com"] = cached
	um.newUser = func(_, _ string, _ *url.URL) (*ThingsMCP, error) {
		return nil, fmt.Errorf("invalid credentials")
	}

	got, err := um.GetOrCreateUser("person@example.com", "definitely-wrong")
	if err == nil || got != nil {
		t.Fatalf("mismatched credential reused cached account: got=%p err=%v", got, err)
	}
}

func TestJSONResultProvidesStructuredContent(t *testing.T) {
	result := jsonResult(map[string]string{"status": "ok"})
	if result.StructuredContent == nil {
		t.Fatal("structuredContent is missing")
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", resultText(t, result))
	}
}

func TestEveryToolDeclaresOutputSchema(t *testing.T) {
	tools := defineTools(NewUserManager())
	if got, want := len(tools), 23; got != want {
		t.Fatalf("registered tool count = %d, want %d", got, want)
	}
	for _, serverTool := range tools {
		if serverTool.Tool.OutputSchema.Type == "" && len(serverTool.Tool.RawOutputSchema) == 0 {
			t.Errorf("tool %s has no output schema", serverTool.Tool.Name)
		}
		var schema map[string]any
		if err := json.Unmarshal(serverTool.Tool.RawOutputSchema, &schema); err != nil {
			t.Errorf("tool %s has invalid output schema: %v", serverTool.Tool.Name, err)
		}
		encoded, err := json.Marshal(serverTool.Tool)
		if err != nil {
			t.Errorf("marshal tool %s: %v", serverTool.Tool.Name, err)
			continue
		}
		var listed map[string]any
		if err := json.Unmarshal(encoded, &listed); err != nil || listed["outputSchema"] == nil {
			t.Errorf("listed tool %s omitted outputSchema: err=%v", serverTool.Tool.Name, err)
		}
	}
}

func TestCallsAreSerializedPerUser(t *testing.T) {
	tmcp := &ThingsMCP{state: memory.NewState(), lastSyncAt: time.Now()}
	var active int32
	var peak int32
	handler := func(_ *ThingsMCP, _ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		current := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if current <= old || atomic.CompareAndSwapInt32(&peak, old, current) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return jsonResult(map[string]bool{"ok": true}), nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := tmcp.callSerialized(context.Background(), makeReq(map[string]any{}), handler)
			if err != nil || result.IsError {
				t.Errorf("serialized call failed: result=%v err=%v", result, err)
			}
		}()
	}
	wg.Wait()
	if peak != 1 {
		t.Fatalf("peak concurrent handlers = %d, want 1", peak)
	}
}

func TestIncrementalSyncDoesNotAdvanceCursorOnLaterPageFailure(t *testing.T) {
	var mu sync.Mutex
	var starts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := r.URL.Query().Get("start-index")
		mu.Lock()
		starts = append(starts, start)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch start {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []any{map[string]any{"new-task": map[string]any{
					"e": "Task6", "t": 0, "p": map[string]any{"tt": "not partially applied"},
				}}},
				"current-item-index": 3,
				"schema":             301,
			})
		case "2":
			http.Error(w, "temporary failure", http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected full-rebuild request at start-index %s", start)
		}
	}))
	defer server.Close()

	client := thingscloud.New(server.URL, "test@example.com", "password", thingscloud.WithRequestInterval(0))
	tmcp := &ThingsMCP{
		client:  client,
		history: &thingscloud.History{Client: client, ID: "history", LoadedServerIndex: 1, LatestServerIndex: 3, LatestSchemaVersion: 301},
		state:   memory.NewState(),
	}
	if _, err := tmcp.incrementalSync(); err == nil {
		t.Fatal("expected incremental sync failure")
	}
	if tmcp.history.LoadedServerIndex != 1 {
		t.Fatalf("live cursor advanced to %d", tmcp.history.LoadedServerIndex)
	}
	if len(tmcp.state.Tasks) != 0 {
		t.Fatalf("partial delta was applied: %#v", tmcp.state.Tasks)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, start := range starts {
		if start == "0" {
			t.Fatal("incremental failure triggered a full rebuild")
		}
	}
}

func TestFullRebuildIgnoresSettings5Metadata(t *testing.T) {
	fc := newFakeCloud("test@example.com",
		thingscloud.Item{UUID: "settings-5", Kind: thingscloud.ItemKind("Settings5"), Action: thingscloud.ItemActionModified, P: json.RawMessage(`{"example":true}`)},
		makeTaskItem("task-1", withTitle("Visible after settings metadata")),
	)
	defer fc.Close()

	tmcp := newTestThingsMCP(t, fc)
	if task := tmcp.state.Tasks["task-1"]; task == nil || task.Title != "Visible after settings metadata" {
		t.Fatalf("task graph was not rebuilt after Settings5: %#v", task)
	}
}

func TestFullRebuildAcceptsLegacyTombstone(t *testing.T) {
	legacyTaskUUID := "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	currentTaskUUID := thingscloud.EncodeLegacyIdentifier(legacyTaskUUID)
	fc := newFakeCloud("test@example.com",
		thingscloud.Item{
			UUID:   legacyTaskUUID,
			Kind:   thingscloud.ItemKindTask3,
			Action: thingscloud.ItemActionCreated,
			P:      json.RawMessage(`{"tt":"Deleted task"}`),
		},
		thingscloud.Item{
			UUID:   "TOMBSTONE-E3F02B25-273A-4520-92C5-19AB2E53F0B6-20191229",
			Kind:   thingscloud.ItemKindTombstonePlain,
			Action: thingscloud.ItemActionCreated,
			P:      json.RawMessage(`{"dloid":"` + legacyTaskUUID + `","dld":1577577600}`),
		},
	)
	defer fc.Close()

	tmcp := newTestThingsMCP(t, fc)
	if task := tmcp.state.Tasks[currentTaskUUID]; task != nil {
		t.Fatalf("legacy Tombstone did not delete task during rebuild: %#v", task)
	}
}

func TestUncertainCommitIsReconciledWithoutRetryingWrite(t *testing.T) {
	var mu sync.Mutex
	var committed map[string]json.RawMessage
	var postCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			postCount++
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode commit: %v", err)
			}
			mu.Lock()
			committed = body
			mu.Unlock()
			_, _ = w.Write([]byte(`{"server-head-index":`))
			return
		}

		mu.Lock()
		body := committed
		mu.Unlock()
		if body == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []any{}, "current-item-index": 0, "schema": 301,
			})
			return
		}
		wireItems := make([]map[string]json.RawMessage, 0, len(body))
		for id, raw := range body {
			wireItems = append(wireItems, map[string]json.RawMessage{id: raw})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": wireItems, "current-item-index": 1, "schema": 301,
		})
	}))
	defer server.Close()

	client := thingscloud.New(server.URL, "test@example.com", "password", thingscloud.WithRequestInterval(0))
	tmcp := &ThingsMCP{
		client:  client,
		history: &thingscloud.History{Client: client, ID: "history", LatestSchemaVersion: 301},
		state:   memory.NewState(),
	}
	envelope := writeEnvelope{id: "task-1", action: 0, kind: "Task6", payload: map[string]any{"tt": "reconciled"}}
	if err := tmcp.writeAndSync(envelope); err != nil {
		t.Fatalf("reconciled write failed: %v", err)
	}
	if postCount != 1 {
		t.Fatalf("commit was retried %d times", postCount)
	}
	if task := tmcp.state.Tasks["task-1"]; task == nil || task.Title != "reconciled" {
		t.Fatalf("reconciled task missing: %#v", task)
	}
	if tmcp.history.LoadedServerIndex != 1 {
		t.Fatalf("loaded cursor = %d, want 1", tmcp.history.LoadedServerIndex)
	}
}

func TestChecklistMutationRejectsMissingItem(t *testing.T) {
	fc := newFakeCloud("test@example.com")
	defer fc.Close()
	tmcp := newTestThingsMCP(t, fc)

	result, err := tmcp.handleEditChecklistItem(context.Background(), makeReq(map[string]any{
		"uuid":  "missing-checklist-item",
		"title": "must not become a ghost",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	assertIsError(t, result)
	if got := len(fc.getCommitLog()); got != 0 {
		t.Fatalf("unexpected backend commits: %d", got)
	}
}

func TestCreateTagRejectsMissingParent(t *testing.T) {
	fc := newFakeCloud("test@example.com")
	defer fc.Close()
	tmcp := newTestThingsMCP(t, fc)

	result, err := tmcp.handleCreateTag(context.Background(), makeReq(map[string]any{
		"name":        "child",
		"parent_uuid": "missing-parent",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	assertIsError(t, result)
	if got := len(fc.getCommitLog()); got != 0 {
		t.Fatalf("unexpected backend commits: %d", got)
	}
}

func TestPermanentDeleteRequiresExplicitConfirmation(t *testing.T) {
	state := memory.NewState()
	if err := state.Update(makeAreaItem("area-1", "Work"), makeTagItem("tag-1", "Tag"), makeChecklistItem("cl-1", "task-1", "Step")); err != nil {
		t.Fatalf("build state: %v", err)
	}
	tmcp := newTestThingsMCPDirect(state)

	tests := []struct {
		name string
		call func() (*mcp.CallToolResult, error)
	}{
		{"area", func() (*mcp.CallToolResult, error) {
			return tmcp.handleDeleteArea(context.Background(), makeReq(map[string]any{"uuid": "area-1"}))
		}},
		{"tag", func() (*mcp.CallToolResult, error) {
			return tmcp.handleDeleteTag(context.Background(), makeReq(map[string]any{"uuid": "tag-1"}))
		}},
		{"checklist", func() (*mcp.CallToolResult, error) {
			return tmcp.handleDeleteChecklistItem(context.Background(), makeReq(map[string]any{"uuid": "cl-1"}))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.call()
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}
			assertIsError(t, result)
		})
	}
}

func TestGenerateUUIDUsesThingsAlphabet(t *testing.T) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := generateUUID()
		if id == "" {
			t.Fatal("empty UUID")
		}
		for _, r := range id {
			if !containsRune(alphabet, r) {
				t.Fatalf("UUID %q contains invalid rune %q", id, r)
			}
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate UUID: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestSplitRecurringPayloadCreatesTemplateAndInstance(t *testing.T) {
	payload := newTaskCreatePayload("daily", map[string]string{
		"schedule":   "today",
		"recurrence": "daily",
	}, -100)
	templateUUID, template, instance, err := splitRecurringPayload(payload)
	if err != nil {
		t.Fatalf("split failed: %v", err)
	}
	if templateUUID == "" || template.Rr == nil || template.Icsd == nil {
		t.Fatalf("invalid template: uuid=%q rr=%v icsd=%v", templateUUID, template.Rr, template.Icsd)
	}
	if len(template.Rt) != 0 || template.St != 1 || template.Sb != 0 {
		t.Fatalf("invalid template relationship/schedule: rt=%v st=%d sb=%d", template.Rt, template.St, template.Sb)
	}
	if instance.Rr != nil || instance.Icsd != nil || len(instance.Rt) != 1 || instance.Rt[0] != templateUUID {
		t.Fatalf("invalid instance: rr=%v icsd=%v rt=%v", instance.Rr, instance.Icsd, instance.Rt)
	}
	if template.Tir == nil || instance.Tir == nil || *template.Tir <= *instance.Tir {
		t.Fatalf("template occurrence was not advanced: template=%v instance=%v", template.Tir, instance.Tir)
	}
}

func TestCreateRecurringTaskCommitsTemplateAndVisibleInstance(t *testing.T) {
	fc := newFakeCloud("test@example.com")
	defer fc.Close()
	tmcp := newTestThingsMCP(t, fc)

	result, err := tmcp.handleCreateTask(context.Background(), makeReq(map[string]any{
		"title":      "daily",
		"schedule":   "today",
		"recurrence": "daily",
	}))
	if err != nil {
		t.Fatalf("handler error: %v", err)
	}
	assertNotError(t, result)
	commits := fc.getCommitLog()
	if len(commits) != 1 {
		t.Fatalf("commit count = %d, want 1", len(commits))
	}
	var body map[string]struct {
		Kind    string         `json:"e"`
		Action  int            `json:"t"`
		Payload map[string]any `json:"p"`
	}
	if err := json.Unmarshal(commits[0], &body); err != nil {
		t.Fatalf("decode commit: %v", err)
	}
	if len(body) != 2 {
		t.Fatalf("commit entity count = %d, want template+instance", len(body))
	}
	var templates, instances int
	for _, item := range body {
		if item.Payload["rr"] != nil {
			templates++
		}
		if rt, ok := item.Payload["rt"].([]any); ok && len(rt) == 1 && item.Payload["rr"] == nil {
			instances++
		}
	}
	if templates != 1 || instances != 1 {
		t.Fatalf("templates=%d instances=%d body=%s", templates, instances, commits[0])
	}

	listed, err := tmcp.handleFindTasks(context.Background(), makeReq(map[string]any{}))
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	tasks := resultJSON[[]TaskOutput](t, listed)
	if len(tasks) != 1 || !tasks[0].IsRecurring {
		t.Fatalf("visible recurring instances = %#v", tasks)
	}
}

func TestAllReadToolHandlersRemainOperational(t *testing.T) {
	initial := []thingscloud.Item{
		makeAreaItem("area-1", "Work"),
		makeTagItem("tag-1", "Tag"),
		makeTaskItem("project-1", withTitle("Project"), withTaskType(thingscloud.TaskTypeProject), withArea("area-1")),
		makeTaskItem("heading-1", withTitle("Heading"), withTaskType(thingscloud.TaskTypeHeading), withParent("project-1")),
		makeTaskItem("task-1", withTitle("Task"), withParent("project-1")),
		makeChecklistItem("checklist-1", "task-1", "Step"),
	}
	fc := newFakeCloud("test@example.com", initial...)
	defer fc.Close()
	tmcp := newTestThingsMCP(t, fc)

	reads := []struct {
		name string
		call func() (*mcp.CallToolResult, error)
	}{
		{"things_find_tasks", func() (*mcp.CallToolResult, error) {
			return tmcp.handleFindTasks(context.Background(), makeReq(map[string]any{}))
		}},
		{"things_show_task", func() (*mcp.CallToolResult, error) {
			return tmcp.handleShowTask(context.Background(), makeReq(map[string]any{"uuid": "task-1"}))
		}},
		{"things_show_project", func() (*mcp.CallToolResult, error) {
			return tmcp.handleShowProject(context.Background(), makeReq(map[string]any{"uuid": "project-1"}))
		}},
		{"things_find_projects", func() (*mcp.CallToolResult, error) {
			return tmcp.handleFindProjects(context.Background(), makeReq(map[string]any{}))
		}},
		{"things_find_headings", func() (*mcp.CallToolResult, error) {
			return tmcp.handleFindHeadings(context.Background(), makeReq(map[string]any{"project_uuid": "project-1"}))
		}},
		{"things_find_areas", func() (*mcp.CallToolResult, error) {
			return tmcp.handleFindAreas(context.Background(), makeReq(map[string]any{}))
		}},
		{"things_find_tags", func() (*mcp.CallToolResult, error) {
			return tmcp.handleFindTags(context.Background(), makeReq(map[string]any{}))
		}},
		{"things_overview", func() (*mcp.CallToolResult, error) {
			return tmcp.handleOverview(context.Background(), makeReq(map[string]any{}))
		}},
		{"things_debug_raw", func() (*mcp.CallToolResult, error) {
			return tmcp.handleDebugRaw(context.Background(), makeReq(map[string]any{"uuid": "task-1"}))
		}},
	}

	for _, read := range reads {
		t.Run(read.name, func(t *testing.T) {
			result, err := read.call()
			if err != nil {
				t.Fatalf("handler error: %v", err)
			}
			assertNotError(t, result)
			if result.StructuredContent == nil {
				t.Fatal("structuredContent is missing")
			}
		})
	}
}

func TestAllWriteToolHandlersRemainOperational(t *testing.T) {
	initial := []thingscloud.Item{
		makeAreaItem("area-1", "Work"),
		makeTagItem("tag-1", "Tag"),
		makeTaskItem("project-1", withTitle("Project"), withTaskType(thingscloud.TaskTypeProject), withArea("area-1")),
		makeTaskItem("heading-1", withTitle("Heading"), withTaskType(thingscloud.TaskTypeHeading), withParent("project-1")),
		makeTaskItem("task-1", withTitle("Task"), withParent("project-1")),
		makeChecklistItem("checklist-1", "task-1", "Step"),
	}
	fc := newFakeCloud("test@example.com", initial...)
	defer fc.Close()
	tmcp := newTestThingsMCP(t, fc)

	call := func(name string, fn func() (*mcp.CallToolResult, error)) map[string]string {
		t.Helper()
		result, err := fn()
		if err != nil {
			t.Fatalf("%s handler error: %v", name, err)
		}
		assertNotError(t, result)
		return resultJSON[map[string]string](t, result)
	}

	call("create task", func() (*mcp.CallToolResult, error) {
		return tmcp.handleCreateTask(context.Background(), makeReq(map[string]any{"title": "New Task", "project_uuid": "project-1"}))
	})
	call("create project", func() (*mcp.CallToolResult, error) {
		return tmcp.handleCreateProject(context.Background(), makeReq(map[string]any{"title": "New Project", "area_uuid": "area-1"}))
	})
	call("create heading", func() (*mcp.CallToolResult, error) {
		return tmcp.handleCreateHeading(context.Background(), makeReq(map[string]any{"title": "New Heading", "project_uuid": "project-1"}))
	})
	createdArea := call("create area", func() (*mcp.CallToolResult, error) {
		return tmcp.handleCreateArea(context.Background(), makeReq(map[string]any{"name": "Temporary Area"}))
	})
	createdTag := call("create tag", func() (*mcp.CallToolResult, error) {
		return tmcp.handleCreateTag(context.Background(), makeReq(map[string]any{"name": "Child", "parent_uuid": "tag-1"}))
	})
	call("edit area", func() (*mcp.CallToolResult, error) {
		return tmcp.handleEditArea(context.Background(), makeReq(map[string]any{"uuid": "area-1", "name": "Work Renamed"}))
	})
	call("edit tag", func() (*mcp.CallToolResult, error) {
		return tmcp.handleEditTag(context.Background(), makeReq(map[string]any{"uuid": "tag-1", "name": "Tag Renamed"}))
	})
	call("edit item", func() (*mcp.CallToolResult, error) {
		return tmcp.handleEditTask(context.Background(), makeReq(map[string]any{"uuid": "task-1", "title": "Task Renamed"}))
	})
	createdChecklist := call("add checklist", func() (*mcp.CallToolResult, error) {
		return tmcp.handleAddChecklistItem(context.Background(), makeReq(map[string]any{"task_uuid": "task-1", "title": "New Step"}))
	})
	call("edit checklist", func() (*mcp.CallToolResult, error) {
		return tmcp.handleEditChecklistItem(context.Background(), makeReq(map[string]any{"uuid": createdChecklist["uuid"], "completed": true}))
	})
	call("delete checklist", func() (*mcp.CallToolResult, error) {
		return tmcp.handleDeleteChecklistItem(context.Background(), makeReq(map[string]any{"uuid": createdChecklist["uuid"], "confirm": true}))
	})
	call("delete area", func() (*mcp.CallToolResult, error) {
		return tmcp.handleDeleteArea(context.Background(), makeReq(map[string]any{"uuid": createdArea["uuid"], "confirm": true}))
	})
	call("delete tag", func() (*mcp.CallToolResult, error) {
		return tmcp.handleDeleteTag(context.Background(), makeReq(map[string]any{"uuid": createdTag["uuid"], "confirm": true}))
	})

	if got, want := len(fc.getCommitLog()), 13; got != want {
		t.Fatalf("backend commit count = %d, want %d", got, want)
	}
	if tmcp.state.Tasks["task-1"].Title != "Task Renamed" {
		t.Fatalf("task edit not applied: %#v", tmcp.state.Tasks["task-1"])
	}
	if _, ok := tmcp.state.Areas[createdArea["uuid"]]; ok {
		t.Fatal("deleted area remains in local state")
	}
	if _, ok := tmcp.state.Tags[createdTag["uuid"]]; ok {
		t.Fatal("deleted tag remains in local state")
	}
}

func TestDiagnoseUsesAuthoritativeHistoryAndFixedPagination(t *testing.T) {
	fc := newFakeCloud("test@example.com", makeTaskItem("task-1", withTitle("Visible")))
	defer fc.Close()
	tmcp := newTestThingsMCP(t, fc)

	report := tmcp.handleDiagnose(fc.email, "testpass")
	if report.Summary.Failed != 0 || len(report.Steps) != 7 {
		t.Fatalf("diagnosis failed: summary=%+v errors=%v", report.Summary, report.Errors)
	}
	fetch := report.Steps[3]
	details, ok := fetch.Details.(map[string]any)
	if !ok {
		t.Fatalf("unexpected fetch details: %#v", fetch.Details)
	}
	if got, ok := details["totalItemsFetched"].(int); !ok || got != 1 {
		t.Fatalf("totalItemsFetched = %#v, want 1", details["totalItemsFetched"])
	}
	resolve := report.Steps[1]
	resolveDetails := resolve.Details.(map[string]any)
	if same, _ := resolveDetails["selectedIsSameAsOwn"].(bool); !same {
		t.Fatalf("diagnostic selected non-authoritative history: %#v", resolveDetails)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal diagnostic report: %v", err)
	}
	for _, secret := range []string{fc.historyID, "Visible", "historyKey", "ownHistoryKey", "selectedHistory"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("diagnostic report leaked %q: %s", secret, encoded)
		}
	}
}

func containsRune(s string, want rune) bool {
	for _, got := range s {
		if got == want {
			return true
		}
	}
	return false
}
