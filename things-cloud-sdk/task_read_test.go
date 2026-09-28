package thingscloud

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTaskReadPayloadNullsAndOmissions(t *testing.T) {
	date := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	alarm := 30
	task := Task{
		Title: "keep", Note: "clear", ScheduledDate: &date, DeadlineDate: &date,
		CompletionDate: &date, ModificationDate: &date, AlarmTimeOffset: &alarm,
		TodayIndexRefDate: &date, AreaIDs: []string{"area"}, ParentTaskIDs: []string{"project"},
		ActionGroupIDs: []string{"heading"}, TagIDs: []string{"tag"},
	}
	omitted, err := DecodeTaskReadPayload([]byte(`{"tt":"unrelated"}`))
	if err != nil {
		t.Fatal(err)
	}
	omitted.ApplyNulls(&task)
	if task.ScheduledDate == nil || task.TodayIndexRefDate == nil || task.Note != "clear" || len(task.AreaIDs) != 1 {
		t.Fatal("omitted fields changed existing state")
	}
	cleared, err := DecodeTaskReadPayload([]byte(`{"sr":null,"dd":null,"sp":null,"md":null,"ato":null,"ar":null,"pr":null,"agr":null,"tg":null,"tir":null,"nt":null,"rr":null}`))
	if err != nil {
		t.Fatal(err)
	}
	cleared.ApplyNulls(&task)
	if task.ScheduledDate != nil || task.DeadlineDate != nil || task.CompletionDate != nil || task.ModificationDate != nil || task.AlarmTimeOffset != nil || task.TodayIndexRefDate != nil {
		t.Error("explicit null did not clear optional date fields")
	}
	if len(task.AreaIDs)+len(task.ParentTaskIDs)+len(task.ActionGroupIDs)+len(task.TagIDs) != 0 || task.Note != "" || task.Title != "keep" {
		t.Error("explicit null did not clear relationships/notes or changed title")
	}
}

func TestTaskReadPayloadRejectsMalformedNotes(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", `{"nt":42}`, `{"nt":true}`, `{"nt":[]}`, `{"nt":{"t":3,"v":"private"}}`, `{"nt":{"t":2,"ps":"bad"}}`} {
		if _, err := DecodeTaskReadPayload([]byte(raw)); err == nil {
			t.Errorf("accepted invalid task payload %q", raw)
		}
	}
}

func TestTaskReadPayloadResolveNote(t *testing.T) {
	payload, err := DecodeTaskReadPayload([]byte(`{"nt":{"t":2,"ps":[{"p":0,"l":0,"r":"Hi "}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := payload.ResolveNote("there")
	if err != nil || got != "Hi there" {
		t.Fatalf("ResolveNote = %q, %v", got, err)
	}
}

func TestTaskReadKindsIncludeObservedLegacyGeneration(t *testing.T) {
	if err := ValidateTaskReadKinds([]Item{{Kind: ItemKindTask2}, {Kind: ItemKindTask7}}); err != nil {
		t.Fatal(err)
	}
	err := ValidateTaskReadKinds([]Item{{Kind: "Task8", ServerIndex: 42, HasServerIndex: true}})
	var unsupported *UnsupportedTaskKindError
	if !errors.As(err, &unsupported) || unsupported.Kind != "Task8" || unsupported.ServerIndex != 42 {
		t.Fatalf("expected indexed unsupported-task error, got %v", err)
	}
	if !strings.Contains(err.Error(), "Task8") {
		t.Fatalf("unexpected diagnostic: %v", err)
	}
}
