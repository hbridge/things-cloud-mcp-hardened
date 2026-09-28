package thingscloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TaskReplayVersion identifies the task read semantics used to build derived
// state. Cached state from older generations must be replayed from scratch.
const TaskReplayVersion = 3

// UnsupportedTaskKindError means the task state would be incomplete if replay
// continued. ServerIndex is -1 when the source did not provide an index.
type UnsupportedTaskKindError struct {
	Kind        ItemKind
	ServerIndex int
}

func (e *UnsupportedTaskKindError) Error() string {
	kind := taskKindDiagnostic(e.Kind)
	if e.ServerIndex >= 0 {
		return fmt.Sprintf("incomplete sync: unsupported task kind %s at server index %d", kind, e.ServerIndex)
	}
	return fmt.Sprintf("incomplete sync: unsupported task kind %s", kind)
}

func taskKindDiagnostic(value ItemKind) string {
	kind := string(value)
	suffix := strings.TrimPrefix(kind, "Task")
	if suffix == kind || suffix == "" || len(suffix) > 12 || strings.Trim(suffix, "0123456789") != "" {
		return "Task*"
	}
	return kind
}

// ValidateTaskReadKinds preflights an entire batch before any task state is
// mutated. It includes the legacy Task2 generation observed in old histories.
func ValidateTaskReadKinds(items []Item) error {
	for _, item := range items {
		switch item.Kind {
		case ItemKindTask7, ItemKindTask, ItemKindTask4, ItemKindTask3, ItemKindTask2, ItemKindTaskPlain:
			continue
		}
		if strings.HasPrefix(string(item.Kind), "Task") {
			index := -1
			if item.HasServerIndex {
				index = item.ServerIndex
			}
			return &UnsupportedTaskKindError{Kind: item.Kind, ServerIndex: index}
		}
	}
	return nil
}

// TaskReadPayload adds explicit-null tracking to the existing wire payload
// without changing its write representation.
type TaskReadPayload struct {
	TaskActionItemPayload
	nullFields map[string]bool
}

// DecodeTaskReadPayload distinguishes an omitted property from an explicit
// null and validates all supported note encodings.
func DecodeTaskReadPayload(raw json.RawMessage) (TaskReadPayload, error) {
	var result TaskReadPayload
	data := bytes.TrimSpace(raw)
	if len(data) == 0 || data[0] != '{' {
		return result, fmt.Errorf("task payload must be a JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return result, fmt.Errorf("decoding task payload: %w", err)
	}
	if err := json.Unmarshal(data, &result.TaskActionItemPayload); err != nil {
		return result, fmt.Errorf("decoding task payload: %w", err)
	}
	if note, ok := fields["nt"]; ok {
		if err := validateTaskReadNote(note); err != nil {
			return result, err
		}
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			if result.nullFields == nil {
				result.nullFields = make(map[string]bool)
			}
			result.nullFields[key] = true
		}
	}
	return result, nil
}

func validateTaskReadNote(raw json.RawMessage) error {
	value := bytes.TrimSpace(raw)
	if bytes.Equal(value, []byte("null")) || (len(value) > 0 && value[0] == '"') {
		return nil
	}
	if len(value) == 0 || value[0] != '{' {
		return fmt.Errorf("task note must be text, null, or a supported structured note")
	}
	var note Note
	if err := json.Unmarshal(value, &note); err != nil {
		return fmt.Errorf("decoding task note: %w", err)
	}
	if note.Type != NoteTypeFullText && note.Type != NoteTypeDelta {
		return fmt.Errorf("unsupported task note type %d", note.Type)
	}
	return nil
}

// ResolveNote applies the note field to current using the read protocol's
// plain-text, full-text, delta, and explicit-null semantics.
func (p TaskReadPayload) ResolveNote(current string) (string, error) {
	if p.nullFields["nt"] {
		return "", nil
	}
	if len(p.Note) == 0 {
		return current, nil
	}

	var noteText string
	if err := json.Unmarshal(p.Note, &noteText); err == nil {
		return noteText, nil
	}

	var note Note
	if err := json.Unmarshal(p.Note, &note); err != nil {
		return "", fmt.Errorf("decoding task note: %w", err)
	}
	switch note.Type {
	case NoteTypeFullText:
		return note.Value, nil
	case NoteTypeDelta:
		result, err := ApplyPatchesChecked(current, note.Patches)
		if err != nil {
			return "", fmt.Errorf("applying task note delta: %w", err)
		}
		return result, nil
	default:
		return "", fmt.Errorf("unsupported task note type %d", note.Type)
	}
}

// ApplyNulls clears fields explicitly set to null while preserving omitted
// fields. The fork also tracks tir and rr, which are not in upstream's Task.
func (p TaskReadPayload) ApplyNulls(task *Task) {
	for key := range p.nullFields {
		switch key {
		case "cd":
			task.CreationDate = time.Time{}
		case "md":
			task.ModificationDate = nil
		case "sr":
			task.ScheduledDate = nil
		case "sp":
			task.CompletionDate = nil
		case "dd":
			task.DeadlineDate = nil
		case "ato":
			task.AlarmTimeOffset = nil
		case "ar":
			task.AreaIDs = nil
		case "pr":
			task.ParentTaskIDs = nil
		case "agr":
			task.ActionGroupIDs = nil
		case "tg":
			task.TagIDs = nil
		case "rt":
			task.RecurrenceIDs = nil
		case "dl":
			task.DelegateIDs = nil
		case "tir":
			task.TodayIndexRefDate = nil
		case "nt":
			task.Note = ""
		case "rr":
			task.Repeater = nil
		}
	}
}
