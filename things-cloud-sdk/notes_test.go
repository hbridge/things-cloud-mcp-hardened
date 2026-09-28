package thingscloud

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNote_FullText(t *testing.T) {
	raw := `{"_t":"tx","t":1,"ch":0,"v":"Hello world"}`
	var n Note
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatal(err)
	}
	if n.Type != NoteTypeFullText {
		t.Errorf("expected type %d, got %d", NoteTypeFullText, n.Type)
	}
	if n.Value != "Hello world" {
		t.Errorf("expected 'Hello world', got '%s'", n.Value)
	}
}

func TestNote_Delta(t *testing.T) {
	raw := `{"_t":"tx","t":2,"ps":[{"r":"inserted text","p":0,"l":0,"ch":12345}]}`
	var n Note
	if err := json.Unmarshal([]byte(raw), &n); err != nil {
		t.Fatal(err)
	}
	if n.Type != NoteTypeDelta {
		t.Errorf("expected type %d, got %d", NoteTypeDelta, n.Type)
	}
	if len(n.Patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(n.Patches))
	}
	if n.Patches[0].Replacement != "inserted text" {
		t.Errorf("unexpected replacement: %s", n.Patches[0].Replacement)
	}
}

func TestNote_ApplyPatch(t *testing.T) {
	original := "Hello world"
	patch := NotePatch{Position: 5, Length: 6, Replacement: " Go"}
	result := ApplyPatches(original, []NotePatch{patch})
	if result != "Hello Go" {
		t.Errorf("expected 'Hello Go', got '%s'", result)
	}
}

func TestNote_ApplyPatch_UsesUTF8ByteOffsets(t *testing.T) {
	original := "Native Task7 note α 🚀\nSecond line."
	patch := NotePatch{Position: 26, Length: 5, Replacement: "Update"}
	if got := ApplyPatches(original, []NotePatch{patch}); got != "Native Task7 note α 🚀\nUpdated line." {
		t.Fatalf("byte-offset patch = %q", got)
	}
}

func TestNote_ApplyPatch_PositionBeyondLength(t *testing.T) {
	// Patch position is beyond the string — should not panic
	result := ApplyPatches("", []NotePatch{{Position: 10, Length: 0, Replacement: "hello"}})
	if result != "hello" {
		t.Errorf("expected 'hello', got '%s'", result)
	}
}

func TestNote_ApplyPatch_LengthBeyondEnd(t *testing.T) {
	result := ApplyPatches("AB", []NotePatch{{Position: 1, Length: 100, Replacement: "X"}})
	if result != "AX" {
		t.Errorf("expected 'AX', got '%s'", result)
	}
}

func TestNote_ApplyMultiplePatches(t *testing.T) {
	original := "ABCDEF"
	patches := []NotePatch{
		{Position: 0, Length: 1, Replacement: "X"},
	}
	result := ApplyPatches(original, patches)
	if result != "XBCDEF" {
		t.Errorf("expected 'XBCDEF', got '%s'", result)
	}
}

func TestApplyPatchesCheckedRejectsInvalidUTF8(t *testing.T) {
	_, err := ApplyPatchesChecked("α", []NotePatch{{Position: 1, Length: 1}})
	if err == nil || !strings.Contains(err.Error(), "patch 0") {
		t.Fatalf("invalid UTF-8 patch error = %v", err)
	}
}

func TestApplyPatchesCheckedRejectsInvalidIntermediateResult(t *testing.T) {
	patches := []NotePatch{
		{Position: 1, Length: 1},
		{Position: 0, Length: 1},
	}
	if got := ApplyPatches("α", patches); got != "" || !utf8.ValidString(got) {
		t.Fatalf("test setup produced %q", got)
	}
	if _, err := ApplyPatchesChecked("α", patches); err == nil {
		t.Fatal("accepted invalid intermediate UTF-8")
	}
}
