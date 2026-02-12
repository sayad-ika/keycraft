package main

import (
	"strings"
	"testing"
	"time"
)

func TestGeneratePasswordIncludesRequiredClasses(t *testing.T) {
	pw, err := generatePassword(24, true, false)
	if err != nil {
		t.Fatalf("generatePassword returned error: %v", err)
	}
	if len(pw) != 24 {
		t.Fatalf("expected length 24, got %d", len(pw))
	}

	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	if !hasLower || !hasUpper || !hasDigit || !hasSymbol {
		t.Fatalf("password missing required classes: lower=%v upper=%v digit=%v symbol=%v", hasLower, hasUpper, hasDigit, hasSymbol)
	}
}

func TestGeneratePasswordNoSymbolsNoAmbiguous(t *testing.T) {
	pw, err := generatePassword(32, false, true)
	if err != nil {
		t.Fatalf("generatePassword returned error: %v", err)
	}
	if len(pw) != 32 {
		t.Fatalf("expected length 32, got %d", len(pw))
	}

	disallowed := "O0Il1!@#$%^&*()-_=+[]{}:;,.?|"
	for _, r := range pw {
		if strings.ContainsRune(disallowed, r) {
			t.Fatalf("password contains disallowed character %q in %q", r, pw)
		}
	}
}

func TestAuditEntriesDetectsIssues(t *testing.T) {
	now := time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC)

	entries := []entry{
		{
			ID:        "id1",
			Service:   "GitHub",
			Username:  "alice",
			Password:  "abc",
			UpdatedAt: "2023-01-01T00:00:00Z",
			CreatedAt: "2023-01-01T00:00:00Z",
		},
		{
			ID:        "id2",
			Service:   "Gmail",
			Username:  "alice",
			Password:  "abc",
			UpdatedAt: "2026-01-01T00:00:00Z",
			CreatedAt: "2026-01-01T00:00:00Z",
		},
		{
			ID:        "id3",
			Service:   "GitHub",
			Username:  "alice",
			Password:  "AnotherStrong123!",
			UpdatedAt: "2026-01-10T00:00:00Z",
			CreatedAt: "2026-01-10T00:00:00Z",
		},
		{
			ID:        "id4",
			Service:   "Bank",
			Username:  "bob",
			Password:  "",
			UpdatedAt: "2026-02-01T00:00:00Z",
			CreatedAt: "2026-02-01T00:00:00Z",
		},
		{
			ID:        "id5",
			Service:   "Forum",
			Username:  "carol",
			Password:  "StrongPass123!",
			UpdatedAt: "invalid-time",
			CreatedAt: "invalid-time",
		},
	}

	issues := auditEntries(entries, 12, 365, now)
	if len(issues) != 8 {
		t.Fatalf("expected 8 issues, got %d", len(issues))
	}

	assertHasIssue(t, issues, "weak_password", "id1")
	assertHasIssue(t, issues, "weak_password", "id2")
	assertHasIssue(t, issues, "reused_password", "id1")
	assertHasIssue(t, issues, "reused_password", "id2")
	assertHasIssue(t, issues, "stale_password", "id1")
	assertHasIssue(t, issues, "duplicate_account", "id3")
	assertHasIssue(t, issues, "missing_password", "id4")
	assertHasIssue(t, issues, "invalid_timestamp", "id5")
}

func TestParseTagsDeduplicatesCaseInsensitive(t *testing.T) {
	got := parseTags("work, Work,banking,banking, personal ")
	if len(got) != 3 {
		t.Fatalf("expected 3 unique tags, got %d (%v)", len(got), got)
	}
	if got[0] != "work" || got[1] != "banking" || got[2] != "personal" {
		t.Fatalf("unexpected tag normalization order: %v", got)
	}
}

func assertHasIssue(t *testing.T, issues []auditIssue, kind, entryID string) {
	t.Helper()
	for _, issue := range issues {
		if issue.Kind == kind && issue.EntryID == entryID {
			return
		}
	}
	t.Fatalf("expected issue kind=%s id=%s not found", kind, entryID)
}
