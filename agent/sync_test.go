package main

import "testing"

func TestToSecrustEvent(t *testing.T) {
	input := SecurityEvent{
		EventID:     4625,
		Timestamp:   "2026-10-29T01:47:35.4760000Z",
		Computer:    "PARAG",
		AccountName: "test-user",
		EventType:   "failed_logon",
		SourceIP:    "-",
		RiskScore:   50,
		Severity:    "medium",
	}

	got, err := ToSecrustEvent(input)
	if err != nil {
		t.Fatal(err)
	}

	if got.EventUID == "" {
		t.Fatal("event UID must not be empty")
	}
	if got.EventID != input.EventID {
		t.Fatalf("event ID mismatch: got %d", got.EventID)
	}
	if got.SourceIP != "" {
		t.Fatalf("expected invalid placeholder IP to be omitted, got %q", got.SourceIP)
	}
	if got.OccurredAt != "2026-10-29T01:47:35.476Z" {
		t.Fatalf("unexpected normalized timestamp: %s", got.OccurredAt)
	}

	second, err := ToSecrustEvent(input)
	if err != nil {
		t.Fatal(err)
	}
	if got.EventUID != second.EventUID {
		t.Fatal("event UID should be stable for identical events")
	}
}

func TestToSecrustEventRejectsInvalidTimestamp(t *testing.T) {
	_, err := ToSecrustEvent(SecurityEvent{
		EventID:   4624,
		Timestamp: "not-a-timestamp",
		Severity:  "low",
	})
	if err == nil {
		t.Fatal("expected invalid timestamp to be rejected")
	}
}
