package main

import (
	"context"
	"testing"
	"time"
)

func TestSecrustHeartbeatIntegration(t *testing.T) {
	cfg, err := LoadAgentConfig()
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewSecrustClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := client.SendHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}

	t.Log("Secrust heartbeat request accepted")
}
func TestSecrustEventUploadIntegration(t *testing.T) {
	cfg, err := LoadAgentConfig()
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewSecrustClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	event := SecurityEvent{
		EventID:     4625,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Computer:    "PARAG-TEST",
		AccountName: "integration-test",
		EventType:   "failed_logon",
		RiskScore:   50,
		Severity:    "medium",
	}

	mapped, err := ToSecrustEvent(event)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Second,
	)
	defer cancel()

	if err := client.SendEvents(ctx, []SecrustEvent{mapped}); err != nil {
		t.Fatal(err)
	}

	t.Log("Secrust event upload accepted")
}
