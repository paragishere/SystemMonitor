package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type SecrustEvent struct {
	EventUID   string         `json:"event_uid"`
	EventID    int            `json:"event_id"`
	EventType  string         `json:"event_type"`
	Severity   string         `json:"severity"`
	RiskScore  int            `json:"risk_score"`
	OccurredAt string         `json:"occurred_at"`
	SourceIP   string         `json:"source_ip,omitempty"`
	Account    string         `json:"account,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type SecrustEventBatch struct {
	Events []SecrustEvent `json:"events"`
}

type SecrustClient struct {
	config AgentConfig
	http   *http.Client
}

func NewSecrustClient(cfg AgentConfig) (*SecrustClient, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("Secrust server URL is missing")
	}
	if cfg.AgentKey == "" || cfg.HostID == "" {
		return nil, errors.New("Secrust agent credentials are incomplete")
	}

	return &SecrustClient{
		config: cfg,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

func (c *SecrustClient) postJSON(
	ctx context.Context,
	path string,
	payload any,
) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.config.ServerURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", c.config.AgentKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Secrust request failed: %w", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf(
			"Secrust returned HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(responseBody)),
		)
	}

	return nil
}

func (c *SecrustClient) SendHeartbeat(ctx context.Context) error {
	return c.postJSON(ctx, "/api/endpoint/heartbeat", map[string]any{})
}

func (c *SecrustClient) SendEvents(
	ctx context.Context,
	events []SecrustEvent,
) error {
	if len(events) == 0 {
		return nil
	}
	if len(events) > 100 {
		return errors.New("event batch exceeds the 100-event API limit")
	}

	return c.postJSON(
		ctx,
		"/api/endpoint/events",
		SecrustEventBatch{Events: events},
	)
}

func ToSecrustEvent(event SecurityEvent) (SecrustEvent, error) {
	occurredAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(event.Timestamp))
	if err != nil {
		return SecrustEvent{}, fmt.Errorf("invalid event timestamp for event %d", event.EventID)
	}

	sourceIP := strings.TrimSpace(event.SourceIP)
	if sourceIP == "-" {
		sourceIP = ""
	}
	if sourceIP != "" && net.ParseIP(sourceIP) == nil {
		sourceIP = ""
	}

	details := map[string]any{
		"computer":   event.Computer,
		"logon_type": event.LogonType,
		"process":    event.ProcessName,
	}

	// Stable fingerprint prevents repeated collection of the same event
	// from creating a new event UID on every upload.
	fingerprint := fmt.Sprintf(
		"%s|%d|%s|%s|%s|%s|%s",
		event.Computer,
		event.EventID,
		occurredAt.UTC().Format(time.RFC3339Nano),
		event.AccountName,
		event.ProcessName,
		sourceIP,
		event.LogonType,
	)
	sum := sha256.Sum256([]byte(fingerprint))

	severity := strings.ToLower(strings.TrimSpace(event.Severity))
	switch severity {
	case "low", "medium", "high", "critical":
	default:
		return SecrustEvent{}, fmt.Errorf("unsupported severity for event %d", event.EventID)
	}

	return SecrustEvent{
		EventUID:   hex.EncodeToString(sum[:]),
		EventID:    event.EventID,
		EventType:  event.EventType,
		Severity:   severity,
		RiskScore:  event.RiskScore,
		OccurredAt: occurredAt.UTC().Format(time.RFC3339Nano),
		SourceIP:   sourceIP,
		Account:    event.AccountName,
		Details:    details,
	}, nil
}
