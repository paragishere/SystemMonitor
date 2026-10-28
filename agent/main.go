package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	AgentVersion       = "0.1.0"
	HostID             = "windows-agent"
	CollectionInterval = 30 * time.Second
	DataDirectory      = `C:\ProgramData\SystemMonitor`
)

func initLogger() {
	logFilePath := filepath.Join(DataDirectory, "agent.log")

	if err := os.MkdirAll(DataDirectory, 0755); err != nil {
		log.Println("[!] Failed to create data directory:", err)
		return
	}

	file, err := os.OpenFile(
		logFilePath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)

	if err != nil {
		log.Println("[!] Failed to open log file:", err)
		return
	}

	log.SetOutput(file)
	log.SetFlags(log.Ldate | log.Ltime)
}

type SecurityEvent struct {
	EventID int `json:"event_id"`
	// RecordID    string `json:"record_id"`
	Timestamp   string `json:"timestamp"`
	Computer    string `json:"computer"`
	AccountName string `json:"account"`
	EventType   string `json:"event_type"`
	LogonType   string `json:"logon_type,omitempty"`
	ProcessName string `json:"process,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	RiskScore   int    `json:"risk_score"`
	Severity    string `json:"severity"`
}

type Alert struct {
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	HostID      string `json:"host_id"`
	AlertType   string `json:"alert_type"`
	Severity    string `json:"severity"`
	RiskScore   int    `json:"risk_score"`
	Description string `json:"description"`
	SourceIP    string `json:"source_ip,omitempty"`
	Account     string `json:"account,omitempty"`
}

type AgentState struct {
	AgentID            string `json:"agent_id"`
	Hostname           string `json:"hostname"`
	OS                 string `json:"os"`
	Version            string `json:"version"`
	Status             string `json:"status"`
	LastHeartbeat      string `json:"last_heartbeat"`
	LastEventTimestamp string `json:"last_event_timestamp"`
}

func parseEventType(eventID int) string {
	switch eventID {
	case 4624:
		return "successful_logon"
	case 4625:
		return "failed_logon"
	case 4672:
		return "special_privilege"
	default:
		return "unknown"
	}
}

func deduplicateEvents(events []SecurityEvent) []SecurityEvent {
	seen := make(map[string]struct{})
	unique := make([]SecurityEvent, 0, len(events))

	for _, event := range events {
		key := fmt.Sprintf(
			"%d|%s|%s|%s|%s|%s|%s",
			event.EventID,
			event.Timestamp,
			event.Computer,
			event.AccountName,
			event.ProcessName,
			event.SourceIP,
			event.LogonType,
		)

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		unique = append(unique, event)
	}

	return unique
}

func getValue(line, prefix string) string {
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

func parseEvents(output string) []SecurityEvent {
	var events []SecurityEvent

	blocks := strings.Split(output, "Event[")

	for _, block := range blocks[1:] {
		event := SecurityEvent{}

		lines := strings.Split(block, "\n")

		inSubject := false
		inNewLogon := false

		for _, rawLine := range lines {
			line := strings.TrimSpace(rawLine)

			if strings.HasPrefix(line, "Event ID:") {
				value := getValue(line, "Event ID:")

				id, err := strconv.Atoi(value)
				if err == nil {
					event.EventID = id
					event.EventType = parseEventType(id)
				}
			}
			// if strings.HasPrefix(line, "Record ID:") {
			// 	event.RecordID = getValue(line, "Record ID:")
			// }

			if strings.HasPrefix(line, "Date:") {
				event.Timestamp = getValue(line, "Date:")
			}

			if strings.HasPrefix(line, "Computer:") {
				event.Computer = getValue(line, "Computer:")
			}

			if line == "Subject:" {
				inSubject = true
				inNewLogon = false
				continue
			}

			if line == "New Logon:" {
				inNewLogon = true
				inSubject = false
				continue
			}

			if line == "Logon Information:" ||
				line == "Process Information:" ||
				line == "Network Information:" ||
				line == "Failure Information:" {

				inSubject = false
				inNewLogon = false
				continue
			}

			if strings.HasPrefix(line, "Account Name:") {
				value := getValue(line, "Account Name:")

				if event.EventID == 4624 && inNewLogon {
					event.AccountName = value
				}

				if (event.EventID == 4625 ||
					event.EventID == 4672) && inSubject {

					event.AccountName = value
				}
			}

			if strings.HasPrefix(line, "Logon Type:") {
				event.LogonType = getValue(line, "Logon Type:")
			}

			if strings.HasPrefix(line, "Process Name:") {
				event.ProcessName = getValue(line, "Process Name:")
			}

			if strings.HasPrefix(line, "Source Network Address:") {
				event.SourceIP = getValue(
					line,
					"Source Network Address:",
				)
			}
		}

		if event.EventID != 0 {
			events = append(events, event)
		}
	}

	return events
}

func calculateRisk(event SecurityEvent) int {
	switch event.EventID {
	case 4625:
		return 5

	case 4624:
		return 0

	case 4672:
		return 40

	default:
		return 0
	}
}

func severityFromRisk(score int) string {
	switch {
	case score >= 80:
		return "critical"

	case score >= 60:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}

func enrichEvents(events []SecurityEvent) {
	for i := range events {
		events[i].RiskScore = calculateRisk(events[i])
		events[i].Severity = severityFromRisk(
			events[i].RiskScore,
		)
	}
}

func saveJSON(filename string, data interface{}) error {
	content, err := json.MarshalIndent(
		data,
		"",
		"  ",
	)

	if err != nil {
		return err
	}

	if err := os.MkdirAll(DataDirectory, 0755); err != nil {
		return err
	}

	filePath := filepath.Join(DataDirectory, filename)

	return os.WriteFile(
		filePath,
		content,
		0644,
	)
}
func parseEventTime(value string) time.Time {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, value)

		if err == nil {
			return t
		}
	}

	return time.Time{}
}

func detectBruteForce(events []SecurityEvent) []Alert {
	var alerts []Alert

	for _, current := range events {

		if current.EventID != 4625 {
			continue
		}

		currentTime := parseEventTime(
			current.Timestamp,
		)

		if currentTime.IsZero() {
			continue
		}

		count := 0

		for _, event := range events {

			if event.EventID != 4625 {
				continue
			}

			if current.SourceIP == "" ||
				current.SourceIP == "-" {

				continue
			}

			if event.SourceIP != current.SourceIP {
				continue
			}

			eventTime := parseEventTime(
				event.Timestamp,
			)

			if eventTime.IsZero() {
				continue
			}

			diff := currentTime.Sub(eventTime)

			if diff >= 0 &&
				diff <= 5*time.Minute {

				count++
			}
		}
		// this is the logic for brute force detection, if the count of failed login attempts from the same source IP within 5 minutes is greater than or equal to 3, an alert is generated
		if count >= 10 {

			alert := Alert{
				ID: fmt.Sprintf(
					"BF-%d",
					time.Now().UnixNano(),
				),

				Timestamp: time.Now().Format(
					time.RFC3339,
				),

				HostID: HostID,

				AlertType: "brute_force_login",

				Severity: "high",

				RiskScore: 60,

				Description: fmt.Sprintf(
					"%d failed login attempts detected from the same source IP within 5 minutes",
					count,
				),

				SourceIP: current.SourceIP,

				Account: current.AccountName,
			}

			duplicate := false

			for _, existing := range alerts {

				if existing.SourceIP ==
					alert.SourceIP {

					duplicate = true
					break
				}
			}

			if !duplicate {
				alerts = append(
					alerts,
					alert,
				)
			}
		}
	}

	return alerts
}

func detectSuccessfulAfterBruteForce(
	events []SecurityEvent,
) []Alert {

	var alerts []Alert

	for _, success := range events {

		if success.EventID != 4624 {
			continue
		}

		successTime := parseEventTime(
			success.Timestamp,
		)

		if successTime.IsZero() {
			continue
		}

		failedCount := 0

		for _, failed := range events {

			if failed.EventID != 4625 {
				continue
			}

			failedTime := parseEventTime(
				failed.Timestamp,
			)

			if failedTime.IsZero() {
				continue
			}

			diff := successTime.Sub(
				failedTime,
			)

			if diff >= 0 &&
				diff <= 5*time.Minute {

				failedCount++
			}
		}

		if failedCount >= 10 {

			alerts = append(
				alerts,
				Alert{
					ID: fmt.Sprintf(
						"AUTH-%d",
						time.Now().UnixNano(),
					),

					Timestamp: time.Now().Format(
						time.RFC3339,
					),

					HostID: HostID,

					AlertType: "successful_login_after_bruteforce",

					Severity: "critical",

					RiskScore: 90,

					Description: fmt.Sprintf(
						"Successful login detected after %d failed login attempts within 5 minutes",
						failedCount,
					),

					SourceIP: success.SourceIP,

					Account: success.AccountName,
				},
			)
		}
	}

	return alerts
}

func saveAgentState() error {

	hostname, err := os.Hostname()

	if err != nil {
		hostname = "unknown"
	}

	state := AgentState{
		AgentID: HostID,

		Hostname: hostname,

		OS: "windows",

		Version: AgentVersion,

		Status: "online",

		LastHeartbeat: time.Now().Format(
			time.RFC3339,
		),
	}

	return saveJSON(
		"agent_state.json",
		state,
	)
}

func runAgentCycle() error {

	fmt.Println()
	fmt.Println("[*] Updating agent state...")

	err := saveAgentState()

	if err != nil {
		fmt.Println(
			"[!] Agent state error:",
			err,
		)
	} else {
		fmt.Println(
			"[+] Agent state updated",
		)
	}

	fmt.Println()
	fmt.Println(
		"[*] Collecting Windows Security Events...",
	)

	cmd := exec.Command(
		"wevtutil",
		"qe",
		"Security",
		`/q:*[System[(EventID=4624 or EventID=4625 or EventID=4672)]]`,
		"/c:100",
		"/rd:true",
		"/f:text",
	)

	output, err := cmd.CombinedOutput()

	if err != nil {

		fmt.Println(
			"[!] Collection failed",
		)

		fmt.Println(
			string(output),
		)

		return err
	}

	fmt.Println(
		"[+] Raw events collected",
	)

	events := parseEvents(string(output))

	if len(events) == 0 {
		fmt.Println("[*] No new events found.")
		return nil
	}

	lastTimestamp := ""

	statePath := filepath.Join(
		DataDirectory,
		"agent_state.json",
	)

	stateData, err := os.ReadFile(statePath)

	if err == nil {
		var state AgentState

		if json.Unmarshal(stateData, &state) == nil {
			lastTimestamp = state.LastEventTimestamp
		}
	}

	if lastTimestamp != "" {
		fmt.Println("[*] Last processed event:", lastTimestamp)

		filteredEvents := make([]SecurityEvent, 0)

		for _, event := range events {

			if event.Timestamp > lastTimestamp {
				filteredEvents = append(
					filteredEvents,
					event,
				)
			}
		}

		events = filteredEvents
	}

	fmt.Println(
		"[+] New events after timestamp filter:",
		len(events),
	)

	if len(events) == 0 {
		fmt.Println("[*] No new events found.")
		return nil
	}

	fmt.Printf(
		"[+] Parsed events: %d\n",
		len(events),
	)

	events = deduplicateEvents(events)

	fmt.Printf(
		"[+] Unique events: %d\n",
		len(events),
	)

	enrichEvents(events)

	err = saveJSON(
		"events.json",
		events,
	)

	if err != nil {

		fmt.Println(
			"[!] Failed to save events:",
			err,
		)

		return err
	}

	fmt.Println(
		"[+] Events saved to events.json",
	)

	fmt.Println()

	for i, event := range events {

		fmt.Println(
			"--------------------------------",
		)

		fmt.Printf(
			"Event #%d\n",
			i+1,
		)

		fmt.Println(
			"--------------------------------",
		)

		fmt.Println(
			"Event ID     :",
			event.EventID,
		)

		fmt.Println(
			"Event Type   :",
			event.EventType,
		)

		fmt.Println(
			"Timestamp    :",
			event.Timestamp,
		)

		fmt.Println(
			"Computer     :",
			event.Computer,
		)

		fmt.Println(
			"Account      :",
			event.AccountName,
		)

		fmt.Println(
			"Logon Type   :",
			event.LogonType,
		)

		fmt.Println(
			"Process      :",
			event.ProcessName,
		)

		fmt.Println(
			"Source IP    :",
			event.SourceIP,
		)

		fmt.Println(
			"Risk Score   :",
			event.RiskScore,
		)

		fmt.Println(
			"Severity     :",
			event.Severity,
		)
	}

	fmt.Println()
	fmt.Println(
		"[*] Running detection engine...",
	)

	var alerts []Alert

	bruteForceAlerts :=
		detectBruteForce(events)

	alerts = append(
		alerts,
		bruteForceAlerts...,
	)

	successAlerts :=
		detectSuccessfulAfterBruteForce(
			events,
		)

	alerts = append(
		alerts,
		successAlerts...,
	)

	if len(alerts) == 0 {

		fmt.Println(
			"[+] No security alerts detected",
		)

	} else {

		fmt.Printf(
			"[!] Alerts detected: %d\n",
			len(alerts),
		)

		for _, alert := range alerts {

			fmt.Println()
			fmt.Println(
				"================================",
			)

			fmt.Println(
				"SECURITY ALERT",
			)

			fmt.Println(
				"================================",
			)

			fmt.Println(
				"Alert ID    :",
				alert.ID,
			)

			fmt.Println(
				"Type        :",
				alert.AlertType,
			)

			fmt.Println(
				"Severity    :",
				alert.Severity,
			)

			fmt.Println(
				"Risk Score  :",
				alert.RiskScore,
			)

			fmt.Println(
				"Description :",
				alert.Description,
			)

			fmt.Println(
				"Source IP   :",
				alert.SourceIP,
			)

			fmt.Println(
				"Account     :",
				alert.Account,
			)
		}
	}

	err = saveJSON(
		"alerts.json",
		alerts,
	)

	if err != nil {

		fmt.Println(
			"[!] Failed to save alerts:",
			err,
		)

		return err
	}

	if len(events) > 0 {
		latestTimestamp := events[0].Timestamp

		for _, event := range events {
			if event.Timestamp > latestTimestamp {
				latestTimestamp = event.Timestamp
			}
		}
		// Upload collected events before advancing the local checkpoint.
		cfg, configErr := LoadAgentConfig()
		if configErr != nil {
			fmt.Println("[!] Secrust sync config unavailable:", configErr)
			return configErr
		}

		client, clientErr := NewSecrustClient(cfg)
		if clientErr != nil {
			fmt.Println("[!] Secrust client unavailable:", clientErr)
			return clientErr
		}

		batch := make([]SecrustEvent, 0, len(events))
		for _, event := range events {
			mapped, mapErr := ToSecrustEvent(event)
			if mapErr != nil {
				fmt.Println("[!] Event mapping failed:", mapErr)
				return mapErr
			}
			batch = append(batch, mapped)
		}

		ctx, cancel := context.WithTimeout(
			context.Background(),
			20*time.Second,
		)
		syncErr := client.SendEvents(ctx, batch)
		cancel()

		if syncErr != nil {
			fmt.Println("[!] Secrust event upload failed:", syncErr)
			return syncErr
		}

		fmt.Printf("[+] Uploaded %d event(s) to Secrust\n", len(batch))
		updateAgentLastEventTimestamp(latestTimestamp)
	}

	fmt.Println(
		"[+] Alerts saved to alerts.json",
	)

	fmt.Println()
	fmt.Println(
		"================================",
	)

	fmt.Println(
		"      COLLECTION COMPLETE",
	)

	fmt.Println(
		"================================",
	)

	return nil
}
func updateAgentLastEventTimestamp(timestamp string) {
	statePath := filepath.Join(
		DataDirectory,
		"agent_state.json",
	)

	data, err := os.ReadFile(statePath)
	if err != nil {
		return
	}

	var state AgentState

	if err := json.Unmarshal(data, &state); err != nil {
		return
	}

	state.LastEventTimestamp = timestamp

	updatedData, err := json.MarshalIndent(
		state,
		"",
		"  ",
	)
	if err != nil {
		return
	}

	_ = os.WriteFile(
		statePath,
		updatedData,
		0644,
	)
}

func main() {
	initLogger()

	if len(os.Args) > 1 {
		switch os.Args[1] {

		case "install":
			err := installService()
			if err != nil {
				fmt.Println("[!] Install failed:", err)
				os.Exit(1)
			}
			fmt.Println("[+] Windows Service installed successfully.")
			return

		case "uninstall":
			err := uninstallService()
			if err != nil {
				fmt.Println("[!] Uninstall failed:", err)
				os.Exit(1)
			}
			fmt.Println("[+] Windows Service uninstalled successfully.")
			return

		case "start":
			err := startService()
			if err != nil {
				fmt.Println("[!] Start failed:", err)
				os.Exit(1)
			}
			fmt.Println("[+] Windows Service started.")
			return

		case "stop":
			err := stopService()
			if err != nil {
				fmt.Println("[!] Stop failed:", err)
				os.Exit(1)
			}
			fmt.Println("[+] Windows Service stopped.")
			return

		case "service":
			err := runService()
			if err != nil {
				fmt.Println("[!] Service error:", err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Println("================================")
	fmt.Println("      SYSTEM MONITOR AGENT")
	fmt.Println("================================")
	fmt.Println("[+] Version:", AgentVersion)
	fmt.Println("[+] Host ID:", HostID)
	fmt.Println("[+] Collection interval:", CollectionInterval)
	fmt.Println()

	for {
		fmt.Println("================================")
		fmt.Println("     STARTING AGENT CYCLE")
		fmt.Println("================================")

		err := runAgentCycle()
		if err != nil {
			fmt.Println("[!] Agent cycle error:", err)
		}

		fmt.Println()
		fmt.Println("[*] Next collection in", CollectionInterval)
		time.Sleep(CollectionInterval)
	}
}
