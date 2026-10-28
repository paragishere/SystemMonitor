package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type AgentConfig struct {
	ServerURL                string `json:"server_url"`
	AgentKey                 string `json:"agent_key"`
	HostID                   string `json:"host_id"`
	HeartbeatIntervalSeconds int    `json:"heartbeat_interval_seconds"`
}

func configPath() string {
	return filepath.Join(DataDirectory, "config.json")
}

func LoadAgentConfig() (AgentConfig, error) {
	path := configPath()

	data, err := os.ReadFile(path)
	if err != nil {
		return AgentConfig{}, fmt.Errorf("read agent config: %w", err)
	}

	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return AgentConfig{}, fmt.Errorf("parse agent config: %w", err)
	}

	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	cfg.AgentKey = strings.TrimSpace(cfg.AgentKey)
	cfg.HostID = strings.TrimSpace(cfg.HostID)

	if cfg.ServerURL == "" {
		return AgentConfig{}, errors.New("server_url is required")
	}

	parsedURL, err := url.ParseRequestURI(cfg.ServerURL)
	if err != nil || parsedURL.Host == "" ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return AgentConfig{}, errors.New("server_url must be a valid HTTP or HTTPS URL")
	}

	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return AgentConfig{}, errors.New("server_url must not contain credentials, query parameters, or fragments")
	}

	if cfg.HeartbeatIntervalSeconds == 0 {
		cfg.HeartbeatIntervalSeconds = 60
	}

	if cfg.HeartbeatIntervalSeconds < 15 ||
		cfg.HeartbeatIntervalSeconds > 3600 {
		return AgentConfig{}, errors.New("heartbeat interval must be between 15 and 3600 seconds")
	}

	// An empty key/host ID is allowed during initial setup.
	// Network operations must reject incomplete credentials.
	return cfg, nil
}

func (cfg AgentConfig) HeartbeatInterval() time.Duration {
	return time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
}
