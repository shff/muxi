package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type HostConfig struct {
	Host       string `json:"host"`
	TargetPort string `json:"target_port"`
}

type Config struct {
	Hosts []HostConfig `json:"hosts"`
}

func LoadConfig(dir string) (*Config, error) {
	configPath := filepath.Join(dir, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return &Config{Hosts: []HostConfig{}}, nil
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	for i, host := range config.Hosts {
		if host.Host == "" {
			return nil, fmt.Errorf("'host' field is required for hosts[%d]", i)
		}
		if host.TargetPort == "" {
			return nil, fmt.Errorf("'target_port' field is required for hosts[%d]", i)
		}
	}

	return &config, nil
}

func AddHost(dir, host, port string) error {
	configPath := filepath.Join(dir, "config.json")

	// Ensure directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Load existing config
	config, err := LoadConfig(dir)
	if err != nil {
		config = &Config{Hosts: []HostConfig{}}
	}

	if port == "" {
		return fmt.Errorf("port must be specified when adding a host")
	}

	// If host already exists, update its port
	found := false
	for i, h := range config.Hosts {
		if h.Host == host {
			config.Hosts[i].TargetPort = port
			found = true
			break
		}
	}

	// Add new host configuration
	if !found {
		config.Hosts = append(config.Hosts, HostConfig{
			Host:       host,
			TargetPort: port,
		})
	}

	// Add new host to /etc/hosts
	if err := addHostToEtcHosts(host); err != nil {
		fmt.Println("Failed to add host to /etc/hosts. Entry will be added by daemon.")
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func RemoveHost(dir, host string) error {
	configPath := filepath.Join(dir, "config.json")

	// Load existing config
	config, err := LoadConfig(dir)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Filter out the host to be removed
	newHosts := []HostConfig{}
	for _, h := range config.Hosts {
		if h.Host != host {
			newHosts = append(newHosts, h)
		}
	}
	config.Hosts = newHosts

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func UpdateEtcHosts() error {
	// Load config
	config, err := LoadConfig(filepath.Join(os.Getenv("HOME"), ".muxi"))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Read /etc/hosts file
	hostsPath := "/etc/hosts"
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read /etc/hosts: %w", err)
	}

	// Collect missing hosts
	missingHosts := []string{}
	for _, hostConfig := range config.Hosts {
		if !containsHostEntry(string(data), hostConfig.Host) {
			missingHosts = append(missingHosts, hostConfig.Host)
		}
	}

	if len(missingHosts) == 0 {
		return nil
	}

	// Add all missing hosts at once
	content := ""
	for _, host := range missingHosts {
		content += fmt.Sprintf("127.0.0.1 %s\n", host)
	}

	// Run using osascript to get admin privileges
	cmd := fmt.Sprintf("echo %s | sudo tee -a %s", strconv.Quote(content), strconv.Quote(hostsPath))
	apple := fmt.Sprintf("do shell script %s with administrator privileges", strconv.Quote(cmd))
	_, err = exec.Command("osascript", "-e", apple).CombinedOutput()
	return err
}

func addHostToEtcHosts(host string) error {
	hostsPath := "/etc/hosts"

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to read /etc/hosts: %w", err)
	}

	entry := fmt.Sprintf("127.0.0.1 %s\n", host)
	if containsHostEntry(string(data), host) {
		return nil // Entry already exists
	}

	// Ensure we're running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("We need root privileges to modify /etc/hosts. The daemon will ask for your password on startup.")
	}

	data = append(data, []byte(entry)...)
	if err := os.WriteFile(hostsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write /etc/hosts: %w", err)
	}

	fmt.Printf("Added host %s to /etc/hosts\n", host)

	return nil
}

func containsHostEntry(lines, host string) bool {
	for line := range strings.SplitSeq(lines, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if slices.Contains(fields[1:], host) {
			return true
		}
	}
	return false
}
