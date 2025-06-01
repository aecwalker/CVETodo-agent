package main

import (
	"fmt"
	"os"

	"github.com/aecwalker/CVETodo-agent/internal/agent"
	"github.com/aecwalker/CVETodo-agent/internal/config"
	"github.com/aecwalker/CVETodo-agent/internal/logger"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "cvetodo-agent",
	Short: "CVETodo Agent - System vulnerability scanner",
	Long: `CVETodo Agent scans your system for installed software packages
and checks them against known CVE vulnerabilities using the CVETodo API.`,
	Version: fmt.Sprintf("%s (%s) built on %s", version, commit, date),
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the CVETodo agent",
	Long:  "Start the CVETodo agent to continuously monitor system for vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if config file exists before attempting to load
		if !config.ConfigExists() {
			fmt.Fprintf(os.Stderr, "Configuration file not found at: %s\n", config.GetConfigPath())
			fmt.Fprintf(os.Stderr, "Please run 'cvetodo-agent config init' to set up your configuration.\n")
			return fmt.Errorf("configuration required")
		}

		// Load configuration
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Initialize logger
		log := logger.New(cfg.LogLevel, cfg.LogFormat)

		// Create and start agent
		agentInstance := agent.New(cfg, log)
		return agentInstance.Run()
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a one-time system scan",
	Long:  "Perform a one-time scan of the system and report vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if config file exists before attempting to load
		if !config.ConfigExists() {
			fmt.Fprintf(os.Stderr, "Configuration file not found at: %s\n", config.GetConfigPath())
			fmt.Fprintf(os.Stderr, "Please run 'cvetodo-agent config init' to set up your configuration.\n")
			return fmt.Errorf("configuration required")
		}

		// Load configuration
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Initialize logger
		log := logger.New(cfg.LogLevel, cfg.LogFormat)

		// Create and run scan
		agentInstance := agent.New(cfg, log)
		return agentInstance.Scan()
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  "Manage agent configuration",
}

var initConfigCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long:  "Create a default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		return config.Init(force)
	},
}

var statusConfigCmd = &cobra.Command{
	Use:   "status",
	Short: "Check configuration status",
	Long:  "Check if configuration file exists and validate configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := config.GetConfigPath()
		
		fmt.Printf("Configuration Status\n")
		fmt.Printf("===================\n\n")
		
		// Check if config file exists
		if config.ConfigExists() {
			fmt.Printf("✓ Config file exists: %s\n", configPath)
			
			// Try to load and validate configuration
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("✗ Configuration validation failed: %v\n", err)
				return nil
			}
			
			fmt.Printf("✓ Configuration is valid\n")
			fmt.Printf("  - API Base URL: %s\n", cfg.API.BaseURL)
			fmt.Printf("  - Team ID: %s\n", cfg.API.TeamID)
			fmt.Printf("  - API Key: %s (hidden)\n", maskString(cfg.API.APIKey))
			fmt.Printf("  - Agent Name: %s\n", cfg.Agent.Name)
			fmt.Printf("  - Scan Interval: %s\n", cfg.Agent.ScanInterval)
			fmt.Printf("  - Enabled Scanners: %v\n", cfg.Scanner.EnabledScanners)
		} else {
			fmt.Printf("✗ Config file not found: %s\n", configPath)
			fmt.Printf("\nTo create a configuration file, run:\n")
			fmt.Printf("  cvetodo-agent config init\n")
		}
		
		return nil
	},
}

// maskString masks all but the first and last 4 characters of a string
func maskString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(runCmd, scanCmd, configCmd)
	configCmd.AddCommand(initConfigCmd, statusConfigCmd)

	// Command-specific flags
	initConfigCmd.Flags().Bool("force", false, "Force overwrite existing configuration file")

	// Global flags
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is $HOME/.cvetodo-agent.yaml)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "text", "log format (text, json)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
} 