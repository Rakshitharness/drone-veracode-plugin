// Copyright 2020 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
)

// Args provides plugin execution arguments.
type Args struct {
	Pipeline

	Level string `envconfig:"PLUGIN_LOG_LEVEL"`

	// Veracode API credentials and other configuration
	VeracodeAPIID  string `envconfig:"VERACODE_API_ID"`
	VeracodeAPIKey string `envconfig:"VERACODE_API_KEY"`
	FileToScan     string `envconfig:"PLUGIN_FILE"`
	FailOnSeverity string `envconfig:"PLUGIN_FAIL_ON_SEVERITY" default:"Very High, High"`
	FailOnCWE      string `envconfig:"PLUGIN_FAIL_ON_CWE" default:"80"`
	BaselineFile   string `envconfig:"PLUGIN_BASELINE_FILE"`
	Timeout        string `envconfig:"PLUGIN_TIMEOUT"`
	ProjectName    string `envconfig:"PLUGIN_PROJECT_NAME"`
	ProjectURL     string `envconfig:"PLUGIN_PROJECT_URL"`
	ProjectRef     string `envconfig:"PLUGIN_PROJECT_REF"`
}

// Exec executes the plugin.
func Exec(ctx context.Context, args Args) error {
	// Ensure the necessary tools are installed
	installDependencies()

	// Download the Veracode Pipeline Scan tool
	downloadVeracodeScanTool()

	// Check if file to scan is provided
	if args.FileToScan == "" {
		return fmt.Errorf("no file to scan provided")
	}

	// Run the Veracode Pipeline Scan tool
	err := runVeracodeScan(args)
	if err != nil {
		log.Fatalf("Veracode scan failed: %v", err)
		return err
	}

	return nil
}

func installDependencies() {
	cmd := exec.Command("apk", "add", "--no-cache", "openjdk11-jre", "curl", "unzip")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to install dependencies: %v", err)
	}
}

func downloadVeracodeScanTool() {
	url := "https://downloads.veracode.com/securityscan/pipeline-scan-LATEST.zip"
	output := "pipeline-scan-LATEST.zip"

	// Download the file
	err := downloadFile(url, output)
	if err != nil {
		log.Fatalf("Failed to download Veracode scan tool: %v", err)
	}

	// Unzip the file
	cmd := exec.Command("unzip", output, "-d", "/bin")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Fatalf("Failed to unzip Veracode scan tool: %v", err)
	}

	// Clean up the zip file
	err = os.Remove(output)
	if err != nil {
		log.Fatalf("Failed to remove zip file: %v", err)
	}
}

func downloadFile(url string, filepath string) error {
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func runVeracodeScan(args Args) error {
	cmd := exec.Command("java", "-jar", "/bin/pipeline-scan.jar",
		"--veracode_api_id", args.VeracodeAPIID,
		"--veracode_api_key", args.VeracodeAPIKey,
		"--file", args.FileToScan,
		"--fail_on_severity", args.FailOnSeverity,
		"--fail_on_cwe", args.FailOnCWE,
		"--baseline_file", args.BaselineFile,
		"--timeout", args.Timeout,
		"--project_name", args.ProjectName,
		"--project_url", args.ProjectURL,
		"--project_ref", args.ProjectRef)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
