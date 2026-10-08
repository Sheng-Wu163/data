// Command client is the standalone driver: it reads a local JSON file of raw
// banners, ships them to the fingerprint server, and prints the verdicts.
//
// Usage:
//
//	client -server http://localhost:8080 -input testdata/input.json [-output out.json]
//
// Environment overrides: SERVER_URL, CLIENT_INPUT, CLIENT_OUTPUT.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Sheng-Wu163/data/internal/model"
	"github.com/Sheng-Wu163/data/internal/normalize"
)

func main() {
	var (
		serverURL  = flag.String("server", envOr("SERVER_URL", "http://localhost:8080"), "fingerprint server base URL")
		inputPath  = flag.String("input", envOr("CLIENT_INPUT", "testdata/input.json"), "path to the input JSON file")
		outputPath = flag.String("output", envOr("CLIENT_OUTPUT", ""), "optional path to write the results JSON")
		wait       = flag.Duration("wait", 30*time.Second, "max time to wait for the server to become healthy")
	)
	flag.Parse()

	if err := run(*serverURL, *inputPath, *outputPath, *wait); err != nil {
		fmt.Fprintf(os.Stderr, "client error: %v\n", err)
		os.Exit(1)
	}
}

func run(serverURL, inputPath, outputPath string, wait time.Duration) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input %q: %w", inputPath, err)
	}
	raw = normalize.SanitizeJSON(raw)

	items, err := model.ParseInputs(raw)
	if err != nil {
		return fmt.Errorf("parse input %q: %w", inputPath, err)
	}
	fmt.Printf("loaded %d banner(s) from %s\n", len(items), inputPath)

	base := strings.TrimRight(serverURL, "/")
	client := &http.Client{Timeout: 30 * time.Second}

	if err := waitHealthy(client, base, wait); err != nil {
		return err
	}

	payload, _ := json.Marshal(items)
	resp, err := client.Post(base+"/fingerprint", "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("post /fingerprint: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var results []model.Result
	if err := json.Unmarshal(respBody, &results); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	pretty, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(pretty))

	if outputPath != "" {
		if err := os.WriteFile(outputPath, pretty, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write %q: %v\n", outputPath, err)
		} else {
			fmt.Printf("wrote %d result(s) to %s\n", len(results), outputPath)
		}
	}
	return nil
}

func waitHealthy(client *http.Client, base string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		resp, err := client.Get(base + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("server at %s not healthy after %s", base, wait)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
