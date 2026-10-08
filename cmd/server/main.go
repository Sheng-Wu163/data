// Command server runs the banner fingerprint HTTP service.
//
// Endpoints:
//
//	GET  /health       - liveness/readiness probe
//	POST /fingerprint  - batch identification of raw banners
//
// The rule set is loaded from RULES_PATH when set, otherwise the embedded
// default set is used. The binary also doubles as its own container health
// probe via the -healthcheck flag, so the image needs no shell or curl.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sheng-Wu163/data/internal/api"
	"github.com/Sheng-Wu163/data/internal/fingerprint"
	"github.com/Sheng-Wu163/data/rules"
)

func main() {
	var (
		healthcheck = flag.Bool("healthcheck", false, "probe the local /health endpoint and exit")
		port        = flag.String("port", envOr("PORT", "8080"), "listen port")
		rulesPath   = flag.String("rules", os.Getenv("RULES_PATH"), "path to a rules JSON file (empty = embedded default)")
	)
	flag.Parse()

	if *healthcheck {
		os.Exit(probe(*port))
	}

	set, err := rules.Load(*rulesPath)
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}
	engine := fingerprint.New(set)
	log.Printf("loaded %d fingerprint rules (ruleset version %d)", engine.RuleCount(), set.Version)

	srv := &http.Server{
		Addr:              ":" + *port,
		Handler:           api.New(engine).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("fingerprint server listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Printf("shutdown signal received, draining connections...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func probe(port string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
