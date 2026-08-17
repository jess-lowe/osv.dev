// Package main implements the OSV Data Quality & Telemetry Dashboard server.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/logger"
)

//go:embed web/*
var webFS embed.FS

var (
	port         = flag.Int("port", 8080, "HTTP port to listen on (also respects PORT env var)")
	gcsBucket    = flag.String("gcs-bucket", "", "Google Cloud Storage bucket to read conversion outcome CSVs from")
	gcsPrefix    = flag.String("gcs-prefix", "", "GCS prefix/folder to scan within the bucket")
	localDir     = flag.String("local-dir", "", "Local directory to scan for conversion outcome CSV files")
	pollInterval = flag.Duration("poll-interval", 5*time.Minute, "Background interval to re-sync from GCS/local directory")
)

const version = "1.2.0"

func main() {
	flag.Parse()
	logger.InitGlobalLogger()
	defer logger.Close()

	// Check if PORT env var is set (standard in Cloud Run and Kubernetes)
	if envPort := os.Getenv("PORT"); envPort != "" {
		var p int
		if _, err := fmt.Sscanf(envPort, "%d", &p); err == nil && p > 0 {
			*port = p
		}
	}

	// Check if GCS_BUCKET or OSV_OUTPUT_GCS_PATH env vars are set
	if *gcsBucket == "" {
		if envBkt := os.Getenv("GCS_BUCKET"); envBkt != "" {
			*gcsBucket = envBkt
		} else if envPath := os.Getenv("OSV_OUTPUT_GCS_PATH"); envPath != "" {
			// Extract bucket from gs://path
			clean := stringsTrimPrefix(envPath, "gs://")
			parts := stringsSplitN(clean, "/", 2)
			*gcsBucket = parts[0]
			if len(parts) > 1 && *gcsPrefix == "" {
				*gcsPrefix = parts[1]
			}
		}
	}

	// If no localDir or gcsBucket provided, default localDir to current working directory
	if *gcsBucket == "" && *localDir == "" {
		*localDir = "."
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger.Info("Starting OSV Data Quality Dashboard",
		slog.String("version", version),
		slog.Int("port", *port),
		slog.String("gcs_bucket", *gcsBucket),
		slog.String("gcs_prefix", *gcsPrefix),
		slog.String("local_dir", *localDir),
	)

	store := NewAnalyticsStore()
	syncer, err := NewStorageSyncer(ctx, store, *gcsBucket, *gcsPrefix, *localDir, *pollInterval)
	if err != nil {
		logger.Fatal("Failed to initialize storage syncer", slog.Any("err", err))
	}
	defer syncer.Close()

	// Perform initial synchronization
	logger.Info("Performing initial data sync...")
	if err := syncer.Sync(ctx); err != nil {
		logger.Warn("Initial data sync completed with warnings", slog.Any("err", err))
	} else {
		logger.Info("Initial data sync completed successfully")
	}

	// Start background poller for continuous updates
	syncer.StartBackgroundPoller(ctx)

	// Prepare embedded web assets
	webSubFS, err := fs.Sub(webFS, "web")
	if err != nil {
		logger.Fatal("Failed to load embedded web assets", slog.Any("err", err))
	}

	srv := NewServer(store, syncer, http.FS(webSubFS), version)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown listener
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info(fmt.Sprintf("Dashboard server listening on http://localhost:%d", *port))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTP server failed", slog.Any("err", err))
		}
	}()

	<-stopChan
	logger.Info("Shutting down dashboard server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTP server shutdown error", slog.Any("err", err))
	}
	logger.Info("Dashboard server stopped cleanly.")
}

func stringsTrimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func stringsSplitN(s, sep string, n int) []string {
	var parts []string
	curr := s
	for len(parts)+1 < n {
		idx := -1
		for i := 0; i+len(sep) <= len(curr); i++ {
			if curr[i:i+len(sep)] == sep {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		parts = append(parts, curr[:idx])
		curr = curr[idx+len(sep):]
	}
	parts = append(parts, curr)
	return parts
}
