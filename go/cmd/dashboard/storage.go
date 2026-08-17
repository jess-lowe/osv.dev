package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// StorageSyncer handles discovering and reading outcome CSVs from GCS or local disk.
type StorageSyncer struct {
	store        *AnalyticsStore
	gcsBucket    string
	gcsPrefix    string
	localDir     string
	gcsClient    *storage.Client
	lastSync     time.Time
	syncError    error
	pollInterval time.Duration
}

// NewStorageSyncer creates a new StorageSyncer.
func NewStorageSyncer(ctx context.Context, store *AnalyticsStore, gcsBucket, gcsPrefix, localDir string, pollInterval time.Duration) (*StorageSyncer, error) {
	var client *storage.Client
	if gcsBucket != "" {
		var err error
		client, err = storage.NewClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCS client: %w", err)
		}
		slog.Info("GCS client initialized for dashboard", slog.String("bucket", gcsBucket), slog.String("prefix", gcsPrefix))
	}

	return &StorageSyncer{
		store:        store,
		gcsBucket:    gcsBucket,
		gcsPrefix:    gcsPrefix,
		localDir:     localDir,
		gcsClient:    client,
		pollInterval: pollInterval,
	}, nil
}

// Close closes the storage client if initialized.
func (s *StorageSyncer) Close() {
	if s.gcsClient != nil {
		s.gcsClient.Close()
	}
}

// Sync performs a full discovery and ingestion pass from all configured sources.
func (s *StorageSyncer) Sync(ctx context.Context) error {
	var syncErrs []string

	// 1. Sync from GCS if configured
	if s.gcsClient != nil && s.gcsBucket != "" {
		if err := s.syncGCS(ctx); err != nil {
			slog.Error("Failed to sync from GCS", slog.Any("err", err))
			syncErrs = append(syncErrs, fmt.Sprintf("GCS sync error: %v", err))
		}
	}

	// 2. Sync from local directory if configured
	if s.localDir != "" {
		if err := s.syncLocalDir(s.localDir); err != nil {
			slog.Error("Failed to sync from local directory", slog.String("dir", s.localDir), slog.Any("err", err))
			syncErrs = append(syncErrs, fmt.Sprintf("Local dir error: %v", err))
		}
	}

	s.lastSync = time.Now().UTC()
	if len(syncErrs) > 0 {
		s.syncError = errors.New(strings.Join(syncErrs, "; "))
		return s.syncError
	}
	s.syncError = nil
	return nil
}

// StartBackgroundPoller runs periodic sync in the background until context cancellation.
func (s *StorageSyncer) StartBackgroundPoller(ctx context.Context) {
	if s.pollInterval <= 0 {
		s.pollInterval = 5 * time.Minute
	}

	go func() {
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				slog.Info("Starting periodic dashboard sync pass...")
				if err := s.Sync(ctx); err != nil {
					slog.Warn("Periodic sync encountered errors", slog.Any("err", err))
				} else {
					slog.Info("Periodic dashboard sync complete", slog.Time("lastSync", s.lastSync))
				}
			}
		}
	}()
}

func (s *StorageSyncer) syncGCS(ctx context.Context) error {
	bucket := s.gcsClient.Bucket(s.gcsBucket)
	query := &storage.Query{
		Prefix: s.gcsPrefix,
	}

	it := bucket.Objects(ctx, query)
	var csvObjects []string

	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list GCS objects: %w", err)
		}
		if strings.HasSuffix(attrs.Name, ".csv") && strings.Contains(attrs.Name, "-conversion-outcomes-") {
			csvObjects = append(csvObjects, attrs.Name)
		}
	}

	slog.Info("Found outcome CSVs in GCS", slog.Int("count", len(csvObjects)), slog.String("bucket", s.gcsBucket))

	for _, objName := range csvObjects {
		rc, err := bucket.Object(objName).NewReader(ctx)
		if err != nil {
			slog.Warn("Failed to open GCS object reader", slog.String("object", objName), slog.Any("err", err))
			continue
		}

		cveMap, err := ParseOutcomeCSV(rc)
		rc.Close()
		if err != nil {
			slog.Warn("Failed to parse GCS CSV", slog.String("object", objName), slog.Any("err", err))
			continue
		}

		filename := filepath.Base(objName)
		timestamp := ExtractTimestampFromFilename(filename)
		source := ExtractSourceFromFilename(filename)

		s.store.AddRun(source, filename, timestamp, cveMap)
		slog.Info("Ingested run from GCS", slog.String("source", source), slog.String("timestamp", timestamp), slog.Int("cve_count", len(cveMap)))
	}

	return nil
}

func (s *StorageSyncer) syncLocalDir(dir string) error {
	slog.Info("Scanning local directory for outcome CSVs", slog.String("dir", dir))
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".csv") && strings.Contains(d.Name(), "-conversion-outcomes-") {
			data, err := os.ReadFile(path)
			if err != nil {
				slog.Warn("Failed to read local CSV", slog.String("path", path), slog.Any("err", err))
				return nil
			}

			cveMap, err := ParseOutcomeCSV(bytes.NewReader(data))
			if err != nil {
				slog.Warn("Failed to parse local CSV", slog.String("path", path), slog.Any("err", err))
				return nil
			}

			filename := d.Name()
			timestamp := ExtractTimestampFromFilename(filename)
			source := ExtractSourceFromFilename(filename)

			s.store.AddRun(source, filename, timestamp, cveMap)
			slog.Info("Ingested run from local file", slog.String("source", source), slog.String("timestamp", timestamp), slog.Int("cve_count", len(cveMap)))
		}
		return nil
	})
}
