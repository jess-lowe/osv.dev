package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Server holds API routing and dependencies.
type Server struct {
	store   *AnalyticsStore
	syncer  *StorageSyncer
	webFS   http.FileSystem
	version string
}

func NewServer(store *AnalyticsStore, syncer *StorageSyncer, webFS http.FileSystem, version string) *Server {
	return &Server{
		store:   store,
		syncer:  syncer,
		webFS:   webFS,
		version: version,
	}
}

// Routes sets up the HTTP multiplexer.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// REST API Endpoints
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/sources", s.handleSources)
	mux.HandleFunc("GET /api/runs", s.handleRuns)
	mux.HandleFunc("GET /api/runs/", s.handleRunDetails)
	mux.HandleFunc("GET /api/compare", s.handleCompare)
	mux.HandleFunc("GET /api/cves", s.handleSearchCVEs)
	mux.HandleFunc("POST /api/upload", s.handleUpload)
	mux.HandleFunc("POST /api/sync", s.handleSync)

	// Web Static Assets & SPA Fallback
	if s.webFS != nil {
		fileServer := http.FileServer(s.webFS)
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}

	return corsMiddleware(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	storageMode := "Local Directory"
	lastSync := time.Now().UTC().Format(time.RFC3339)
	if s.syncer != nil {
		if s.syncer.gcsBucket != "" {
			storageMode = "Google Cloud Storage (" + s.syncer.gcsBucket + ")"
		}
		if !s.syncer.lastSync.IsZero() {
			lastSync = s.syncer.lastSync.Format(time.RFC3339)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      s.version,
		"time":         time.Now().UTC().Format(time.RFC3339),
		"storage_mode": storageMode,
		"sources":      s.store.GetSources(),
		"last_sync":    lastSync,
	})
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	sources := s.store.GetSources()
	writeJSON(w, http.StatusOK, map[string]any{
		"sources": sources,
	})
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "nvd"
	}

	minRecords := 0
	if minStr := r.URL.Query().Get("min_records"); minStr != "" {
		if val, err := strconv.Atoi(minStr); err == nil {
			minRecords = val
		}
	}

	runs := s.store.GetRuns(source, minRecords)
	if runs == nil {
		runs = []*RunSummary{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"source": source,
		"total":  len(runs),
		"runs":   runs,
	})
}

func (s *Server) handleRunDetails(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/runs/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		http.Error(w, "missing run timestamp in path", http.StatusBadRequest)
		return
	}
	timestamp := pathParts[0]
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "nvd"
	}

	run := s.store.GetRunDetails(source, timestamp)
	if run == nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, run)
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "nvd"
	}
	runA := r.URL.Query().Get("runA")
	runB := r.URL.Query().Get("runB")

	if runA == "" || runB == "" {
		http.Error(w, "runA and runB query parameters required", http.StatusBadRequest)
		return
	}

	comp, err := s.store.CompareRuns(source, runA, runB)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, comp)
}

func (s *Server) handleSearchCVEs(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "nvd"
	}
	run := r.URL.Query().Get("run")
	if run == "" {
		http.Error(w, "run query parameter required", http.StatusBadRequest)
		return
	}

	outcome := r.URL.Query().Get("outcome")
	search := r.URL.Query().Get("search")
	limit := 50
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if val, err := strconv.Atoi(limStr); err == nil && val > 0 {
			limit = val
		}
	}
	offset := 0
	if offStr := r.URL.Query().Get("offset"); offStr != "" {
		if val, err := strconv.Atoi(offStr); err == nil && val >= 0 {
			offset = val
		}
	}

	cves, total := s.store.SearchCVEs(source, run, outcome, search, limit, offset)

	writeJSON(w, http.StatusOK, map[string]any{
		"source": source,
		"run":    run,
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"cves":   cves,
	})
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(50 << 20); err != nil { // 50MB max
		http.Error(w, "failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file field required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	source := r.FormValue("source")
	if source == "" {
		source = ExtractSourceFromFilename(header.Filename)
	}

	cveMap, err := ParseOutcomeCSV(file)
	if err != nil {
		http.Error(w, "failed to parse CSV: "+err.Error(), http.StatusBadRequest)
		return
	}

	timestamp := ExtractTimestampFromFilename(header.Filename)
	s.store.AddRun(source, header.Filename, timestamp, cveMap)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "success",
		"message":   "CSV ingested successfully",
		"source":    source,
		"filename":  header.Filename,
		"timestamp": timestamp,
		"cve_count": len(cveMap),
	})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if s.syncer == nil {
		http.Error(w, "syncer not configured", http.StatusInternalServerError)
		return
	}

	go func() {
		_ = s.syncer.Sync(r.Context())
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "sync_initiated",
		"message": "Storage synchronization started in background",
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
