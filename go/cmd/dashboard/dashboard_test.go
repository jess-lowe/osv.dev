package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseOutcomeCSV(t *testing.T) {
	csvData := `CVEID,Outcome
CVE-2024-1001,Successful
CVE-2024-1002,NoRepos
CVE-2024-1003,NoCommitRanges
CVE-2024-1004,Rejected
`
	cveMap, err := ParseOutcomeCSV(strings.NewReader(csvData))
	if err != nil {
		t.Fatalf("ParseOutcomeCSV failed: %v", err)
	}

	if len(cveMap) != 4 {
		t.Errorf("expected 4 records, got %d", len(cveMap))
	}
	if cveMap["CVE-2024-1001"] != "Successful" {
		t.Errorf("expected Successful, got %s", cveMap["CVE-2024-1001"])
	}
	if cveMap["CVE-2024-1002"] != "NoRepos" {
		t.Errorf("expected NoRepos, got %s", cveMap["CVE-2024-1002"])
	}
}

func TestAnalyticsStoreAndTransitions(t *testing.T) {
	store := NewAnalyticsStore()

	// Run 1
	run1CVEs := map[string]string{
		"CVE-2024-0001": "NoCommitRanges",
		"CVE-2024-0002": "NoRepos",
		"CVE-2024-0003": "Successful",
		"CVE-2024-0004": "Successful",
	}
	store.AddRun("nvd", "nvd-outcomes-2026-08-01T00:00.csv", "2026-08-01T00:00", run1CVEs)

	// Run 2 (with status improvements and a new CVE)
	run2CVEs := map[string]string{
		"CVE-2024-0001": "Successful", // Transitioned NoCommitRanges -> Successful
		"CVE-2024-0002": "Successful", // Transitioned NoRepos -> Successful
		"CVE-2024-0003": "Successful", // Unchanged
		"CVE-2024-0005": "Successful", // New CVE (0004 removed)
	}
	store.AddRun("nvd", "nvd-outcomes-2026-08-02T00:00.csv", "2026-08-02T00:00", run2CVEs)

	runs := store.GetRuns("nvd", 0)
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(runs))
	}

	// Verify Run 2 metrics
	r2 := runs[1]
	if r2.Total != 4 {
		t.Errorf("expected total 4, got %d", r2.Total)
	}
	if r2.Counts["Successful"] != 4 {
		t.Errorf("expected 4 Successful, got %d", r2.Counts["Successful"])
	}
	if r2.Rates["Successful"] != 100.0 {
		t.Errorf("expected 100%% success rate, got %f", r2.Rates["Successful"])
	}

	// Verify transitions in run 2
	if r2.Deltas == nil {
		t.Fatalf("expected deltas for run 2, got nil")
	}
	if r2.Deltas.ChangedCount != 2 {
		t.Errorf("expected 2 changed CVEs, got %d", r2.Deltas.ChangedCount)
	}
	if r2.Transitions["NoCommitRanges -> Successful"] != 1 {
		t.Errorf("expected 1 NoCommitRanges -> Successful, got %d", r2.Transitions["NoCommitRanges -> Successful"])
	}
	if r2.Transitions["NoRepos -> Successful"] != 1 {
		t.Errorf("expected 1 NoRepos -> Successful, got %d", r2.Transitions["NoRepos -> Successful"])
	}
	if r2.Deltas.NewCount != 1 {
		t.Errorf("expected 1 new CVE, got %d", r2.Deltas.NewCount)
	}
	if r2.Deltas.RemovedCount != 1 {
		t.Errorf("expected 1 removed CVE, got %d", r2.Deltas.RemovedCount)
	}

	// Test CompareRuns
	comp, err := store.CompareRuns("nvd", "2026-08-01T00:00", "2026-08-02T00:00")
	if err != nil {
		t.Fatalf("CompareRuns failed: %v", err)
	}
	if comp.TotalChanged != 2 {
		t.Errorf("expected 2 changed in comparison, got %d", comp.TotalChanged)
	}
	if comp.Transitions["NoCommitRanges -> Successful"] != 1 {
		t.Errorf("expected 1 transition, got %d", comp.Transitions["NoCommitRanges -> Successful"])
	}

	// Test SearchCVEs
	cves, total := store.SearchCVEs("nvd", "2026-08-02T00:00", "Successful", "CVE-2024-0001", 10, 0)
	if total != 1 || len(cves) != 1 {
		t.Errorf("expected 1 search match, got total=%d len=%d", total, len(cves))
	}
	if cves[0].From != "NoCommitRanges" || cves[0].To != "Successful" {
		t.Errorf("unexpected transition: from=%s to=%s", cves[0].From, cves[0].To)
	}
}

func TestServerEndpoints(t *testing.T) {
	store := NewAnalyticsStore()
	store.AddRun("nvd", "nvd-outcomes-2026-08-01T00:00.csv", "2026-08-01T00:00", map[string]string{
		"CVE-2024-1001": "Successful",
		"CVE-2024-1002": "NoRepos",
	})
	store.AddRun("nvd", "nvd-outcomes-2026-08-02T00:00.csv", "2026-08-02T00:00", map[string]string{
		"CVE-2024-1001": "Successful",
		"CVE-2024-1002": "Successful",
	})

	srv := NewServer(store, nil, nil, "1.2.0")
	handler := srv.Routes()

	// 1. GET /api/health
	req := httptest.NewRequest("GET", "/api/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/health, got %d", rr.Code)
	}
	var healthResp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&healthResp); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if healthResp["status"] != "ok" {
		t.Errorf("expected status ok, got %v", healthResp["status"])
	}

	// 2. GET /api/sources
	req = httptest.NewRequest("GET", "/api/sources", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/sources, got %d", rr.Code)
	}

	// 3. GET /api/runs?source=nvd
	req = httptest.NewRequest("GET", "/api/runs?source=nvd", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/runs, got %d", rr.Code)
	}
	var runsResp struct {
		Runs []*RunSummary `json:"runs"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&runsResp); err != nil {
		t.Fatalf("failed to decode runs response: %v", err)
	}
	if len(runsResp.Runs) != 2 {
		t.Errorf("expected 2 runs, got %d", len(runsResp.Runs))
	}

	// 4. GET /api/compare?source=nvd&runA=2026-08-01T00:00&runB=2026-08-02T00:00
	req = httptest.NewRequest("GET", "/api/compare?source=nvd&runA=2026-08-01T00:00&runB=2026-08-02T00:00", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/compare, got %d", rr.Code)
	}
	var compResp ComparisonResult
	if err := json.NewDecoder(rr.Body).Decode(&compResp); err != nil {
		t.Fatalf("failed to decode comparison response: %v", err)
	}
	if compResp.Transitions["NoRepos -> Successful"] != 1 {
		t.Errorf("expected 1 transition, got %d", compResp.Transitions["NoRepos -> Successful"])
	}

	// 5. POST /api/upload
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "nvd-conversion-outcomes-all-2026-08-03T00:00.csv")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = fw.Write([]byte("CVEID,Outcome\nCVE-2024-9999,Successful\n"))
	_ = mw.WriteField("source", "nvd")
	mw.Close()

	req = httptest.NewRequest("POST", "/api/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/upload, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify run was added
	runsAfter := store.GetRuns("nvd", 0)
	if len(runsAfter) != 3 {
		t.Errorf("expected 3 runs after upload, got %d", len(runsAfter))
	}
}
