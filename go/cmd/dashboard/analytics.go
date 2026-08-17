// Package main implements the OSV Data Quality & Telemetry Dashboard server.
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var cveYearRegex = regexp.MustCompile(`CVE-([0-9]{4})-`)

// RunSummary represents aggregated metrics for a single converter execution run.
type RunSummary struct {
	Source         string                    `json:"source"`
	Filename       string                    `json:"filename"`
	Timestamp      string                    `json:"timestamp"`
	Total          int                       `json:"total"`
	Counts         map[string]int            `json:"counts"`
	Rates          map[string]float64        `json:"rates"`
	YearBreakdown  map[string]map[string]int `json:"year_breakdown"`
	Deltas         *RunDelta                 `json:"deltas,omitempty"`
	Transitions    map[string]int            `json:"transitions,omitempty"`
	ChangedCVEs    []ChangedCVE              `json:"changed_cves,omitempty"`
	TotalChanged   int                       `json:"total_changed"`
	TotalUnchanged int                       `json:"total_unchanged"`
}

// RunDelta captures changes relative to a baseline run.
type RunDelta struct {
	PrevTimestamp  string   `json:"prev_timestamp"`
	CommonCount    int      `json:"common_count"`
	NewCount       int      `json:"new_count"`
	RemovedCount   int      `json:"removed_count"`
	ChangedCount   int      `json:"changed_count"`
	UnchangedCount int      `json:"unchanged_count"`
	NewSample      []string `json:"new_sample"`
	RemovedSample  []string `json:"removed_sample"`
}

// ChangedCVE captures an individual CVE's transition between outcomes.
type ChangedCVE struct {
	CVE  string `json:"cve"`
	From string `json:"from"`
	To   string `json:"to"`
}

// ComparisonResult represents on-demand comparison between two runs.
type ComparisonResult struct {
	Source       string         `json:"source"`
	RunA         *RunSummary    `json:"run_a"`
	RunB         *RunSummary    `json:"run_b"`
	TotalDelta   int            `json:"total_delta"`
	CountDeltas  map[string]int `json:"count_deltas"`
	Transitions  map[string]int `json:"transitions"`
	ChangedCVEs  []ChangedCVE   `json:"changed_cves"`
	TotalChanged int            `json:"total_changed"`
	CommonCount  int            `json:"common_count"`
	NewCount     int            `json:"new_count"`
	RemovedCount int            `json:"removed_count"`
}

// RawRun holds the full in-memory mapping of CVE ID to Outcome.
type RawRun struct {
	Source    string
	Filename  string
	Timestamp string
	CVEs      map[string]string // CVEID -> Outcome string
}

// AnalyticsStore manages in-memory data and computations across multiple sources.
type AnalyticsStore struct {
	mu      sync.RWMutex
	sources map[string][]*RawRun // source -> ordered list of RawRun
}

// NewAnalyticsStore creates an empty analytics store.
func NewAnalyticsStore() *AnalyticsStore {
	return &AnalyticsStore{
		sources: make(map[string][]*RawRun),
	}
}

// AddRun ingests a raw run into the store and maintains chronological ordering.
func (s *AnalyticsStore) AddRun(source string, filename string, timestamp string, cveMap map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sourceKey := strings.ToLower(source)
	runs := s.sources[sourceKey]

	// Check if run already exists by timestamp/filename
	for i, r := range runs {
		if r.Timestamp == timestamp || r.Filename == filename {
			runs[i] = &RawRun{
				Source:    sourceKey,
				Filename:  filename,
				Timestamp: timestamp,
				CVEs:      cveMap,
			}
			s.sortRuns(sourceKey)
			return
		}
	}

	runs = append(runs, &RawRun{
		Source:    sourceKey,
		Filename:  filename,
		Timestamp: timestamp,
		CVEs:      cveMap,
	})
	s.sources[sourceKey] = runs
	s.sortRuns(sourceKey)
}

func (s *AnalyticsStore) sortRuns(sourceKey string) {
	runs := s.sources[sourceKey]
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].Timestamp < runs[j].Timestamp
	})
	s.sources[sourceKey] = runs
}

// GetSources returns all available source identifiers.
func (s *AnalyticsStore) GetSources() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sources := make([]string, 0, len(s.sources))
	for k := range s.sources {
		sources = append(sources, k)
	}
	sort.Strings(sources)
	return sources
}

// GetRuns returns the list of run summaries for a given source.
func (s *AnalyticsStore) GetRuns(source string, minRecords int) []*RunSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sourceKey := strings.ToLower(source)
	rawRuns := s.sources[sourceKey]
	if len(rawRuns) == 0 {
		return nil
	}

	filteredRaw := make([]*RawRun, 0, len(rawRuns))
	for _, r := range rawRuns {
		if len(r.CVEs) >= minRecords {
			filteredRaw = append(filteredRaw, r)
		}
	}

	summaries := make([]*RunSummary, len(filteredRaw))
	for i, r := range filteredRaw {
		var prev *RawRun
		if i > 0 {
			prev = filteredRaw[i-1]
		}
		summaries[i] = computeRunSummary(r, prev)
	}

	return summaries
}

// GetRunDetails returns full details for a specific run.
func (s *AnalyticsStore) GetRunDetails(source string, timestamp string) *RunSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sourceKey := strings.ToLower(source)
	rawRuns := s.sources[sourceKey]

	for i, r := range rawRuns {
		if r.Timestamp == timestamp || r.Filename == timestamp {
			var prev *RawRun
			if i > 0 {
				prev = rawRuns[i-1]
			}
			return computeRunSummary(r, prev)
		}
	}
	return nil
}

// CompareRuns computes comparison between two specific runs.
func (s *AnalyticsStore) CompareRuns(source string, timestampA, timestampB string) (*ComparisonResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sourceKey := strings.ToLower(source)
	rawRuns := s.sources[sourceKey]

	var runA, runB *RawRun
	for _, r := range rawRuns {
		if r.Timestamp == timestampA || r.Filename == timestampA {
			runA = r
		}
		if r.Timestamp == timestampB || r.Filename == timestampB {
			runB = r
		}
	}

	if runA == nil || runB == nil {
		return nil, fmt.Errorf("could not find both runs for comparison: %s vs %s", timestampA, timestampB)
	}

	summaryA := computeRunSummary(runA, nil)
	summaryB := computeRunSummary(runB, nil)

	commonCount := 0
	newCount := 0
	removedCount := 0
	transitions := make(map[string]int)
	var changedCVEs []ChangedCVE

	for cve, oB := range runB.CVEs {
		if oA, exists := runA.CVEs[cve]; exists {
			commonCount++
			transKey := fmt.Sprintf("%s -> %s", oA, oB)
			transitions[transKey]++
			if oA != oB {
				changedCVEs = append(changedCVEs, ChangedCVE{
					CVE:  cve,
					From: oA,
					To:   oB,
				})
			}
		} else {
			newCount++
		}
	}

	for cve := range runA.CVEs {
		if _, exists := runB.CVEs[cve]; !exists {
			removedCount++
		}
	}

	countDeltas := make(map[string]int)
	allOutcomes := make(map[string]bool)
	for k := range summaryA.Counts {
		allOutcomes[k] = true
	}
	for k := range summaryB.Counts {
		allOutcomes[k] = true
	}
	for k := range allOutcomes {
		countDeltas[k] = summaryB.Counts[k] - summaryA.Counts[k]
	}

	return &ComparisonResult{
		Source:       sourceKey,
		RunA:         summaryA,
		RunB:         summaryB,
		TotalDelta:   runB.Total() - runA.Total(),
		CountDeltas:  countDeltas,
		Transitions:  transitions,
		ChangedCVEs:  changedCVEs,
		TotalChanged: len(changedCVEs),
		CommonCount:  commonCount,
		NewCount:     newCount,
		RemovedCount: removedCount,
	}, nil
}

// SearchCVEs searches or filters CVE records in a run.
func (s *AnalyticsStore) SearchCVEs(source string, timestamp string, outcomeFilter string, searchFilter string, limit int, offset int) ([]ChangedCVE, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sourceKey := strings.ToLower(source)
	rawRuns := s.sources[sourceKey]

	var targetRun *RawRun
	var prevRun *RawRun

	for i, r := range rawRuns {
		if r.Timestamp == timestamp || r.Filename == timestamp {
			targetRun = r
			if i > 0 {
				prevRun = rawRuns[i-1]
			}
			break
		}
	}

	if targetRun == nil {
		return nil, 0
	}

	var matches []ChangedCVE
	searchLower := strings.ToLower(strings.TrimSpace(searchFilter))

	for cve, outcome := range targetRun.CVEs {
		if outcomeFilter != "" && outcomeFilter != "all" && outcome != outcomeFilter {
			continue
		}
		if searchLower != "" && !strings.Contains(strings.ToLower(cve), searchLower) {
			continue
		}

		prevOutcome := "New"
		if prevRun != nil {
			if po, ok := prevRun.CVEs[cve]; ok {
				prevOutcome = po
			}
		}

		matches = append(matches, ChangedCVE{
			CVE:  cve,
			From: prevOutcome,
			To:   outcome,
		})
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CVE < matches[j].CVE
	})

	totalMatches := len(matches)
	if offset >= totalMatches {
		return nil, totalMatches
	}
	end := offset + limit
	if end > totalMatches || limit <= 0 {
		end = totalMatches
	}

	return matches[offset:end], totalMatches
}

func (r *RawRun) Total() int {
	return len(r.CVEs)
}

func computeRunSummary(curr *RawRun, prev *RawRun) *RunSummary {
	counts := make(map[string]int)
	yearBreakdown := make(map[string]map[string]int)
	total := len(curr.CVEs)

	for cve, outcome := range curr.CVEs {
		counts[outcome]++

		m := cveYearRegex.FindStringSubmatch(cve)
		year := "Unknown"
		if len(m) >= 2 {
			year = m[1]
		}
		if yearBreakdown[year] == nil {
			yearBreakdown[year] = make(map[string]int)
		}
		yearBreakdown[year][outcome]++
	}

	rates := make(map[string]float64)
	if total > 0 {
		for k, v := range counts {
			rates[k] = (float64(v) / float64(total)) * 100.0
		}
	}

	summary := &RunSummary{
		Source:        curr.Source,
		Filename:      curr.Filename,
		Timestamp:     curr.Timestamp,
		Total:         total,
		Counts:        counts,
		Rates:         rates,
		YearBreakdown: yearBreakdown,
	}

	if prev != nil {
		commonCount := 0
		newCount := 0
		removedCount := 0
		transitions := make(map[string]int)
		var changedCVEs []ChangedCVE
		var newSample []string
		var removedSample []string

		for cve, oCurr := range curr.CVEs {
			if oPrev, exists := prev.CVEs[cve]; exists {
				commonCount++
				transKey := fmt.Sprintf("%s -> %s", oPrev, oCurr)
				transitions[transKey]++
				if oPrev != oCurr {
					changedCVEs = append(changedCVEs, ChangedCVE{
						CVE:  cve,
						From: oPrev,
						To:   oCurr,
					})
				}
			} else {
				newCount++
				if len(newSample) < 10 {
					newSample = append(newSample, cve)
				}
			}
		}

		for cve := range prev.CVEs {
			if _, exists := curr.CVEs[cve]; !exists {
				removedCount++
				if len(removedSample) < 10 {
					removedSample = append(removedSample, cve)
				}
			}
		}

		summary.Deltas = &RunDelta{
			PrevTimestamp:  prev.Timestamp,
			CommonCount:    commonCount,
			NewCount:       newCount,
			RemovedCount:   removedCount,
			ChangedCount:   len(changedCVEs),
			UnchangedCount: commonCount - len(changedCVEs),
			NewSample:      newSample,
			RemovedSample:  removedSample,
		}
		summary.Transitions = transitions
		summary.TotalChanged = len(changedCVEs)
		summary.TotalUnchanged = commonCount - len(changedCVEs)
		// Keep a capped sample in the summary for lightweight payload
		if len(changedCVEs) > 200 {
			summary.ChangedCVEs = changedCVEs[:200]
		} else {
			summary.ChangedCVEs = changedCVEs
		}
	}

	return summary
}

// ParseOutcomeCSV parses a CSV file into a CVE ID -> Outcome mapping.
func ParseOutcomeCSV(r io.Reader) (map[string]string, error) {
	csvReader := csv.NewReader(r)
	csvReader.ReuseRecord = true
	cveMap := make(map[string]string)

	headers, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV headers: %w", err)
	}

	cveIdx := 0
	outcomeIdx := 1
	for i, h := range headers {
		hLower := strings.ToLower(strings.TrimSpace(h))
		if hLower == "cveid" || hLower == "cve" || hLower == "id" {
			cveIdx = i
		} else if hLower == "outcome" || hLower == "status" {
			outcomeIdx = i
		}
	}

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing CSV record: %w", err)
		}
		if len(record) > cveIdx && len(record) > outcomeIdx {
			cve := strings.TrimSpace(record[cveIdx])
			outcome := strings.TrimSpace(record[outcomeIdx])
			if cve != "" && outcome != "" {
				cveMap[cve] = outcome
			}
		}
	}

	return cveMap, nil
}

// ExtractTimestampFromFilename attempts to parse standard timestamp formats from filenames.
func ExtractTimestampFromFilename(filename string) string {
	re := regexp.MustCompile(`(202[0-9]-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2})`)
	m := re.FindStringSubmatch(filename)
	if len(m) >= 2 {
		return m[1]
	}
	return time.Now().UTC().Format("2006-01-02T15:04")
}

// ExtractSourceFromFilename guesses the source name from filename.
func ExtractSourceFromFilename(filename string) string {
	lower := strings.ToLower(filename)
	if strings.Contains(lower, "cve5") {
		return "cve5"
	}
	if strings.Contains(lower, "nvd") {
		return "nvd"
	}
	return "unknown"
}
