package models

import (
	"fmt"
	"log/slog"

	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type ConversionOutcome int

const (
	Extension = ".json"
)

const (
	// Set of enums for categorizing conversion outcomes.
	ConversionUnknown ConversionOutcome = iota // Shouldn't happen
	Successful                                 // It worked!
	Rejected                                   // The CVE was rejected
	NoSoftware                                 // The CVE had no CPEs relating to software (i.e. Operating Systems or Hardware).
	NoRepos                                    // The CPE Vendor/Product had no repositories derived for it.
	NoCommitRanges                             // No viable commit ranges could be calculated from the repository for the CVE's CPE(s).
	NoRanges                                   // No version ranges could be extracted from the record.
	FixUnresolvable                            // Partial resolution of versions, resulting in a false positive.
)

// RefTagDenyList contains reference tags that are often associated with unreliable or
// irrelevant repository URLs. References with these tags are currently ignored
// to avoid incorrect repository associations.
var RefTagDenyList = []string{
	// "Exploit",
	// "Third Party Advisory",
	"Broken Link", // Actively ignore these.
}

func (c ConversionOutcome) String() string {
	return [...]string{"ConversionUnknown", "Successful", "Rejected", "NoSoftware", "NoRepos", "NoCommitRanges", "NoRanges", "FixUnresolvable"}[c]
}

// ConversionMetrics holds the collected data about the conversion process for a single CVE.
type ConversionMetrics struct {
	CVEID                 CVEID                            `json:"id"`              // The CVE ID
	CNA                   string                           `json:"cna"`             // The CNA that assigned the CVE.
	Outcome               ConversionOutcome                `json:"outcome"`         // The final outcome of the conversion (e.g., "Successful", "Failed").
	Repos                 []string                         `json:"repos"`           // A list of repositories extracted from the CVE's references.
	RefTypesCount         map[osvschema.Reference_Type]int `json:"ref_types_count"` // A count of each type of reference found.
	VersionSources        []VersionSource                  `json:"version_sources"` // A list of the ways the versions were extracted
	Notes                 []string                         `json:"notes"`           // A collection of notes and warnings generated during conversion.
	CPEs                  []string                         `json:"cpes"`
	UnresolvedRangesCount int                              `json:"unresolved_ranges_count"`
	ResolvedRangesCount   int                              `json:"resolved_ranges_count"`
}

// LogLevel is the severity of the log message.
type LogLevel int

const (
	Debug LogLevel = iota
	Info
	Warn
	Error
)

// AddNote adds a formatted note to the ConversionMetrics.
// It accepts an optional LogLevel as the last argument.
// If no LogLevel is provided, it defaults to LogLevelDebug.
func (m *ConversionMetrics) AddNote(format string, a ...any) {
	level := Debug
	if len(a) > 0 {
		if l, ok := a[len(a)-1].(LogLevel); ok {
			level = l
			a = a[:len(a)-1]
		}
	}

	m.Notes = append(m.Notes, fmt.Sprintf(format, a...))

	switch level {
	case Debug:
		logger.Debug(fmt.Sprintf(format, a...), slog.String("cna", m.CNA), slog.String("cve", string(m.CVEID)))
	case Info:
		logger.Info(fmt.Sprintf(format, a...), slog.String("cna", m.CNA), slog.String("cve", string(m.CVEID)))
	case Warn:
		logger.Warn(fmt.Sprintf(format, a...), slog.String("cna", m.CNA), slog.String("cve", string(m.CVEID)))
	case Error:
		logger.Error(fmt.Sprintf(format, a...), slog.String("cna", m.CNA), slog.String("cve", string(m.CVEID)))
	}
}

// AddSource appends a source to the ConversionMetrics
func (m *ConversionMetrics) AddSource(source VersionSource) {
	m.VersionSources = append(m.VersionSources, source)
}

// VersionSource indicates the source of the extracted version information.
type VersionSource string

const (
	VersionSourceNone        VersionSource = "NOVERS"
	VersionSourceAffected    VersionSource = "CVEAFFVERS"
	VersionSourceGit         VersionSource = "GITVERS"
	VersionSourceCPE         VersionSource = "CPEVERS"
	VersionSourceDescription VersionSource = "DESCRVERS"
)

func DetermineOutcome(metrics *ConversionMetrics) {
	// check if we have affected ranges/versions.
	if len(metrics.Repos) == 0 {
		// Fix unlikely, as no repos to resolve
		metrics.Outcome = NoRepos
		return
	}

	if metrics.ResolvedRangesCount > 0 {
		metrics.Outcome = Successful
	} else if metrics.UnresolvedRangesCount > 0 {
		metrics.Outcome = NoCommitRanges
	} else {
		metrics.Outcome = NoRanges
	}
}
