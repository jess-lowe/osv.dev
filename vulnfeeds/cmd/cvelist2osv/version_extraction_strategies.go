package cvelist2osv

import (
	"log/slog"
	"slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/google/osv/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// VersionExtractor defines the interface for different version extraction strategies.
type VersionExtractor interface {
	ExtractVersions(cve cves.CVE5, v *vulns.Vulnerability, metrics *ConversionMetrics, repos []string)
	FindNormalAffectedRanges(affected cves.Affected, metrics *ConversionMetrics) ([]osvschema.Range, VersionRangeType)
}

// VersionExtractorFactory creates a VersionExtractor based on the CNA.
type VersionExtractorFactory struct{}

// GetVersionExtractor returns the appropriate VersionExtractor for a given CNA.
func (f *VersionExtractorFactory) GetVersionExtractor(cna string) VersionExtractor {
	switch cna {
	case "Linux":
		return &LinuxVersionExtractor{}
	default:
		return &DefaultVersionExtractor{}
	}
}

func cpeVersionExtraction(cve cves.CVE5, metrics *ConversionMetrics) ([]osvschema.Range, error) {
	cpeRanges, cpeStrings, err := findCPEVersionRanges(cve)
	if err == nil && len(cpeRanges) > 0 {
		metrics.VersionSources = append(metrics.VersionSources, VersionSourceCPE)
		metrics.CPEs = vulns.Unique(cpeStrings)
		return cpeRanges, nil
	} else if err != nil {
		metrics.AddNote("%s", err.Error())
	}
	return nil, err
}

// fallbackVersionExtraction is a helper function for CPE and description extraction.
func fallbackVersionExtraction(cve cves.CVE5, metrics *ConversionMetrics) []osvschema.Range {
	// As a last resort, try extracting versions from the description text.
	versions, extractNotes := cves.ExtractVersionsFromText(nil, cves.EnglishDescription(cve.Containers.CNA.Descriptions))
	for _, note := range extractNotes {
		metrics.AddNote("%s", note)
	}
	if len(versions) > 0 {
		// NOTE: These versions are not currently saved due to the need for better validation.
		metrics.VersionSources = append(metrics.VersionSources, VersionSourceDescription)
		metrics.AddNote("Extracted versions from description but did not save them: %+v", versions)
	}
	return []osvschema.Range{}
}

// DefaultVersionExtractor provides the default version extraction logic.
type DefaultVersionExtractor struct{}

// ExtractVersions for DefaultVersionExtractor.
func (d *DefaultVersionExtractor) ExtractVersions(cve cves.CVE5, v *vulns.Vulnerability, metrics *ConversionMetrics, repos []string) {
	gotVersions := false
	affected := combineAffected(cve)
	repoTagsCache := git.RepoTagsCache{}
	for _, cveAff := range affected {
		versionRanges, _ := d.FindNormalAffectedRanges(cveAff, metrics)

		if len(versionRanges) == 0 {
			continue
		}

		gotVersions = true

		aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
		if err != nil {
			logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
		}

		v.Affected = append(v.Affected, aff)
		metrics.VersionSources = append(metrics.VersionSources, VersionSourceAffected)
	}

	if !gotVersions {
		metrics.AddNote("No versions in affected, attempting to extract from CPE")
		versionRanges, _ := cpeVersionExtraction(cve, metrics)

		if len(versionRanges) != 0 {
			gotVersions = true
			aff, err := gitVersionsToCommits(cve.Metadata.CVEID, versionRanges, repos, metrics, repoTagsCache)
			if err != nil {
				logger.Error("Failed to convert git versions to commits", slog.Any("err", err))
			}

			v.Affected = append(v.Affected, aff)
		}
	}

	// if !gotVersions {
	// 	metrics.AddNote("No versions in CPEs so attempting extraction from description")
	// 	versionRanges, err := fallbackVersionExtraction(cve, metrics)
	// }

}

func (d *DefaultVersionExtractor) FindNormalAffectedRanges(affected cves.Affected, metrics *ConversionMetrics) ([]osvschema.Range, VersionRangeType) {
	var unpairedIntroduced, unpairedFixed, unpairedLastAffected []string
	var versionRanges []osvschema.Range
	for _, vers := range affected.Versions {
		if vers.Status != "affected" {
			continue
		}

		currentVersionType := toVersionRangeType(vers.VersionType)

		// Quality check the version strings to avoid using filler content.
		vQuality := vulns.CheckQuality(vers.Version)
		vLessThanQual := vulns.CheckQuality(vers.LessThan)
		vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

		hasIntro := vQuality.AtLeast(acceptableQuality)
		hasFixed := vLessThanQual.AtLeast(acceptableQuality)
		hasLastAffected := vLTOEQual.AtLeast(acceptableQuality)

		// Handle self-contained ranges first.
		if hasIntro && (hasFixed || hasLastAffected) {
			if hasFixed {
				versionRanges = append(versionRanges, buildVersionRange(vers.Version, "", vers.LessThan))
				metrics.AddNote("Found self-contained range: introduced=%s, fixed=%s", vers.Version, vers.LessThan)
			} else {
				versionRanges = append(versionRanges, buildVersionRange(vers.Version, vers.LessThanOrEqual, ""))
				metrics.AddNote("Found self-contained range: introduced=%s, last_affected=%s", vers.Version, vers.LessThanOrEqual)
			}
			continue
		}

		// Collect parts of potential split ranges.
		if hasIntro {
			unpairedIntroduced = append(unpairedIntroduced, vers.Version)
		}
		if hasFixed {
			unpairedFixed = append(unpairedFixed, vers.LessThan)
		}
		if hasLastAffected {
			unpairedLastAffected = append(unpairedLastAffected, vers.LessThanOrEqual)
		}

		// Handle GitHub/GitLab style ranges encoded in the version string.
		av, err := git.ParseVersionRange(vers.Version)
		if err == nil {
			if av.Introduced == "" {
				continue
			}
			if av.Fixed != "" {
				versionRanges = append(versionRanges, buildVersionRange(av.Introduced, "", av.Fixed))
			} else if av.LastAffected != "" {
				versionRanges = append(versionRanges, buildVersionRange(av.Introduced, av.LastAffected, ""))
			}
			// This was a self-contained range, so remove from unpaired.
			unpairedIntroduced = slices.DeleteFunc(unpairedIntroduced, func(s string) bool { return s == vers.Version })
			continue
		}

		if currentVersionType == VersionRangeTypeGit {
			versionRanges = append(versionRanges, buildVersionRange(vers.Version, "", ""))
			// This was a self-contained range, so remove from unpaired.
			unpairedIntroduced = slices.DeleteFunc(unpairedIntroduced, func(s string) bool { return s == vers.Version })
		}
	}

	// Attempt to pair up collected versions for split ranges.
	// For now, we handle the simple case of one of each.
	if len(unpairedIntroduced) == 1 && len(unpairedFixed) == 1 {
		versionRanges = append(versionRanges, buildVersionRange(unpairedIntroduced[0], "", unpairedFixed[0]))
		metrics.AddNote("Formed split range: introduced=%s, fixed=%s", unpairedIntroduced[0], unpairedFixed[0])
		unpairedIntroduced, unpairedFixed = nil, nil // Clear them as they are now used.
	}
	if len(unpairedIntroduced) == 1 && len(unpairedLastAffected) == 1 {
		versionRanges = append(versionRanges, buildVersionRange(unpairedIntroduced[0], unpairedLastAffected[0], ""))
		metrics.AddNote("Formed split range: introduced=%s, last_affected=%s", unpairedIntroduced[0], unpairedLastAffected[0])
		unpairedIntroduced, unpairedLastAffected = nil, nil // Clear them as they are now used.
	}

	// Fallback for remaining single versions.
	for _, version := range unpairedIntroduced {
		versionRanges = append(versionRanges, buildVersionRange("0", version, ""))
		metrics.AddNote("Single version found %v - Assuming introduced = 0 and last affected = %v", version, version)
	}

	return versionRanges, VersionRangeTypeUnknown
}

// LinuxVersionExtractor provides the version extraction logic for Linux kernel CVEs.
type LinuxVersionExtractor struct {
	DefaultVersionExtractor
}

// ExtractVersions for LinuxVersionExtractor.
func (l *LinuxVersionExtractor) ExtractVersions(cve cves.CVE5, v *vulns.Vulnerability, metrics *ConversionMetrics, repos []string) {
	gotVersions := false
	affected := combineAffected(cve)

	hasGit := false
	for _, cveAff := range affected {
		var versionRanges []osvschema.Range
		var versionType VersionRangeType
		if cveAff.DefaultStatus == "affected" {
			versionRanges, versionType = findInverseAffectedRanges(cveAff, cve.Metadata.AssignerShortName, metrics)
		} else {
			versionRanges, versionType = l.FindNormalAffectedRanges(cveAff, metrics)
		}
		if versionType == VersionRangeTypeGit && hasGit {
			continue
		}

		if len(versionRanges) == 0 {
			continue
		}

		gotVersions = true
		if versionType == VersionRangeTypeGit {
			hasGit = true
		}

		var aff osvschema.Affected
		for _, vr := range versionRanges {
			if versionType == VersionRangeTypeGit {
				vr.Type = osvschema.RangeGit
				vr.Repo = cveAff.Repo
			} else {
				vr.Type = osvschema.RangeEcosystem
			}
			aff.Ranges = append(aff.Ranges, vr)
		}
		if versionType != VersionRangeTypeGit {
			aff.Package = osvschema.Package{
				Ecosystem: string(osvschema.EcosystemLinux),
				Name:      "Kernel",
			}
		}

		v.Affected = append(v.Affected, aff)
		metrics.VersionSources = append(metrics.VersionSources, VersionSourceAffected)
	}

	if !gotVersions {
		fallbackVersionExtraction(cve, metrics)
	}
}

func (d *LinuxVersionExtractor) FindNormalAffectedRanges(affected cves.Affected, metrics *ConversionMetrics) ([]osvschema.Range, VersionRangeType) {
	var unpairedIntroduced, unpairedFixed, unpairedLastAffected []string
	var versionRanges []osvschema.Range
	for _, vers := range affected.Versions {
		if vers.Status != "affected" {
			continue
		}

		currentVersionType := toVersionRangeType(vers.VersionType)

		// Quality check the version strings to avoid using filler content.
		vQuality := vulns.CheckQuality(vers.Version)
		vLessThanQual := vulns.CheckQuality(vers.LessThan)
		vLTOEQual := vulns.CheckQuality(vers.LessThanOrEqual)

		hasIntro := vQuality.AtLeast(acceptableQuality)
		hasFixed := vLessThanQual.AtLeast(acceptableQuality)
		hasLastAffected := vLTOEQual.AtLeast(acceptableQuality)

		// Handle self-contained ranges first.
		if hasIntro && (hasFixed || hasLastAffected) {
			if hasFixed {
				versionRanges = append(versionRanges, buildVersionRange(vers.Version, "", vers.LessThan))
				metrics.AddNote("Found self-contained range: introduced=%s, fixed=%s", vers.Version, vers.LessThan)
			} else {
				versionRanges = append(versionRanges, buildVersionRange(vers.Version, vers.LessThanOrEqual, ""))
				metrics.AddNote("Found self-contained range: introduced=%s, last_affected=%s", vers.Version, vers.LessThanOrEqual)
			}
			continue
		}

		// Collect parts of potential split ranges.
		if hasIntro {
			unpairedIntroduced = append(unpairedIntroduced, vers.Version)
		}
		if hasFixed {
			unpairedFixed = append(unpairedFixed, vers.LessThan)
		}
		if hasLastAffected {
			unpairedLastAffected = append(unpairedLastAffected, vers.LessThanOrEqual)
		}

		// Handle GitHub/GitLab style ranges encoded in the version string.
		av, err := git.ParseVersionRange(vers.Version)
		if err == nil {
			if av.Introduced == "" {
				continue
			}
			if av.Fixed != "" {
				versionRanges = append(versionRanges, buildVersionRange(av.Introduced, "", av.Fixed))
			} else if av.LastAffected != "" {
				versionRanges = append(versionRanges, buildVersionRange(av.Introduced, av.LastAffected, ""))
			}
			// This was a self-contained range, so remove from unpaired.
			unpairedIntroduced = slices.DeleteFunc(unpairedIntroduced, func(s string) bool { return s == vers.Version })
			continue
		}

		if currentVersionType == VersionRangeTypeGit {
			versionRanges = append(versionRanges, buildVersionRange(vers.Version, "", ""))
			// This was a self-contained range, so remove from unpaired.
			unpairedIntroduced = slices.DeleteFunc(unpairedIntroduced, func(s string) bool { return s == vers.Version })
		}
	}

	// Attempt to pair up collected versions for split ranges.
	// For now, we handle the simple case of one of each.
	if len(unpairedIntroduced) == 1 && len(unpairedFixed) == 1 {
		versionRanges = append(versionRanges, buildVersionRange(unpairedIntroduced[0], "", unpairedFixed[0]))
		metrics.AddNote("Formed split range: introduced=%s, fixed=%s", unpairedIntroduced[0], unpairedFixed[0])
		unpairedIntroduced, unpairedFixed = nil, nil // Clear them as they are now used.
	}
	if len(unpairedIntroduced) == 1 && len(unpairedLastAffected) == 1 {
		versionRanges = append(versionRanges, buildVersionRange(unpairedIntroduced[0], unpairedLastAffected[0], ""))
		metrics.AddNote("Formed split range: introduced=%s, last_affected=%s", unpairedIntroduced[0], unpairedLastAffected[0])
		unpairedIntroduced, unpairedLastAffected = nil, nil // Clear them as they are now used.
	}

	// Fallback for remaining single versions.
	for _, version := range unpairedIntroduced {
		versionRanges = append(versionRanges, buildVersionRange("0", version, ""))
		metrics.AddNote("Single version found %v - Assuming introduced = 0 and last affected = %v", version, version)
	}

	return versionRanges, VersionRangeTypeGit
}
