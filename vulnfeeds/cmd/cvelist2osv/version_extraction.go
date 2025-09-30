package cvelist2osv

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"slices"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/utility/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Examines repos and tries to convert versions to commits by treating them as Git tags.
// Takes a CVE ID string (for logging), VersionInfo with AffectedVersions and
// typically no AffectedCommits and attempts to add AffectedCommits (including Fixed commits) where there aren't any.
// Refuses to add the same commit to AffectedCommits more than once.
func gitVersionsToCommits(cveID cves.CVEID, versionRanges []osvschema.Range, repos []string, metrics *ConversionMetrics, cache git.RepoTagsCache) (osvschema.Affected, error) {
	var newAff osvschema.Affected
	var newVersionRanges []osvschema.Range
	unresolvedRanges := versionRanges

	for _, repo := range repos {
		if len(unresolvedRanges) == 0 {
			break // All ranges have been resolved.
		}

		normalizedTags, err := git.NormalizeRepoTags(repo, cache)
		if err != nil {
			logger.Warn("Failed to normalize tags", slog.String("cve", string(cveID)), slog.String("repo", repo))
			metrics.AddNote("[%s]: Failed to normalize tags for %s", string(cveID), repo)
			continue
		}

		var stillUnresolvedRanges []osvschema.Range
		for _, vr := range unresolvedRanges {
			var introducedCommit, fixedCommit, lastAffectedCommit string
			var resolutionErr error

			for _, ev := range vr.Events {
				logger.Info("Attempting version resolution", slog.String("cve", string(cveID)), slog.Any("event", ev), slog.String("repo", repo))
				if ev.Introduced != "" {
					if ev.Introduced == "0" {
						introducedCommit = "0"
					} else {
						introducedCommit, resolutionErr = git.VersionToCommit(ev.Introduced, normalizedTags)
						if resolutionErr != nil {
							logger.Warn("Failed to get Git commit for introduced version", slog.String("cve", string(cveID)), slog.String("version", ev.Introduced), slog.String("repo", repo))
							metrics.AddNote("[%s]: Failed to get Git commit for introduced version %s - %s", string(cveID), ev.Introduced, repo)
						} else {
							logger.Info("Successfully derived commit for introduced version", slog.String("cve", string(cveID)), slog.String("commit", introducedCommit), slog.String("version", ev.Introduced))
							metrics.AddNote("[%s]: Successfully derived commit %s for introduced version %s", string(cveID), introducedCommit, ev.Introduced)
						}
					}
				}
				if ev.Fixed != "" {
					fixedCommit, resolutionErr = git.VersionToCommit(ev.Fixed, normalizedTags)
					if resolutionErr != nil {
						logger.Warn("Failed to get Git commit for fixed version", slog.String("cve", string(cveID)), slog.String("version", ev.Fixed), slog.String("repo", repo))
						metrics.AddNote("[%s]: Failed to get Git commit for fixed version %s - %s", string(cveID), ev.Fixed, repo)
					} else {
						logger.Info("Successfully derived commit for fixed version", slog.String("cve", string(cveID)), slog.String("commit", fixedCommit), slog.String("version", ev.Fixed))
						metrics.AddNote("[%s]: Successfully derived commit %s for fixed version %s", string(cveID), fixedCommit, ev.Fixed)
					}
				}
				if ev.LastAffected != "" {
					lastAffectedCommit, resolutionErr = git.VersionToCommit(ev.LastAffected, normalizedTags)
					if resolutionErr != nil {
						logger.Warn("Failed to get Git commit for last affected version", slog.String("cve", string(cveID)), slog.String("version", ev.LastAffected), slog.String("repo", repo))
						metrics.AddNote("[%s]: Failed to get Git commit for last affected version %s - %s", string(cveID), ev.LastAffected, repo)
					} else {
						logger.Info("Successfully derived commit for last affected version", slog.String("cve", string(cveID)), slog.String("commit", lastAffectedCommit), slog.String("version", ev.LastAffected))
						metrics.AddNote("[%s]: Successfully derived commit %s for last affected version %s", string(cveID), lastAffectedCommit, ev.LastAffected)
					}
				}
			}

			resolved := false
			if fixedCommit != "" && introducedCommit != "" {
				newVR := buildVersionRange(introducedCommit, "", fixedCommit)
				newVR.Repo = repo
				newVR.Type = osvschema.RangeGit
				newVR.DatabaseSpecific = make(map[string]any)
				newVR.DatabaseSpecific["versions"] = vr.Events
				newVersionRanges = append(newVersionRanges, newVR)
				resolved = true
			} else if lastAffectedCommit != "" && introducedCommit != "" {
				newVR := buildVersionRange(introducedCommit, lastAffectedCommit, "")
				newVR.Repo = repo
				newVR.Type = osvschema.RangeGit
				newVR.DatabaseSpecific = make(map[string]any)
				newVR.DatabaseSpecific["versions"] = vr.Events
				newVersionRanges = append(newVersionRanges, newVR)
				resolved = true
			}

			if !resolved {
				stillUnresolvedRanges = append(stillUnresolvedRanges, vr)
			}
		}
		unresolvedRanges = stillUnresolvedRanges
	}

	var err error
	if len(unresolvedRanges) > 0 {
		newAff.DatabaseSpecific = make(map[string]any)
		newAff.DatabaseSpecific["unresolved_versions"] = unresolvedRanges
	}

	if len(newVersionRanges) > 0 {
		newAff.Ranges = newVersionRanges
	} else if len(unresolvedRanges) > 0 { // Only error if there were ranges to resolve but none were.
		err = errors.New("was not able to get git version ranges")
	}

	return newAff, err
}

// findInverseAffectedRanges calculates the affected version ranges by analyzing a list
// of 'unaffected' versions. This is common in Linux kernel CVEs where a product is
// considered affected by default, and only unaffected versions are listed.
// It sorts the introduced and fixed versions to create chronological ranges.
func findInverseAffectedRanges(cveAff cves.Affected, cnaAssigner string, metrics *ConversionMetrics) (ranges []osvschema.Range, versType VersionRangeType) {
	if cnaAssigner != "Linux" {
		metrics.AddNote("Currently only supporting Linux inverse logic")
		return nil, VersionRangeTypeUnknown
	}
	var introduced []string
	fixed := make([]string, 0, len(cveAff.Versions))
	for _, vers := range cveAff.Versions {
		versionValue := vers.Version
		if vers.Status == "affected" {
			numParts := len(strings.Split(versionValue, "."))
			switch numParts {
			case 2:
				introduced = append(introduced, versionValue+".0")
			case 3:
				introduced = append(introduced, versionValue)
			default:
				metrics.AddNote("Bad non-semver version given: %s", versionValue)
				continue
			}
		}
		if vers.Status != "unaffected" {
			continue
		}

		if versionValue == "0" || toVersionRangeType(vers.VersionType) != VersionRangeTypeSemver {
			continue
		}
		fixed = append(fixed, versionValue)
		// Infer the next introduced version from the 'lessThanOrEqual' field.
		// For example, if "5.10.*" is unaffected, the next introduced version is "5.11.0".
		minorVers := strings.Split(vers.LessThanOrEqual, ".*")[0]
		parts := strings.Split(minorVers, ".")
		if len(parts) > 1 {
			if intMin, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				nextIntroduced := fmt.Sprintf("%s.%d.0", parts[0], intMin+1)
				introduced = append(introduced, nextIntroduced)
			}
		}
	}
	slices.SortFunc(introduced, compareSemverLike)
	slices.SortFunc(fixed, compareSemverLike)

	// If the first fixed version is earlier than the first introduced, assume introduction from "0".
	if len(fixed) > 0 && len(introduced) > 0 && compareSemverLike(fixed[0], introduced[0]) < 0 {
		introduced = append([]string{"0"}, introduced...)
	}

	// Create ranges by pairing sorted introduced and fixed versions.
	for index, f := range fixed {
		if index < len(introduced) {
			ranges = append(ranges, buildVersionRange(introduced[index], "", f))
			metrics.AddNote("Introduced from version value - %s", introduced[index])
			metrics.AddNote("Fixed from version value - %s", f)
		}
	}

	if len(ranges) != 0 {
		return ranges, VersionRangeTypeSemver
	}
	metrics.AddNote("no ranges found")

	return nil, VersionRangeTypeUnknown
}
