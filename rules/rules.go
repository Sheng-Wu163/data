// Package rules loads banner fingerprint rules from a JSON document.
//
// Rules are intentionally kept as data, not code, so that fingerprint coverage
// can evolve without recompiling the binaries. A curated default rule set is
// embedded into the binary; setting RULES_PATH loads an external file instead,
// which is how the Docker deployment injects the rule set (mounted read-only).
package rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

//go:embed rules.json
var defaultRules []byte

// OSRule maps a banner fragment to an operating-system hint.
type OSRule struct {
	Regex string `json:"regex"`
	OS    string `json:"os"`
	re    *regexp.Regexp
}

// Rule is a single fingerprint definition. A rule matches a banner when all
// RequireAll patterns match and at least one RequireAny pattern matches (when
// RequireAny is non-empty). Higher Priority rules are evaluated first.
type Rule struct {
	Name           string   `json:"name"`
	Protocol       string   `json:"protocol"`
	Priority       int      `json:"priority"`
	RequireAll     []string `json:"require_all"`
	RequireAny     []string `json:"require_any"`
	ProductDefault string   `json:"product_default"`
	ProductRegex   string   `json:"product_regex"`
	VersionRegex   string   `json:"version_regex"`
	OSRules        []OSRule `json:"os_rules"`
	Confidence     float64  `json:"confidence"`

	requireAll []*regexp.Regexp
	requireAny []*regexp.Regexp
	productRe  *regexp.Regexp
	versionRe  *regexp.Regexp
}

// Set is the top-level rules document.
type Set struct {
	Version           int     `json:"version"`
	UnknownConfidence float64 `json:"unknown_confidence"`
	Rules             []Rule  `json:"rules"`
}

// Load reads and compiles a rule set. When path is empty the embedded default
// rule set is used. Rules are compiled and sorted by descending priority so
// the engine can evaluate them in order.
func Load(path string) (*Set, error) {
	raw := defaultRules
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rules file %q: %w", path, err)
		}
		raw = b
	}

	var s Set
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if len(s.Rules) == 0 {
		return nil, fmt.Errorf("rules set is empty")
	}
	for i := range s.Rules {
		if err := s.Rules[i].compile(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", s.Rules[i].Name, err)
		}
	}
	sort.SliceStable(s.Rules, func(i, j int) bool {
		return s.Rules[i].Priority > s.Rules[j].Priority
	})
	return &s, nil
}

func (r *Rule) compile() error {
	var err error
	if r.requireAll, err = compileAll(r.RequireAll); err != nil {
		return err
	}
	if r.requireAny, err = compileAll(r.RequireAny); err != nil {
		return err
	}
	if r.ProductRegex != "" {
		if r.productRe, err = regexp.Compile(r.ProductRegex); err != nil {
			return fmt.Errorf("product_regex: %w", err)
		}
	}
	if r.VersionRegex != "" {
		if r.versionRe, err = regexp.Compile(r.VersionRegex); err != nil {
			return fmt.Errorf("version_regex: %w", err)
		}
	}
	for i := range r.OSRules {
		if r.OSRules[i].Regex == "" {
			continue
		}
		re, err := regexp.Compile(r.OSRules[i].Regex)
		if err != nil {
			return fmt.Errorf("os_rules[%d]: %w", i, err)
		}
		r.OSRules[i].re = re
	}
	return nil
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Matches reports whether the banner satisfies the rule's conditions.
func (r *Rule) Matches(banner string) bool {
	for _, re := range r.requireAll {
		if !re.MatchString(banner) {
			return false
		}
	}
	if len(r.requireAny) > 0 {
		matched := false
		for _, re := range r.requireAny {
			if re.MatchString(banner) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// ExtractProduct returns the first capture group of ProductRegex, falling back
// to ProductDefault.
func (r *Rule) ExtractProduct(banner string) string {
	if r.productRe != nil {
		if m := r.productRe.FindStringSubmatch(banner); len(m) > 1 {
			return m[1]
		}
	}
	return r.ProductDefault
}

// ExtractVersion returns the first capture group of VersionRegex, or "".
func (r *Rule) ExtractVersion(banner string) string {
	if r.versionRe != nil {
		if m := r.versionRe.FindStringSubmatch(banner); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// ExtractOS returns the OS hint from the first matching OS rule, or "".
func (r *Rule) ExtractOS(banner string) string {
	for i := range r.OSRules {
		if r.OSRules[i].re != nil && r.OSRules[i].re.MatchString(banner) {
			return r.OSRules[i].OS
		}
	}
	return ""
}
