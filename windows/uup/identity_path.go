package uup

import (
	"fmt"
	"path"
	"strings"
)

type ComponentPathIdentity struct {
	Identity AssemblyIdentity
	Stem     string
	Suffix   string
}

func ParsePackageManifestName(name string) (AssemblyIdentity, error) {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	if !strings.EqualFold(path.Ext(base), ".mum") {
		return AssemblyIdentity{}, fmt.Errorf("uup servicing: %q is not a package manifest", name)
	}
	parts := strings.Split(strings.TrimSuffix(base, path.Ext(base)), "~")
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[4] == "" {
		return AssemblyIdentity{}, fmt.Errorf("uup servicing: invalid package manifest name %q", name)
	}
	language := parts[3]
	if language == "" {
		language = "neutral"
	}
	return AssemblyIdentity{
		Name: parts[0], PublicKeyToken: parts[1], ProcessorArchitecture: parts[2],
		Language: language, Version: parts[4], BuildType: "release",
	}, nil
}

func ParseComponentManifestName(name string) (ComponentPathIdentity, error) {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	extension := path.Ext(base)
	if !strings.EqualFold(extension, ".manifest") {
		return ComponentPathIdentity{}, fmt.Errorf("uup servicing: %q is not a component manifest", name)
	}
	return parseComponentStem(strings.TrimSuffix(base, extension))
}

func ParseComponentContentName(name string) (ComponentPathIdentity, string, error) {
	cleaned := strings.TrimPrefix(strings.ReplaceAll(name, "/", "\\"), "\\")
	separator := strings.IndexByte(cleaned, '\\')
	if separator <= 0 || separator == len(cleaned)-1 {
		return ComponentPathIdentity{}, "", fmt.Errorf("uup servicing: invalid component content name %q", name)
	}
	identity, err := parseComponentStem(cleaned[:separator])
	if err != nil {
		return ComponentPathIdentity{}, "", err
	}
	return identity, cleaned[separator+1:], nil
}

func parseComponentStem(stem string) (ComponentPathIdentity, error) {
	parts := strings.Split(stem, "_")
	if len(parts) < 6 {
		return ComponentPathIdentity{}, fmt.Errorf("uup servicing: invalid component identity %q", stem)
	}
	name := strings.Join(parts[1:len(parts)-4], "_")
	if parts[0] == "" || name == "" || parts[len(parts)-4] == "" || parts[len(parts)-3] == "" || parts[len(parts)-1] == "" {
		return ComponentPathIdentity{}, fmt.Errorf("uup servicing: invalid component identity %q", stem)
	}
	language := parts[len(parts)-2]
	if language == "" || strings.EqualFold(language, "none") {
		language = "neutral"
	}
	return ComponentPathIdentity{
		Identity: AssemblyIdentity{
			Name: name, PublicKeyToken: parts[len(parts)-4], Version: parts[len(parts)-3],
			Language: language, ProcessorArchitecture: parts[0], BuildType: "release",
		},
		Stem: stem, Suffix: parts[len(parts)-1],
	}, nil
}

func (i ComponentPathIdentity) FamilyKey() string {
	return strings.ToLower(strings.Join([]string{i.Identity.ProcessorArchitecture, i.Identity.Name, i.Identity.PublicKeyToken, i.Identity.Language}, "\x00"))
}

func componentPathMayMatch(candidate ComponentPathIdentity, wanted AssemblyIdentity) bool {
	if !strings.EqualFold(candidate.Identity.ProcessorArchitecture, wanted.ProcessorArchitecture) ||
		!strings.EqualFold(candidate.Identity.PublicKeyToken, wanted.PublicKeyToken) ||
		!strings.EqualFold(candidate.Identity.Version, wanted.Version) ||
		!sameManifestLanguage(candidate.Identity.Language, wanted.Language) {
		return false
	}
	candidateName := componentPathName(candidate.Identity.Name)
	wantedName := componentPathName(wanted.Name)
	if split := strings.Index(candidateName, ".."); split >= 0 {
		suffix := split + 2
		for suffix < len(candidateName) && candidateName[suffix] == '.' {
			suffix++
		}
		return strings.HasPrefix(wantedName, candidateName[:split]) && strings.HasSuffix(wantedName, candidateName[suffix:])
	}
	return candidateName == wantedName
}

// CBS component-store names remove display punctuation from assembly identity
// names before applying the middle-run abbreviation used by WinSxS paths.
// Existing identity separators such as hyphens remain significant.
func componentPathName(name string) string {
	return strings.Map(func(character rune) rune {
		switch character {
		case ' ', '(', ')':
			return -1
		default:
			return character
		}
	}, strings.ToLower(name))
}

func sameManifestLanguage(left, right string) bool {
	if left == "" {
		left = "neutral"
	}
	if right == "" {
		right = "neutral"
	}
	if right == "*" {
		return true
	}
	if strings.Contains(left, "..") {
		parts := strings.SplitN(strings.ToLower(left), "..", 2)
		lowerRight := strings.ToLower(right)
		return strings.HasPrefix(lowerRight, parts[0]) && strings.HasSuffix(lowerRight, parts[1])
	}
	return strings.EqualFold(left, right)
}
