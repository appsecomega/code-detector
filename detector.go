// Package main — language-agnostic detector + Veracode pipeline gate.
//
// Go equivalent of code_detector.py:
//
//	has_code (agnostic, any language) vs veracode_scannable (SAST gate).
//
// Stdlib-only, no external dependencies.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// 1. Extension -> language map (agnostic, broad)
// ---------------------------------------------------------------------------

var extToLang = map[string]string{
	".py": "Python", ".pyw": "Python", ".pyx": "Python", ".pxd": "Python",
	".ipynb": "Python",
	".js":    "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
	".ts": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".tsx": "TypeScript",
	".vue": "Vue", ".svelte": "Svelte", ".astro": "Astro",
	".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
	".groovy": "Groovy", ".gradle": "Gradle", ".clj": "Clojure", ".cljs": "Clojure",
	".cs": "C#", ".vb": "VB.NET", ".fs": "F#", ".fsx": "F#",
	".c": "C", ".h": "C/C++ Header", ".cpp": "C++", ".hpp": "C++",
	".cc": "C++", ".hh": "C++", ".cxx": "C++", ".hxx": "C++",
	".m": "Objective-C", ".mm": "Objective-C++",
	".rs": "Rust", ".go": "Go", ".swift": "Swift",
	".d": "D", ".nim": "Nim", ".zig": "Zig", ".v": "V",
	".dart": "Dart", ".lua": "Lua",
	".rb": "Ruby", ".php": "PHP", ".pl": "Perl", ".pm": "Perl",
	".sh": "Shell", ".bash": "Shell", ".zsh": "Shell", ".ksh": "Shell",
	".ps1": "PowerShell", ".psm1": "PowerShell",
	".r": "R", ".jl": "Julia", ".hs": "Haskell", ".ml": "OCaml",
	".mli": "OCaml", ".elm": "Elm", ".erl": "Erlang", ".hrl": "Erlang",
	".ex": "Elixir", ".exs": "Elixir",
	".sol": "Solidity", ".cob": "COBOL", ".cbl": "COBOL",
	".pas": "Pascal", ".pp": "Pascal", ".adb": "Ada", ".ads": "Ada",
	".f": "Fortran", ".f90": "Fortran", ".f95": "Fortran", ".for": "Fortran",
	".asm": "Assembly", ".s": "Assembly", ".nasm": "Assembly",
	".jsp": "Java/JSP", ".jspx": "Java/JSP", ".asp": "ASP", ".aspx": "ASP.NET",
	".erb": "Ruby/ERB", ".haml": "Ruby/Haml", ".ejs": "JavaScript/EJS",
	".twig": "PHP/Twig",
	".html": "HTML", ".htm": "HTML",
	".css": "CSS", ".scss": "SCSS", ".sass": "Sass", ".less": "Less",
	".sql": "SQL", ".psql": "SQL", ".tf": "Terraform", ".rego": "Rego",
	".apex": "Apex", ".cls": "Apex",
}

// ---------------------------------------------------------------------------
// 1b. Veracode SAST criteria — languages that produce a module
// ---------------------------------------------------------------------------

var veracodeSupportedLangs = map[string]bool{
	"Python":     true,
	"JavaScript": true, "TypeScript": true, "Vue": true,
	"Java": true, "Kotlin": true, "Scala": true, "Groovy": true, "Clojure": true,
	"C#": true, "VB.NET": true, "F#": true,
	"C": true, "C++": true, "C/C++ Header": true,
	"Objective-C": true, "Objective-C++": true,
	"Go": true, "Rust": true, "Swift": true, "Dart": true,
	"Ruby": true, "PHP": true, "Perl": true,
	"Java/JSP": true, "ASP": true, "ASP.NET": true,
	"Ruby/ERB": true, "Ruby/Haml": true, "JavaScript/EJS": true,
	"PHP/Twig": true, "PHP/Blade": true,
	"Apex":  true,
	"COBOL": true,
}

var veracodeArtifactExts = map[string]bool{
	".jar": true, ".war": true, ".ear": true, ".jpi": true, ".hpi": true,
	".dll": true, ".exe": true,
	".apk": true, ".aab": true, ".aar": true,
	".so": true, ".lib": true,
	".class": true,
}

// ---------------------------------------------------------------------------
// 2. Manifests / SBOM / config
// ---------------------------------------------------------------------------

var manifestFilenames = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"bun.lockb": true, ".npmrc": true,
	"requirements.txt": true, "requirements-dev.txt": true, "requirements.in": true,
	"pipfile": true, "pipfile.lock": true, "poetry.lock": true, "pyproject.toml": true,
	"setup.py": true, "setup.cfg": true, "pdm.lock": true, "conda.yml": true, "environment.yml": true,
	"pom.xml": true, "settings.gradle": true, "settings.gradle.kts": true, "gradle.properties": true,
	"build.gradle": true, "build.gradle.kts": true,
	"gemfile": true, "gemfile.lock": true,
	"composer.json": true, "composer.lock": true,
	"go.mod": true, "go.sum": true, "cargo.toml": true, "cargo.lock": true,
	"packages.config": true, "nuget.config": true,
	"dockerfile": true, "containerfile": true, "vcpkg.json": true, "conanfile.txt": true, "conanfile.py": true,
	"bower.json": true, ".bowerrc": true,
}

var manifestGlobs = []string{
	"*.csproj", "*.vbproj", "*.fsproj", "*.sln", "*.nuspec",
	"gemfile*", "dockerfile*", "containerfile*",
	"requirements*.txt", "constraints*.txt",
}

var sbomFilenames = map[string]bool{
	"bom.json": true, "bom.xml": true, "sbom.json": true, "sbom.xml": true,
	"cyclonedx.json": true, "cyclonedx.xml": true,
	"spdx.json": true, "spdx.xml": true,
}

var sbomGlobs = []string{
	"*.cdx.json", "*.cdx.xml",
	"*.spdx.json", "*.spdx", "*.spdx.yml", "*.spdx.yaml",
	"*sbom*.json", "*sbom*.xml", "*bom*.json", "*bom*.xml",
}

var sbomContentMarkers = []string{
	"cyclonedx", "bom-format", "spdxid", "spdxversion",
	"\"bomformat\"", "spdx-2.", "documentdescribes",
}

// ---------------------------------------------------------------------------
// 3. Ignored
// ---------------------------------------------------------------------------

var ignoreDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, ".bzr": true,
	"node_modules": true, "bower_components": true, "jspm_packages": true,
	".venv": true, "venv": true, "env": true, ".env": true, "__pycache__": true, ".tox": true, ".nox": true,
	"site-packages": true, ".mypy_cache": true, ".pytest_cache": true, ".ruff_cache": true,
	"vendor": true, "third_party": true, "third-party": true,
	"target": true, "build": true, "dist": true, "out": true, "bin": true, "obj": true,
	".gradle": true, ".idea": true, ".vscode": true, ".vs": true,
	"coverage": true, ".coverage": true, ".nyc_output": true,
	"pods": true, "carthage": true,
}

var ignoreFileGlobs = []string{
	"*.min.js", "*.min.css", "*.bundle.js", "*.bundle.css",
	"*.map", "*.d.ts",
}

const (
	maxFileBytes     = 5 * 1024 * 1024
	maxFilesToScan   = 50000
	minCodeLinesDflt = 1
)

var hashCommentLangs = map[string]bool{
	"Python": true, "Ruby": true, "Perl": true, "Shell": true, "R": true,
	"Julia": true, "PHP": true, "PowerShell": true, "YAML": true,
	"Makefile": true, "Ruby/ERB": true, "Ruby/Haml": true,
}

var slashCommentLangs = map[string]bool{
	"JavaScript": true, "TypeScript": true, "Java": true, "Kotlin": true,
	"Scala": true, "C": true, "C++": true, "C/C++ Header": true, "C#": true,
	"Go": true, "Rust": true, "Swift": true, "Dart": true,
	"Solidity": true, "Groovy": true, "Objective-C": true, "Objective-C++": true,
}

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

// CodeFile describes a source file with real content.
type CodeFile struct {
	Path              string `json:"path"`
	Language          string `json:"language"`
	CodeLines         int    `json:"code_lines"`
	VeracodeSupported bool   `json:"veracode_supported"`
}

// Analysis is the scan result, ready for the pipeline to decide scan vs skip.
type Analysis struct {
	Root              string         `json:"root"`
	HasCode           bool           `json:"has_code"`
	VeracodeScannable bool           `json:"veracode_scannable"`
	Category          string         `json:"category"`
	Languages         map[string]int `json:"languages"`
	VeracodeLanguages map[string]int `json:"veracode_languages"`
	CodeFiles         []CodeFile     `json:"code_files"`
	ManifestFiles     []string       `json:"manifest_files"`
	SbomFiles         []string       `json:"sbom_files"`
	ArtifactFiles     []string       `json:"artifact_files"`
	TotalFilesSeen    int            `json:"total_files_seen"`
	Reason            string         `json:"reason"`
	Action            string         `json:"action"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func globMatch(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	if err != nil {
		return false
	}
	return ok
}

func anyGlobMatch(globs []string, name string) bool {
	for _, g := range globs {
		if globMatch(g, name) {
			return true
		}
	}
	return false
}

func isManifest(nameLower string) bool {
	if manifestFilenames[nameLower] {
		return true
	}
	return anyGlobMatch(manifestGlobs, nameLower)
}

func looksLikeSbomName(nameLower string) bool {
	if sbomFilenames[nameLower] {
		return true
	}
	return anyGlobMatch(sbomGlobs, nameLower)
}

// IsSbomFile detects an SBOM by typical name OR CycloneDX/SPDX content.
func IsSbomFile(fp string) bool {
	if looksLikeSbomName(strings.ToLower(filepath.Base(fp))) {
		return true
	}
	ext := strings.ToLower(filepath.Ext(fp))
	switch ext {
	case ".json", ".xml", ".yml", ".yaml", ".spdx", ".txt":
	default:
		return false
	}
	st, err := os.Stat(fp)
	if err != nil || st.Size() > 2*1024*1024 {
		return false
	}
	f, err := os.Open(fp)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 8192)
	n, _ := f.Read(head)
	head = head[:n]
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	txt := strings.ToLower(string(head))
	for _, m := range sbomContentMarkers {
		if strings.Contains(txt, m) {
			return true
		}
	}
	return false
}

// LangForFile maps a file to its language by extension (compound .blade.php included).
func LangForFile(fp string) (string, bool) {
	nl := strings.ToLower(filepath.Base(fp))
	if strings.HasSuffix(nl, ".blade.php") {
		return "PHP/Blade", true
	}
	ext := strings.ToLower(filepath.Ext(fp))
	if l, ok := extToLang[ext]; ok {
		return l, true
	}
	return "", false
}

func isIgnoredFile(fp string) bool {
	return anyGlobMatch(ignoreFileGlobs, strings.ToLower(filepath.Base(fp)))
}

func looksBinary(sample []byte) bool {
	return bytes.IndexByte(sample, 0) >= 0
}

func shebangLanguage(firstLine string) (string, bool) {
	s := strings.ToLower(firstLine)
	if !strings.HasPrefix(s, "#!") {
		return "", false
	}
	mapping := map[string]string{
		"python": "Python", "node": "JavaScript", "deno": "TypeScript",
		"ruby": "Ruby", "php": "PHP", "perl": "Perl",
		"bash": "Shell", "sh": "Shell", "zsh": "Shell",
		"powershell": "PowerShell", "pwsh": "PowerShell",
		"rscript": "R", "julia": "Julia", "lua": "Lua",
	}
	for k, l := range mapping {
		if strings.Contains(s, k) {
			return l, true
		}
	}
	return "", false
}

// CountRealCodeLines counts lines with real content (skips blank and comment-only lines).
func CountRealCodeLines(file, language string) int {
	if strings.EqualFold(filepath.Ext(file), ".ipynb") {
		return ipynbCodeLines(file)
	}
	st, err := os.Stat(file)
	if err != nil || st.Size() == 0 || st.Size() > maxFileBytes {
		return 0
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	// Normalize \r\n -> \n and cap at 5000 lines.
	txt := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(txt, "\n")
	if len(lines) > 5000 {
		lines = lines[:5000]
	}
	if len(lines) == 0 {
		return 0
	}
	count := 0
	for _, raw := range lines {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if hashCommentLangs[language] && strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "#!") {
			continue
		}
		if slashCommentLangs[language] && strings.HasPrefix(s, "//") {
			continue
		}
		if len(strings.Fields(s)) <= 12 {
			if strings.HasPrefix(s, "--") || strings.HasPrefix(s, "%") || strings.HasPrefix(s, ";") {
				continue
			}
		}
		count++
		if count >= 50 {
			break
		}
	}
	return count
}

func ipynbCodeLines(file string) int {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	var nb struct {
		Cells []struct {
			CellType string      `json:"cell_type"`
			Source   interface{} `json:"source"`
		} `json:"cells"`
	}
	if err := json.Unmarshal(data, &nb); err != nil {
		return 0
	}
	n := 0
	for _, c := range nb.Cells {
		if c.CellType != "code" {
			continue
		}
		var lines []string
		switch v := c.Source.(type) {
		case string:
			lines = strings.Split(v, "\n")
		case []interface{}:
			for _, e := range v {
				if s, ok := e.(string); ok {
					lines = append(lines, strings.Split(s, "\n")...)
				}
			}
		}
		for _, l := range lines {
			t := strings.TrimSpace(l)
			if t != "" && !strings.HasPrefix(t, "#") {
				n++
				if n >= 50 {
					return n
				}
			}
		}
	}
	return n
}

func isIgnoredDirRel(rel string) bool {
	if rel == "." || rel == "" {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if ignoreDirs[part] || strings.HasPrefix(part, ".git") {
			return true
		}
	}
	return false
}

func iterCandidateFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p == root {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if isIgnoredDirRel(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		// File: skip broken symlinks.
		if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if _, err := os.Stat(p); err != nil {
				return nil
			}
		}
		out = append(out, p)
		if len(out) >= maxFilesToScan {
			return filepath.SkipAll
		}
		return nil
	})
	return out
}

func zipHasScannableInside(zipPath string) bool {
	z, err := zip.OpenReader(zipPath)
	if err != nil {
		return false
	}
	defer z.Close()
	checked := 0
	for _, f := range z.File {
		if checked >= 2000 {
			break
		}
		checked++
		nl := strings.ToLower(f.Name)
		if strings.Contains(nl, "node_modules/") || strings.Contains(nl, "venv/") || strings.Contains(nl, "__pycache__/") {
			continue
		}
		if strings.HasSuffix(nl, ".blade.php") {
			return true
		}
		ext := strings.ToLower(path.Ext(nl))
		if veracodeArtifactExts[ext] {
			return true
		}
		if l, ok := extToLang[ext]; ok && veracodeSupportedLangs[l] {
			return true
		}
	}
	return false
}

func relOrAbs(root, fp string) string {
	if r, err := filepath.Rel(root, fp); err == nil {
		return r
	}
	return fp
}

// ---------------------------------------------------------------------------
// Main API
// ---------------------------------------------------------------------------

// AnalyzeProject scans a folder, single file or archive and classifies it for the pipeline.
func AnalyzeProject(target string, minCodeLines int, useCloc bool) Analysis {
	if minCodeLines < 1 {
		minCodeLines = 1
	}
	fi, err := os.Stat(target)
	if err != nil {
		return Analysis{Root: target, HasCode: false, Category: "empty", Reason: "Path does not exist.", Action: "skip",
			Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
	}

	// ---- Archive (.zip/.tar/.tgz) -> extract to temp and analyze recursively ----
	if !fi.IsDir() && isArchiveName(target) {
		tmp, err := os.MkdirTemp("", "codedetect_")
		if err != nil {
			return Analysis{Root: target, Reason: "Failed to create temp dir: " + err.Error(), Action: "skip",
				Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		}
		defer os.RemoveAll(tmp)
		if err := extractArchive(target, tmp); err != nil {
			return Analysis{Root: target, Category: "non-scannable-only", Reason: err.Error(), Action: "skip",
				Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		}
		inner := AnalyzeProject(tmp, minCodeLines, useCloc)
		inner.Root = target
		return inner
	}

	// ---- Single file (non-archive) ----
	if !fi.IsDir() {
		ext := strings.ToLower(filepath.Ext(target))
		if veracodeArtifactExts[ext] {
			return Analysis{Root: target, HasCode: false, VeracodeScannable: true,
				Category: "artifact", ArtifactFiles: []string{filepath.Base(target)},
				TotalFilesSeen: 1, Action: "scan",
				Reason:    fmt.Sprintf("'%s' is a Veracode-scannable compiled artifact (no source, but produces a module).", filepath.Base(target)),
				Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		}
		if IsSbomFile(target) {
			return Analysis{Root: target, HasCode: false, Category: "sbom-only",
				SbomFiles: []string{filepath.Base(target)}, TotalFilesSeen: 1, Action: "skip",
				Reason:    fmt.Sprintf("'%s' is an SBOM (CycloneDX/SPDX) — produces no SAST module. Skip the upload.", filepath.Base(target)),
				Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		}
		lang, ok := LangForFile(target)
		if !ok {
			data, err := os.ReadFile(target)
			if err == nil {
				first := strings.SplitN(string(data), "\n", 2)[0]
				lang, ok = shebangLanguage(first)
			}
		}
		if !ok {
			if isManifest(strings.ToLower(filepath.Base(target))) {
				return Analysis{Root: target, Category: "manifest-only",
					ManifestFiles: []string{filepath.Base(target)}, TotalFilesSeen: 1, Action: "skip",
					Reason:    fmt.Sprintf("'%s' is a manifest/config file — no scannable code.", filepath.Base(target)),
					Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
			}
			return Analysis{Root: target, Category: "non-scannable-only", TotalFilesSeen: 1, Action: "skip",
				Reason:    fmt.Sprintf("'%s' is neither code nor artifact (likely doc/config/SBOM).", filepath.Base(target)),
				Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		}
		n := CountRealCodeLines(target, lang)
		has := n >= minCodeLines
		vsupp := veracodeSupportedLangs[lang]
		vscan := has && vsupp
		cat := "non-scannable-only"
		if vscan {
			cat = "code"
		} else if has {
			cat = "code-unsupported-by-veracode"
		}
		a := Analysis{Root: target, HasCode: has, VeracodeScannable: vscan,
			Category: cat, TotalFilesSeen: 1,
			Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		if has {
			a.Languages[lang] = 1
			a.CodeFiles = []CodeFile{{Path: target, Language: lang, CodeLines: n, VeracodeSupported: vsupp}}
		}
		if vscan {
			a.VeracodeLanguages[lang] = 1
		}
		if has {
			a.Reason = fmt.Sprintf("%s: %d real line(s) in '%s'", lang, n, filepath.Base(target))
			if !vsupp {
				a.Reason += " (language outside Veracode SAST)."
			}
		} else {
			a.Reason = fmt.Sprintf("'%s' is %s but empty/comment-only.", filepath.Base(target), lang)
		}
		if vscan {
			a.Action = "scan"
		} else {
			a.Action = "skip"
		}
		return a
	}

	// ---- Directory ----
	root := target
	var codeFiles []CodeFile
	var manifests, sboms, artifacts []string
	candidates := iterCandidateFiles(root)
	total := len(candidates)

	for _, fp := range candidates {
		if isIgnoredFile(fp) {
			continue
		}
		if IsSbomFile(fp) {
			sboms = append(sboms, relOrAbs(root, fp))
			continue
		}
		ext := strings.ToLower(filepath.Ext(fp))
		if veracodeArtifactExts[ext] {
			artifacts = append(artifacts, relOrAbs(root, fp))
			continue
		}
		if ext == ".zip" {
			if st, err := os.Stat(fp); err == nil && st.Size() < 500*1024*1024 {
				if zipHasScannableInside(fp) {
					artifacts = append(artifacts, relOrAbs(root, fp)+" (module container)")
					continue
				}
				continue
			}
		}
		if lang, ok := LangForFile(fp); ok {
			st, err := os.Stat(fp)
			if err != nil || st.Size() > maxFileBytes {
				continue
			}
			f, err := os.Open(fp)
			if err != nil {
				continue
			}
			head := make([]byte, 8192)
			n, _ := f.Read(head)
			f.Close()
			if looksBinary(head[:n]) {
				continue
			}
			if c := CountRealCodeLines(fp, lang); c >= minCodeLines {
				codeFiles = append(codeFiles, CodeFile{Path: relOrAbs(root, fp), Language: lang, CodeLines: c, VeracodeSupported: veracodeSupportedLangs[lang]})
			}
			continue
		}
		if isManifest(strings.ToLower(filepath.Base(fp))) {
			manifests = append(manifests, relOrAbs(root, fp))
			continue
		}
		if filepath.Ext(fp) == "" {
			st, err := os.Stat(fp)
			if err != nil || st.Size() >= 256*1024 {
				continue
			}
			data, err := os.ReadFile(fp)
			if err != nil || looksBinary(data) {
				continue
			}
			first := strings.SplitN(string(data), "\n", 2)[0]
			if shab, ok := shebangLanguage(first); ok {
				if c := CountRealCodeLines(fp, shab); c >= minCodeLines {
					codeFiles = append(codeFiles, CodeFile{Path: relOrAbs(root, fp), Language: shab, CodeLines: c, VeracodeSupported: veracodeSupportedLangs[shab]})
				}
			}
		}
	}

	langCount := map[string]int{}
	vlangCount := map[string]int{}
	for _, c := range codeFiles {
		langCount[c.Language]++
		if c.VeracodeSupported {
			vlangCount[c.Language]++
		}
	}
	has := len(codeFiles) > 0
	vscan := len(vlangCount) > 0 || len(artifacts) > 0

	var category, reason string
	switch {
	case total == 0:
		category = "empty"
		reason = "Empty directory or only ignored folders (third-party/build/.git)."
	case vscan:
		if len(vlangCount) > 0 {
			category = "code"
		} else {
			category = "artifact"
		}
		var parts []string
		if len(vlangCount) > 0 {
			parts = append(parts, fmt.Sprintf("%d file(s) %s", len(codeFiles), topLangs(vlangCount, 3)))
		}
		if len(artifacts) > 0 {
			ex := artifacts
			if len(ex) > 3 {
				ex = ex[:3]
			}
			parts = append(parts, fmt.Sprintf("%d artifact(s): %s", len(artifacts), strings.Join(ex, ", ")))
		}
		reason = "Scannable by Veracode: " + strings.Join(parts, "; ") + "."
	case has:
		category = "code-unsupported-by-veracode"
		reason = fmt.Sprintf("Has code, but in a language Veracode SAST doesn't turn into a module (%s). SAST upload would fail with 'No modules found' — skip or use SCA.", topLangs(langCount, 3))
	case len(sboms) > 0 && len(manifests) == 0:
		category = "sbom-only"
		ex := sboms
		if len(ex) > 3 {
			ex = ex[:3]
		}
		reason = fmt.Sprintf("SBOM only (%d: %s) — no source or artifact. SAST has no module; use SCA or skip. Total scanned: %d.", len(sboms), strings.Join(ex, ", "), total)
	case len(sboms) > 0:
		category = "sbom-only"
		ex := sboms
		if len(ex) > 3 {
			ex = ex[:3]
		}
		reason = fmt.Sprintf("SBOM + manifest/config, no code (%d SBOM: %s; %d manifest(s)). Total scanned: %d.", len(sboms), strings.Join(ex, ", "), len(manifests), total)
	case len(manifests) > 0:
		category = "manifest-only"
		ex := manifests
		if len(ex) > 5 {
			ex = ex[:5]
		}
		reason = fmt.Sprintf("Manifest/config/docs only (%d: %s) — no files with real code content. Total scanned: %d.", len(manifests), strings.Join(ex, ", "), total)
	default:
		category = "non-scannable-only"
		reason = fmt.Sprintf("No recognized code/artifact/SBOM. Total scanned: %d (docs/config/assets or empty files).", total)
	}

	if useCloc {
		if info := clocSummary(root); info != "" {
			reason += " [cloc: " + info + "]"
		}
	}

	sort.Slice(codeFiles, func(i, j int) bool {
		if codeFiles[i].Language == codeFiles[j].Language {
			return codeFiles[i].Path < codeFiles[j].Path
		}
		return codeFiles[i].Language < codeFiles[j].Language
	})
	sort.Strings(manifests)
	sort.Strings(sboms)
	sort.Strings(artifacts)
	capList := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		if len(s) > 100 {
			return s[:100]
		}
		return s
	}
	action := "skip"
	if vscan {
		action = "scan"
	}
	if langCount == nil {
		langCount = map[string]int{}
	}
	if vlangCount == nil {
		vlangCount = map[string]int{}
	}
	return Analysis{Root: root, HasCode: has, VeracodeScannable: vscan,
		Category: category, Languages: langCount, VeracodeLanguages: vlangCount,
		CodeFiles: codeFiles, ManifestFiles: capList(manifests),
		SbomFiles: capList(sboms), ArtifactFiles: capList(artifacts),
		TotalFilesSeen: total, Reason: reason, Action: action}
}

func topLangs(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	if len(all) > n {
		all = all[:n]
	}
	var parts []string
	for _, e := range all {
		parts = append(parts, fmt.Sprintf("%s (%d)", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

// HasScannableCode returns true when there is code (any language).
func HasScannableCode(target string, minCodeLines int) bool {
	return AnalyzeProject(target, minCodeLines, false).HasCode
}

// IsVeracodeScannable returns true when Veracode SAST can extract a module; false = skip.
func IsVeracodeScannable(target string, minCodeLines int) bool {
	return AnalyzeProject(target, minCodeLines, false).VeracodeScannable
}

// ShouldSkipVeracodeScan returns (skip, reason) so the pipeline can log without failing the build.
func ShouldSkipVeracodeScan(target string, minCodeLines int) (bool, string) {
	a := AnalyzeProject(target, minCodeLines, false)
	return !a.VeracodeScannable, a.Reason
}

// DetectLanguages returns {language: file_count} (agnostic).
func DetectLanguages(target string) map[string]int {
	return AnalyzeProject(target, minCodeLinesDflt, false).Languages
}

// DetectVeracodeLanguages returns {supported_language: file_count}.
func DetectVeracodeLanguages(target string) map[string]int {
	return AnalyzeProject(target, minCodeLinesDflt, false).VeracodeLanguages
}

// ---------------------------------------------------------------------------
// Archives
// ---------------------------------------------------------------------------

func isArchiveName(name string) bool {
	nl := strings.ToLower(name)
	return strings.HasSuffix(nl, ".zip") || strings.HasSuffix(nl, ".tar.gz") ||
		strings.HasSuffix(nl, ".tgz") || strings.HasSuffix(nl, ".tar") ||
		strings.HasSuffix(nl, ".tar.bz2")
}

func extractArchive(archive, dest string) error {
	nl := strings.ToLower(archive)
	if strings.HasSuffix(nl, ".zip") {
		return extractZip(archive, dest)
	}
	if strings.HasSuffix(nl, ".tar.gz") || strings.HasSuffix(nl, ".tgz") ||
		strings.HasSuffix(nl, ".tar") || strings.HasSuffix(nl, ".tar.bz2") {
		return extractTar(archive, dest)
	}
	return fmt.Errorf("unsupported archive: %s", archive)
}

func extractZip(archive, dest string) error {
	z, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer z.Close()
	for _, f := range z.File {
		// ZipSlip protection.
		clean := filepath.Clean(f.Name)
		if strings.Contains(clean, "..") {
			continue
		}
		out := filepath.Join(dest, clean)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(out, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(out), 0o755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		of, err := os.Create(out)
		if err != nil {
			rc.Close()
			continue
		}
		_, _ = io.Copy(of, rc)
		of.Close()
		rc.Close()
	}
	return nil
}

func extractTar(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	nl := strings.ToLower(archive)
	var r io.Reader = f
	if strings.HasSuffix(nl, ".gz") || strings.HasSuffix(nl, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	} else if strings.HasSuffix(nl, ".bz2") {
		r = bzip2.NewReader(f)
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.Contains(clean, "..") {
			continue
		}
		out := filepath.Join(dest, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(out, 0o755)
		case tar.TypeReg, tar.TypeRegA:
			_ = os.MkdirAll(filepath.Dir(out), 0o755)
			of, err := os.Create(out)
			if err != nil {
				continue
			}
			_, _ = io.Copy(of, tr)
			of.Close()
		}
	}
	return nil
}

// clocSummary appends a cloc summary when installed (optional, never required).
func clocSummary(root string) string {
	cloc, err := exec.LookPath("cloc")
	if err != nil {
		return ""
	}
	out, err := exec.Command(cloc, "--quiet", "--csv", root).Output()
	if err != nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	start := len(lines) - 5
	if start < 0 {
		start = 0
	}
	for i := len(lines) - 1; i >= start; i-- {
		if strings.HasPrefix(lines[i], "SUM") {
			parts := strings.Split(lines[i], ",")
			if len(parts) >= 5 {
				return fmt.Sprintf("%s file(s), %s code lines (SUM)", parts[4], parts[3])
			}
			return lines[i]
		}
	}
	return ""
}
