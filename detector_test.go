package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestManifestOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"x"}`)
	writeFile(t, dir, "README.md", "# readme")
	a := AnalyzeProject(dir, 1, false)
	if a.HasCode || a.VeracodeScannable {
		t.Fatalf("esperava sem código, obteve %+v", a)
	}
	if a.Category != "manifest-only" {
		t.Fatalf("categoria esperada manifest-only, obteve %q", a.Category)
	}
}

func TestWithCode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", "print(\"oi\")\n")
	writeFile(t, dir, "package.json", `{"name":"y"}`)
	a := AnalyzeProject(dir, 1, false)
	if !a.HasCode || !a.VeracodeScannable {
		t.Fatalf("esperava código escaneável, obteve %+v", a)
	}
	if a.Category != "code" {
		t.Fatalf("categoria esperada code, obteve %q", a.Category)
	}
}

func TestSbomOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sbom.json", `{"bomFormat":"CycloneDX","components":[]}`)
	writeFile(t, dir, "README.md", "# doc")
	a := AnalyzeProject(dir, 1, false)
	if a.HasCode || a.VeracodeScannable {
		t.Fatalf("esperava sbom-only sem código, obteve %+v", a)
	}
	if a.Category != "sbom-only" {
		t.Fatalf("categoria esperada sbom-only, obteve %q", a.Category)
	}
}

func TestShellOnlyVeracodeGate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.sh", "#!/bin/bash\necho oi\n")
	a := AnalyzeProject(dir, 1, false)
	if !a.HasCode {
		t.Fatalf("shell conta como código agnóstico: %+v", a)
	}
	if a.VeracodeScannable {
		t.Fatalf("shell sozinho não deveria ser veracode-scannable: %+v", a)
	}
	if a.Category != "code-unsupported-by-veracode" {
		t.Fatalf("categoria esperada code-unsupported-by-veracode, obteve %q", a.Category)
	}
}

func TestArtifact(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.jar", "fake-jar")
	a := AnalyzeProject(dir, 1, false)
	if !a.VeracodeScannable {
		t.Fatalf("jar deveria ser escaneável: %+v", a)
	}
}
