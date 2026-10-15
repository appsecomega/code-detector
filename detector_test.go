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
		t.Fatalf("expected no code, got %+v", a)
	}
	if a.Category != "manifest-only" {
		t.Fatalf("expected category manifest-only, got %q", a.Category)
	}
}

func TestWithCode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", "print(\"oi\")\n")
	writeFile(t, dir, "package.json", `{"name":"y"}`)
	a := AnalyzeProject(dir, 1, false)
	if !a.HasCode || !a.VeracodeScannable {
		t.Fatalf("expected scannable code, got %+v", a)
	}
	if a.Category != "code" {
		t.Fatalf("expected category code, got %q", a.Category)
	}
}

func TestSbomOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sbom.json", `{"bomFormat":"CycloneDX","components":[]}`)
	writeFile(t, dir, "README.md", "# doc")
	a := AnalyzeProject(dir, 1, false)
	if a.HasCode || a.VeracodeScannable {
		t.Fatalf("expected sbom-only without code, got %+v", a)
	}
	if a.Category != "sbom-only" {
		t.Fatalf("expected category sbom-only, got %q", a.Category)
	}
}

func TestShellOnlyVeracodeGate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "deploy.sh", "#!/bin/bash\necho oi\n")
	a := AnalyzeProject(dir, 1, false)
	if !a.HasCode {
		t.Fatalf("shell counts as agnostic code: %+v", a)
	}
	if a.VeracodeScannable {
		t.Fatalf("shell alone should not be veracode-scannable: %+v", a)
	}
	if a.Category != "code-unsupported-by-veracode" {
		t.Fatalf("expected category code-unsupported-by-veracode, got %q", a.Category)
	}
}

func TestArtifact(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.jar", "fake-jar")
	a := AnalyzeProject(dir, 1, false)
	if !a.VeracodeScannable {
		t.Fatalf("jar should be scannable: %+v", a)
	}
}
