// Command code-detector — gate de esteira Veracode.
//
//	true  = tem módulo escaneável (faça o upload)
//	false = só SBOM/manifesto/docs (pule o SAST sem erro)
//
// Exit codes (p/ pipeline):
//
//	0 = escaneável OU análise ok sem --fail-on-no-code
//	2 = não escaneável + --fail-on-no-code (sinal de "skip")
//	1 = erro de uso/IO
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Preenchidas via ldflags no build/release (GoReleaser).
// Desenvolvimento local mostra version=dev.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	// Parse manual (aceita flags antes OU depois do path, estilo argparse):
	//   ./code-detector ./repo --mode veracode -q
	//   ./code-detector --mode veracode -q ./repo
	mode := "veracode"
	jsonOut := false
	verbose := false
	minLines := minCodeLinesDflt
	useCloc := false
	quiet := false
	failOnNoCode := false
	var positional []string

	i := 0
	for i < len(argv) {
		a := argv[i]
		// --flag=valor
		if strings.HasPrefix(a, "-") && strings.Contains(a, "=") {
			kv := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)
			a, argv = "--"+kv[0], append([]string{kv[1]}, argv[i+1:]...)
			i = 0
			_ = kv
			continue
		}
		switch a {
		case "--mode", "-mode":
			i++
			if i >= len(argv) {
				fmt.Fprintln(os.Stderr, "--mode exige veracode|generic")
				return 1
			}
			mode = argv[i]
		case "--json", "-json":
			jsonOut = true
		case "--verbose", "-verbose", "--v", "-v":
			verbose = true
		case "--min-lines", "-min-lines":
			i++
			if i >= len(argv) {
				fmt.Fprintln(os.Stderr, "--min-lines exige um número")
				return 1
			}
			var n int
			if _, err := fmt.Sscanf(argv[i], "%d", &n); err != nil || n < 1 {
				fmt.Fprintln(os.Stderr, "--min-lines inválido")
				return 1
			}
			minLines = n
		case "--use-cloc", "-use-cloc":
			useCloc = true
		case "--quiet", "-quiet", "--q", "-q":
			quiet = true
		case "--fail-on-no-code", "-fail-on-no-code":
			failOnNoCode = true
		case "--help", "-help", "-h":
			fmt.Fprintln(os.Stderr, "uso: code-detector [--mode veracode|generic] [--json] [-q] [--fail-on-no-code] [--min-lines N] [--version] <pasta|arquivo|archive>")
			return 0
		case "--version", "-version":
			fmt.Printf("code-detector %s (commit %s, %s)\n", version, commit, date)
			return 0
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "flag desconhecida: %s\n", a)
				return 1
			}
			positional = append(positional, a)
		}
		i++
	}
	if len(positional) != 1 {
		fmt.Fprintln(os.Stderr, "uso: code-detector [--mode veracode|generic] [--json] [-q] [--fail-on-no-code] <pasta|arquivo|archive>")
		return 1
	}
	if mode != "veracode" && mode != "generic" {
		fmt.Fprintln(os.Stderr, "mode inválido: use veracode ou generic")
		return 1
	}
	target := positional[0]
	if _, err := os.Stat(target); err != nil {
		fmt.Fprintf(os.Stderr, "caminho inexistente: %s\n", target)
		a := Analysis{Root: target, Category: "empty", Action: "skip", Reason: "Caminho inexistente.",
			Languages: map[string]int{}, VeracodeLanguages: map[string]int{}}
		emit(a, mode, false, jsonOut, quiet, verbose)
		return exitFor(false, failOnNoCode)
	}

	a := AnalyzeProject(target, minLines, useCloc)
	result := a.VeracodeScannable
	if mode == "generic" {
		result = a.HasCode
	}
	emit(a, mode, result, jsonOut, quiet, verbose)
	return exitFor(result, failOnNoCode)
}

func exitFor(result, failOnNoCode bool) int {
	if failOnNoCode && !result {
		return 2
	}
	return 0
}

func emit(a Analysis, mode string, result, jsonOut, quiet, verbose bool) {
	if jsonOut {
		type out struct {
			Analysis
			Mode   string `json:"mode"`
			Result bool   `json:"result"`
		}
		data, _ := json.MarshalIndent(out{a, mode, result}, "", "  ")
		fmt.Println(string(data))
		return
	}
	if quiet {
		fmt.Println(boolStr(result))
		return
	}
	fmt.Println(boolStr(result))
	fmt.Printf("mode: %s | category: %s | action: %s\n", mode, a.Category, a.Action)
	fmt.Printf("linguagens: %s\n", langsStr(a.Languages))
	if len(a.SbomFiles) > 0 {
		fmt.Printf("sbom: %v\n", head(a.SbomFiles, 5))
	}
	if len(a.ArtifactFiles) > 0 {
		fmt.Printf("artefatos: %v\n", head(a.ArtifactFiles, 5))
	}
	fmt.Printf("motivo: %s\n", a.Reason)
	if verbose && len(a.CodeFiles) > 0 {
		fmt.Println("arquivos de código (top 20):")
		for i, c := range a.CodeFiles {
			if i >= 20 {
				break
			}
			tag := ""
			if !c.VeracodeSupported {
				tag = " [fora do SAST]"
			}
			fmt.Printf("  - %s [%s, %d linhas]%s\n", c.Path, c.Language, c.CodeLines, tag)
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func head(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func langsStr(m map[string]int) string {
	if len(m) == 0 {
		return "{}"
	}
	var parts []string
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s:%d", k, v))
	}
	return "{" + strings.Join(parts, " ") + "}"
}
