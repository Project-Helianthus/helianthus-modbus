package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type evidenceDocument struct {
	Tests       map[string]string `json:"tests"`
	TestSources map[string]string `json:"test_sources"`
	TestFiles   map[string]string `json:"test_files"`
	TestMains   []string          `json:"test_mains"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: acceptance_evidence <repository-root>")
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		fail("%v", err)
	}
	files, err := testGoFiles(root)
	if err != nil {
		fail("%v", err)
	}
	fset := token.NewFileSet()
	evidence := evidenceDocument{
		Tests:       make(map[string]string),
		TestSources: make(map[string]string),
		TestFiles:   make(map[string]string),
		TestMains:   make([]string, 0),
	}
	for _, path := range files {
		source, err := os.ReadFile(path)
		if err != nil {
			fail("%s: %v", path, err)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			fail("%s: %v", path, err)
		}
		fileSum := sha256.Sum256(source)
		evidence.TestFiles[filepath.ToSlash(relative)] =
			hex.EncodeToString(fileSum[:])
		file, err := parser.ParseFile(
			fset,
			path,
			source,
			parser.ParseComments,
		)
		if err != nil {
			fail("%s: %v", path, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil {
				continue
			}
			if function.Name.Name == "TestMain" {
				evidence.TestMains = append(
					evidence.TestMains,
					filepath.ToSlash(relative),
				)
				continue
			}
			if !strings.HasPrefix(function.Name.Name, "Test") {
				continue
			}
			if _, duplicate := evidence.Tests[function.Name.Name]; duplicate {
				fail("duplicate test function %s", function.Name.Name)
			}
			var normalized strings.Builder
			if err := format.Node(&normalized, fset, function); err != nil {
				fail("%s: %v", function.Name.Name, err)
			}
			sum := sha256.Sum256([]byte(normalized.String()))
			evidence.Tests[function.Name.Name] = hex.EncodeToString(sum[:])
			evidence.TestSources[function.Name.Name] =
				filepath.ToSlash(relative)
		}
	}
	sort.Strings(evidence.TestMains)
	output, err := json.Marshal(evidence)
	if err != nil {
		fail("%v", err)
	}
	fmt.Println(string(output))
}

func testGoFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(
		root,
		func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() {
				if info.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		},
	)
	sort.Strings(files)
	return files, err
}

func fail(format string, arguments ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
