//go:build ignore

// Discover test identities enabled by the integration tag in selected packages.
// Comparing go list results preserves platform/race constraints and distinguishes
// integration-only files from ordinary unit tests. Parse Go syntax, not regexes.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type packageInfo struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
	Error        *struct{ Err string }
}

type identity struct{ Package, Test string }

func packages(args []string, integration bool) (map[string]packageInfo, error) {
	flags := []string{"list", "-e", "-json"}
	if integration {
		flags = append(flags, "-tags=integration")
	}
	flags = append(flags, args...)
	output, err := exec.Command("go", flags...).Output()
	if err != nil {
		return nil, err
	}
	result := map[string]packageInfo{}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var pkg packageInfo
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		// A package composed only of integration-tagged files may legitimately be
		// absent from the default build. The integration build must still be valid.
		if integration && pkg.Error != nil {
			return nil, fmt.Errorf("integration package load failed")
		}
		result[pkg.ImportPath] = pkg
	}
	return result, nil
}

func testNames(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	testingAlias := ""
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, err
		}
		if imported == "testing" {
			testingAlias = "testing"
			if spec.Name != nil {
				testingAlias = spec.Name.Name
			}
		}
	}
	var names []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		suffix := strings.TrimPrefix(fn.Name.Name, "Test")
		if suffix != "" {
			first, _ := utf8.DecodeRuneInString(suffix)
			if unicode.IsLower(first) {
				continue
			}
		}
		if fn.Type.TypeParams != nil || fn.Type.Results != nil || fn.Type.Params.NumFields() != 1 {
			continue
		}
		pointer, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		valid := false
		switch typ := pointer.X.(type) {
		case *ast.SelectorExpr:
			alias, ok := typ.X.(*ast.Ident)
			valid = ok && testingAlias != "" && alias.Name == testingAlias && typ.Sel.Name == "T"
		case *ast.Ident:
			valid = testingAlias == "." && typ.Name == "T"
		}
		if valid {
			names = append(names, fn.Name.Name)
		}
	}
	return names, nil
}

func discover(args []string) ([]identity, error) {
	ordinary, err := packages(args, false)
	if err != nil {
		return nil, err
	}
	tagged, err := packages(args, true)
	if err != nil {
		return nil, err
	}
	found := map[identity]bool{}
	for path, pkg := range tagged {
		base := ordinary[path]
		ordinaryFiles := map[string]bool{}
		for _, name := range append(base.TestGoFiles, base.XTestGoFiles...) {
			ordinaryFiles[name] = true
		}
		for _, name := range append(pkg.TestGoFiles, pkg.XTestGoFiles...) {
			if ordinaryFiles[name] {
				continue
			}
			names, err := testNames(filepath.Join(pkg.Dir, name))
			if err != nil {
				return nil, err
			}
			for _, name := range names {
				found[identity{Package: path, Test: name}] = true
			}
		}
	}
	result := make([]identity, 0, len(found))
	for test := range found {
		result = append(result, test)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Package != result[j].Package {
			return result[i].Package < result[j].Package
		}
		return result[i].Test < result[j].Test
	})
	return result, nil
}

func main() {
	identities, err := discover(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration test discovery failed")
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(identities); err != nil {
		os.Exit(1)
	}
}
