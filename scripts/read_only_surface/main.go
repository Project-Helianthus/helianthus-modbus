package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

var allowedFunctionCodes = map[int64]bool{3: true, 4: true, 43: true}

func main() {
	if len(os.Args) != 2 {
		fail("usage: read_only_surface <repository-root>")
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		fail("%v", err)
	}
	files, err := productGoFiles(root)
	if err != nil {
		fail("%v", err)
	}
	fset := token.NewFileSet()
	writeSelectors := make(map[*ast.SelectorExpr]string)
	allowedWrites := make(map[*ast.SelectorExpr]bool)
	connSelectors := make(map[*ast.SelectorExpr]string)
	allowedConnSelectors := make(map[*ast.SelectorExpr]bool)
	connCallCounts := make(map[string]int)
	internalCallCounts := make(map[string]int)
	aduIdentifierCounts := make(map[string]int)
	aduTraceCalls := make(map[string]int)
	rawEncoderCalls := 0
	for _, path := range files {
		if filepath.Ext(path) != ".go" ||
			len(path) >= len("_test.go") &&
				path[len(path)-len("_test.go"):] == "_test.go" {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			fail("%s: %v", path, err)
		}
		validateImports(fset, file)
		base := filepath.Base(path)
		validateRTUImports(fset, base, file)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			validateTransportMethod(base, function)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.Ident:
					if base == "tcp_transport.go" && value.Name == "adu" {
						switch function.Name.Name {
						case "writeReservationUntil",
							"writeCoalescedUntil",
							"performInvokedWrite":
						default:
							fail(
								"%s: encoded ADU escaped authorized dataflow",
								location(fset, value),
							)
						}
						aduIdentifierCounts[function.Name.Name]++
					}
				case *ast.SelectorExpr:
					if value.Sel.Name == "Write" {
						writeSelectors[value] = location(fset, value)
					}
					if value.Sel.Name == "conn" {
						connSelectors[value] = location(fset, value)
					}
				case *ast.CallExpr:
					validateIndirectWriteCall(fset, value)
					validateDeadlineCapability(
						fset,
						base,
						function.Name.Name,
						value,
						allowedConnSelectors,
						connCallCounts,
					)
					if selector, ok := value.Fun.(*ast.SelectorExpr); ok &&
						selector.Sel.Name == "Write" &&
						base == "tcp_transport.go" &&
						function.Name.Name == "performInvokedWrite" &&
						expression(fset, selector.X) == "transport.conn" &&
						len(value.Args) == 1 &&
						expression(fset, value.Args[0]) == "adu" {
						allowedWrites[selector] = true
					}
					if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
						if base == "tcp_transport.go" &&
							expression(fset, selector.X) == "hex" &&
							selector.Sel.Name == "EncodeToString" &&
							len(value.Args) == 1 &&
							expression(fset, value.Args[0]) == "adu" {
							aduTraceCalls[function.Name.Name]++
						}
						if conn, ok := selector.X.(*ast.SelectorExpr); ok &&
							conn.Sel.Name == "conn" &&
							expression(fset, conn) == "transport.conn" &&
							allowedConnCall(
								function.Name.Name,
								selector.Sel.Name,
								len(value.Args),
							) {
							allowedConnSelectors[conn] = true
							key := function.Name.Name + "/" + selector.Sel.Name
							connCallCounts[key]++
						}
						if expression(fset, selector.X) == "transport" {
							switch selector.Sel.Name {
							case "writeADULocked",
								"writeCoalescedADULocked",
								"performInvokedWrite",
								"writeReservationUntil",
								"writeCoalescedUntil",
								"readResponsesUntil":
								key := function.Name.Name + "/" +
									selector.Sel.Name
								internalCallCounts[key]++
							}
						}
					}
					if identifier, ok := value.Fun.(*ast.Ident); ok &&
						identifier.Name == "encodeTCPADU" {
						allowed := (base == "tcp_adu.go" &&
							(function.Name.Name == "EncodeTCPReadADU" ||
								function.Name.Name == "EncodeTCPDeviceIDAccessADU")) ||
							(base == "private_function.go" &&
								function.Name.Name == "EncodeTCPPrivateFunctionADU")
						if !allowed {
							fail(
								"%s: raw TCP encoder called from %s",
								location(fset, value),
								function.Name.Name,
							)
						}
						rawEncoderCalls++
					}
					validateFunctionCodeConversion(fset, value)
				case *ast.CompositeLit:
					validateByteLiteral(fset, value)
				case *ast.AssignStmt:
					validateIndexedFunctionByte(fset, value)
				}
				return true
			})
		}
	}
	if len(writeSelectors) != 1 || len(allowedWrites) != 1 {
		for selector, where := range writeSelectors {
			if !allowedWrites[selector] {
				fail("%s: unauthorized or aliased Write selector", where)
			}
		}
		fail(
			"expected one direct transport Write, found selectors=%d allowed=%d",
			len(writeSelectors),
			len(allowedWrites),
		)
	}
	for selector, where := range connSelectors {
		if !allowedConnSelectors[selector] {
			fail("%s: unauthorized access to transport connection", where)
		}
	}
	expectedConnCalls := map[string]int{
		"writeReservationUntil/SetWriteDeadlineCapability": 1,
		"writeCoalescedUntil/SetWriteDeadlineCapability":   1,
		"performInvokedWrite/Write":                        1,
		"readResponsesUntil/SetReadDeadlineCapability":     1,
		"readResponsesUntil/Read":                          1,
		"closeTerminal/Close":                              1,
		"closeDetached/Close":                              1,
	}
	if !equalCounts(connCallCounts, expectedConnCalls) {
		fail("transport connection call graph changed: %v", connCallCounts)
	}
	expectedInternalCalls := map[string]int{
		"WriteReservation/writeReservationUntil":    1,
		"WriteCoalesced/writeCoalescedUntil":        1,
		"writeReservationUntil/performInvokedWrite": 1,
		"writeCoalescedUntil/performInvokedWrite":   1,
		"ReadResponses/readResponsesUntil":          1,
	}
	if !equalCounts(internalCallCounts, expectedInternalCalls) {
		fail("transport write call graph changed: %v", internalCallCounts)
	}
	expectedADUIdentifiers := map[string]int{
		"writeReservationUntil": 3,
		"writeCoalescedUntil":   4,
		"performInvokedWrite":   2,
	}
	if !equalCounts(aduIdentifierCounts, expectedADUIdentifiers) {
		fail("encoded ADU dataflow changed: %v", aduIdentifierCounts)
	}
	expectedADUTraceCalls := map[string]int{
		"writeReservationUntil": 1,
		"writeCoalescedUntil":   1,
	}
	if !equalCounts(aduTraceCalls, expectedADUTraceCalls) {
		fail("encoded ADU trace dataflow changed: %v", aduTraceCalls)
	}
	if rawEncoderCalls != 3 {
		fail("expected three bounded raw TCP encoder calls, found %d", rawEncoderCalls)
	}
	fmt.Println("Read-only AST surface passed.")
}

func validateDeadlineCapability(
	fset *token.FileSet,
	file string,
	function string,
	call *ast.CallExpr,
	allowed map[*ast.SelectorExpr]bool,
	counts map[string]int,
) {
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || identifier.Name != "newSocketInterrupter" ||
		file != "tcp_transport.go" || len(call.Args) != 2 {
		return
	}
	socket, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || expression(fset, socket) != "transport.conn" {
		fail("%s: aliased socket interrupt target", location(fset, call))
	}
	method, ok := call.Args[1].(*ast.SelectorExpr)
	if !ok {
		fail("%s: malformed socket deadline capability", location(fset, call))
	}
	conn, ok := method.X.(*ast.SelectorExpr)
	if !ok || expression(fset, conn) != "transport.conn" {
		fail("%s: aliased socket deadline capability", location(fset, call))
	}
	expected := ""
	switch function {
	case "writeReservationUntil", "writeCoalescedUntil":
		expected = "SetWriteDeadline"
	case "readResponsesUntil":
		expected = "SetReadDeadline"
	default:
		fail(
			"%s: socket deadline capability escaped through %s",
			location(fset, call),
			function,
		)
	}
	if method.Sel.Name != expected {
		fail(
			"%s: unexpected socket deadline capability %s",
			location(fset, method),
			method.Sel.Name,
		)
	}
	allowed[socket] = true
	allowed[conn] = true
	counts[function+"/"+expected+"Capability"]++
}

func productGoFiles(root string) ([]string, error) {
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
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			switch filepath.ToSlash(relative) {
			case "scripts/read_only_surface/main.go",
				"scripts/acceptance_evidence/main.go",
				"rtu_serial.go",
				"rtu_serial_linux.go",
				"rtu_serial_stub.go":
				return nil
			}
			if filepath.Ext(path) == ".go" &&
				len(path) >= len("_test.go") &&
				path[len(path)-len("_test.go"):] != "_test.go" {
				files = append(files, path)
			}
			return nil
		},
	)
	sort.Strings(files)
	return files, err
}

func validateIndirectWriteCall(fset *token.FileSet, call *ast.CallExpr) {
	name := expression(fset, call.Fun)
	switch name {
	case "io.Copy", "io.CopyBuffer", "io.CopyN", "io.WriteString",
		"fmt.Fprint", "fmt.Fprintf", "fmt.Fprintln",
		"binary.Write", "os.WriteFile":
		fail("%s: unauthorized indirect write call %s", location(fset, call), name)
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if ok && (selector.Sel.Name == "ReadFrom" ||
		selector.Sel.Name == "WriteTo" ||
		selector.Sel.Name == "WriteString" ||
		selector.Sel.Name == "WriteByte" ||
		selector.Sel.Name == "WriteRune" ||
		selector.Sel.Name == "Encode" ||
		selector.Sel.Name == "Flush") {
		fail(
			"%s: unauthorized indirect write method %s",
			location(fset, call),
			selector.Sel.Name,
		)
	}
}

func validateImports(fset *token.FileSet, file *ast.File) {
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			fail("%s: malformed import", location(fset, imported))
		}
		if imported.Name != nil {
			fail(
				"%s: product import aliases are forbidden",
				location(fset, imported),
			)
		}
		switch path {
		case "reflect", "unsafe", "syscall", "plugin":
			fail("%s: forbidden capability import %s", location(fset, imported), path)
		}
	}
}

func validateRTUImports(fset *token.FileSet, base string, file *ast.File) {
	expectedByFile := map[string]map[string]bool{
		"rtu_adu.go": {
			"sync": true,
			"time": true,
		},
		"rtu_capability.go": {},
		"rtu_endpoint.go": {
			"context":      true,
			"encoding/hex": true,
			"errors":       true,
			"math":         true,
			"sync":         true,
			"sync/atomic":  true,
			"time":         true,
		},
		"rtu_timing.go": {
			"math": true,
			"time": true,
		},
	}
	expected, guarded := expectedByFile[base]
	if !guarded {
		return
	}
	actual := make(map[string]bool, len(file.Imports))
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			fail("%s: malformed RTU import", location(fset, imported))
		}
		actual[path] = true
	}
	if !equalImportSets(actual, expected) {
		fail("%s: RTU import allowlist changed: %v", base, sortedKeys(actual))
	}
}

func equalImportSets(actual map[string]bool, expected map[string]bool) bool {
	if len(actual) != len(expected) {
		return false
	}
	for path := range expected {
		if !actual[path] {
			return false
		}
	}
	return true
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func allowedConnCall(function string, method string, arguments int) bool {
	switch function + "/" + method {
	case "writeADULocked/SetWriteDeadline",
		"writeCoalescedADULocked/SetWriteDeadline",
		"readResponsesUntil/SetReadDeadline":
		return arguments == 1
	case "performInvokedWrite/Write", "readResponsesUntil/Read":
		return arguments == 1
	case "closeTerminal/Close", "closeDetached/Close":
		return arguments == 0
	default:
		return false
	}
}

func equalCounts(actual map[string]int, expected map[string]int) bool {
	if len(actual) != len(expected) {
		return false
	}
	for key, count := range expected {
		if actual[key] != count {
			return false
		}
	}
	return true
}

func validateTransportMethod(file string, function *ast.FuncDecl) {
	if function.Recv == nil || !function.Name.IsExported() {
		return
	}
	receiver := expression(token.NewFileSet(), function.Recv.List[0].Type)
	if receiver != "*TCPTransport" {
		return
	}
	switch function.Name.Name {
	case "WriteReservation", "WriteCoalesced", "ReadResponses":
		return
	default:
		fail(
			"%s: unauthorized exported TCPTransport method %s",
			file,
			function.Name.Name,
		)
	}
}

func validateFunctionCodeConversion(fset *token.FileSet, call *ast.CallExpr) {
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || identifier.Name != "FunctionCode" || len(call.Args) != 1 {
		return
	}
	literal, ok := call.Args[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return
	}
	code, err := strconv.ParseInt(literal.Value, 0, 64)
	if err != nil || !allowedFunctionCodes[code] {
		fail(
			"%s: disallowed numeric FunctionCode conversion",
			location(fset, call),
		)
	}
}

func validateByteLiteral(fset *token.FileSet, literal *ast.CompositeLit) {
	array, ok := literal.Type.(*ast.ArrayType)
	if !ok {
		return
	}
	element, ok := array.Elt.(*ast.Ident)
	if !ok || element.Name != "byte" || len(literal.Elts) == 0 {
		return
	}
	first, ok := literal.Elts[0].(*ast.BasicLit)
	if ok && first.Kind == token.INT {
		fail(
			"%s: raw numeric function byte in emitted byte slice",
			location(fset, first),
		)
	}
}

func validateIndexedFunctionByte(fset *token.FileSet, assignment *ast.AssignStmt) {
	for index, left := range assignment.Lhs {
		if index >= len(assignment.Rhs) {
			break
		}
		target, ok := left.(*ast.IndexExpr)
		if !ok {
			continue
		}
		position, ok := target.Index.(*ast.BasicLit)
		if !ok || position.Kind != token.INT || position.Value != "0" {
			continue
		}
		value, ok := assignment.Rhs[index].(*ast.BasicLit)
		if ok && value.Kind == token.INT {
			fail(
				"%s: raw numeric assignment to first emitted byte",
				location(fset, value),
			)
		}
	}
}

func expression(fset *token.FileSet, expression ast.Expr) string {
	var output bytes.Buffer
	if err := format.Node(&output, fset, expression); err != nil {
		return ""
	}
	return output.String()
}

func location(fset *token.FileSet, node ast.Node) string {
	return fset.Position(node.Pos()).String()
}

func fail(format string, arguments ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
