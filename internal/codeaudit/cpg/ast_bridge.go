package cpg

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Default AST extraction timeout per file (5 seconds).
const defaultASTTimeout = 5 * time.Second

// pythonDumpScript parses Python source code and outputs a compact normalized JSON AST representation.
const pythonDumpScript = `
import sys, ast, json

def serialize_ast(node):
    if node is None:
        return None
    if isinstance(node, ast.AST):
        d = {"_type": node.__class__.__name__}
        for field, value in ast.iter_fields(node):
            if isinstance(node, ast.Constant) and field == "value":
                d["literal"] = value
                d["value_str"] = str(value) if value is not None else ""
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and field == "args":
                d["arguments"] = serialize_ast(value)
            elif isinstance(node, (ast.BinOp, ast.UnaryOp, ast.BoolOp)) and field == "op":
                d["op"] = value.__class__.__name__
            elif isinstance(node, ast.Compare) and field == "ops":
                d["ops"] = [x.__class__.__name__ for x in value]
            elif isinstance(node, ast.arg) and field == "arg":
                d["name"] = value
                d["arg"] = value
            elif isinstance(node, ast.keyword) and field == "arg":
                d["arg"] = value
            elif field == "ctx":
                d["ctx"] = value.__class__.__name__
            else:
                d[field] = serialize_ast(value)
        for attr in ("lineno", "col_offset", "end_lineno", "end_col_offset"):
            if hasattr(node, attr):
                d[attr] = getattr(node, attr)
        return d
    elif isinstance(node, list):
        return [serialize_ast(x) for x in node]
    elif isinstance(node, (str, int, float, bool)):
        return node
    return str(node)

try:
    if len(sys.argv) > 1 and sys.argv[1] != "-":
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
        fn = sys.argv[1]
    else:
        src = sys.stdin.read()
        fn = "<stdin>"

    tree = ast.parse(src, filename=fn)
    sys.stdout.write(json.dumps(serialize_ast(tree)))
except Exception as e:
    sys.stderr.write(f"AST extraction error: {e}\n")
    sys.exit(1)
`

// ASTNode represents a generic node in the Python AST hierarchy.
type ASTNode struct {
	Type         string `json:"_type"`
	Lineno       int    `json:"lineno,omitempty"`
	ColOffset    int    `json:"col_offset,omitempty"`
	EndLineno    int    `json:"end_lineno,omitempty"`
	EndColOffset int    `json:"end_col_offset,omitempty"`

	// Identifiers, names and literals
	Name     string      `json:"name,omitempty"`
	ID       string      `json:"id,omitempty"`
	Attr     string      `json:"attr,omitempty"`
	Module   string      `json:"module,omitempty"`
	Level    int         `json:"level,omitempty"`
	Literal  interface{} `json:"literal,omitempty"`
	ValueStr string      `json:"value_str,omitempty"`
	Op       string      `json:"op,omitempty"`
	Ops      []string    `json:"ops,omitempty"`
	Ctx      string      `json:"ctx,omitempty"`

	// Child pointers
	Value        *ASTNode `json:"value,omitempty"`
	Target       *ASTNode `json:"target,omitempty"`
	Func         *ASTNode `json:"func,omitempty"`
	Test         *ASTNode `json:"test,omitempty"`
	Left         *ASTNode `json:"left,omitempty"`
	Right        *ASTNode `json:"right,omitempty"`
	Operand      *ASTNode `json:"operand,omitempty"`
	Slice        *ASTNode `json:"slice,omitempty"`
	Exc          *ASTNode `json:"exc,omitempty"`
	Cause        *ASTNode `json:"cause,omitempty"`
	ContextExpr  *ASTNode `json:"context_expr,omitempty"`
	OptionalVars *ASTNode `json:"optional_vars,omitempty"`
	TypeNode     *ASTNode `json:"type,omitempty"`

	// Lists of child nodes
	Body          []*ASTNode          `json:"body,omitempty"`
	Orelse        []*ASTNode          `json:"orelse,omitempty"`
	Finalbody     []*ASTNode          `json:"finalbody,omitempty"`
	DecoratorList []*ASTNode          `json:"decorator_list,omitempty"`
	Targets       []*ASTNode          `json:"targets,omitempty"`
	Args          []*ASTNode          `json:"args,omitempty"` // For Call.args
	Keywords      []*ASTKeyword       `json:"keywords,omitempty"`
	Names         []*ASTAlias         `json:"names,omitempty"`
	Handlers      []*ASTExceptHandler `json:"handlers,omitempty"`
	Bases         []*ASTNode          `json:"bases,omitempty"`
	Keys          []*ASTNode          `json:"keys,omitempty"`
	Values        []*ASTNode          `json:"values,omitempty"`
	Elts          []*ASTNode          `json:"elts,omitempty"`
	Comparators   []*ASTNode          `json:"comparators,omitempty"`
	Items         []*ASTWithItem      `json:"items,omitempty"`

	// Function arguments
	Arguments *ASTArguments `json:"arguments,omitempty"`
}

// ASTAlias represents an imported name or alias (e.g., `import os as my_os`).
type ASTAlias struct {
	Type   string `json:"_type"`
	Name   string `json:"name"`
	AsName string `json:"asname,omitempty"`
}

// ASTKeyword represents a keyword argument in a Call node (e.g., `json=payload`).
type ASTKeyword struct {
	Type  string   `json:"_type"`
	Arg   string   `json:"arg"`
	Value *ASTNode `json:"value"`
}

// ASTArg represents a formal parameter in a function definition.
type ASTArg struct {
	Type       string   `json:"_type"`
	Name       string   `json:"name"`
	Arg        string   `json:"arg"`
	Annotation *ASTNode `json:"annotation,omitempty"`
}

// ASTArguments represents the parameter list of a FunctionDef.
type ASTArguments struct {
	Type     string     `json:"_type"`
	Args     []*ASTArg  `json:"args"`
	Vararg   *ASTArg    `json:"vararg,omitempty"`
	Kwarg    *ASTArg    `json:"kwarg,omitempty"`
	Defaults []*ASTNode `json:"defaults,omitempty"`
}

// ASTExceptHandler represents an except block in a try-except statement.
type ASTExceptHandler struct {
	Type     string     `json:"_type"`
	Name     string     `json:"name,omitempty"`
	TypeNode *ASTNode   `json:"type,omitempty"`
	Body     []*ASTNode `json:"body"`
}

// ASTWithItem represents an item in a with statement.
type ASTWithItem struct {
	Type         string   `json:"_type"`
	ContextExpr  *ASTNode `json:"context_expr"`
	OptionalVars *ASTNode `json:"optional_vars,omitempty"`
}

// ASTModule represents the root of a Python AST tree.
type ASTModule struct {
	Type string     `json:"_type"`
	Body []*ASTNode `json:"body"`
}

// Typed aliases for convenience and semantic clarity.
type ASTStmt = ASTNode
type ASTExpr = ASTNode
type ASTFuncDef = ASTNode
type ASTCall = ASTNode
type ASTAssign = ASTNode
type ASTImport = ASTNode

// ExtractAST invokes python3 to parse a Python file into an ASTModule with a 5-second timeout.
func ExtractAST(ctx context.Context, filePath string) (*ASTModule, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, defaultASTTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctxTimeout, "python3", "-c", pythonDumpScript, filePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctxTimeout.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("ast extraction timed out (5s limit): %w", ctxTimeout.Err())
		}
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("ast extraction failed for %s: %s", filePath, errMsg)
	}

	var mod ASTModule
	if err := json.Unmarshal(stdout.Bytes(), &mod); err != nil {
		return nil, fmt.Errorf("failed to parse ast json for %s: %w", filePath, err)
	}
	return &mod, nil
}

// ExtractASTSource parses a raw Python source code string into an ASTModule with a 5-second timeout.
func ExtractASTSource(ctx context.Context, sourceCode string) (*ASTModule, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, defaultASTTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctxTimeout, "python3", "-c", pythonDumpScript, "-")
	cmd.Stdin = strings.NewReader(sourceCode)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctxTimeout.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("ast extraction timed out (5s limit): %w", ctxTimeout.Err())
		}
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("ast extraction failed from source: %s", errMsg)
	}

	var mod ASTModule
	if err := json.Unmarshal(stdout.Bytes(), &mod); err != nil {
		return nil, fmt.Errorf("failed to parse ast json from source: %w", err)
	}
	return &mod, nil
}

// GetCallFuncName returns the qualified or simple function name called in a Call node (e.g. "requests.post").
func (n *ASTNode) GetCallFuncName() string {
	if n == nil || n.Func == nil {
		return ""
	}
	return n.Func.GetDottedName()
}

// GetDottedName resolves chained Attribute and Name nodes into a dotted string (e.g. "os.path.join").
func (n *ASTNode) GetDottedName() string {
	if n == nil {
		return ""
	}
	if n.Type == "Name" {
		return n.ID
	}
	if n.Type == "Attribute" {
		if n.Value != nil {
			prefix := n.Value.GetDottedName()
			if prefix != "" {
				return prefix + "." + n.Attr
			}
		}
		return n.Attr
	}
	return ""
}

// GetParamNames returns the list of parameter names defined in a function's arguments.
func (n *ASTNode) GetParamNames() []string {
	if n == nil || n.Arguments == nil {
		return nil
	}
	var params []string
	for _, a := range n.Arguments.Args {
		if a.Arg != "" {
			params = append(params, a.Arg)
		} else if a.Name != "" {
			params = append(params, a.Name)
		}
	}
	return params
}

// GetAssignTargetNames extracts target variable names from an assignment statement.
func (n *ASTNode) GetAssignTargetNames() []string {
	if n == nil {
		return nil
	}
	var names []string
	for _, target := range n.Targets {
		if target.ID != "" {
			names = append(names, target.ID)
		} else if target.Attr != "" {
			names = append(names, target.GetDottedName())
		}
	}
	return names
}

// GetImportedNames returns all names imported by an Import or ImportFrom node.
func (n *ASTNode) GetImportedNames() []string {
	if n == nil {
		return nil
	}
	var names []string
	for _, alias := range n.Names {
		if alias.AsName != "" {
			names = append(names, alias.AsName)
		} else if alias.Name != "" {
			names = append(names, alias.Name)
		}
	}
	return names
}

// GetChildren returns all immediate child AST nodes.
func (n *ASTNode) GetChildren() []*ASTNode {
	if n == nil {
		return nil
	}
	var children []*ASTNode

	// Singular child pointers
	if n.Value != nil {
		children = append(children, n.Value)
	}
	if n.Target != nil {
		children = append(children, n.Target)
	}
	if n.Func != nil {
		children = append(children, n.Func)
	}
	if n.Test != nil {
		children = append(children, n.Test)
	}
	if n.Left != nil {
		children = append(children, n.Left)
	}
	if n.Right != nil {
		children = append(children, n.Right)
	}
	if n.Operand != nil {
		children = append(children, n.Operand)
	}
	if n.Slice != nil {
		children = append(children, n.Slice)
	}
	if n.Exc != nil {
		children = append(children, n.Exc)
	}
	if n.Cause != nil {
		children = append(children, n.Cause)
	}
	if n.ContextExpr != nil {
		children = append(children, n.ContextExpr)
	}
	if n.OptionalVars != nil {
		children = append(children, n.OptionalVars)
	}
	if n.TypeNode != nil {
		children = append(children, n.TypeNode)
	}

	// Slices of children
	children = append(children, n.Body...)
	children = append(children, n.Orelse...)
	children = append(children, n.Finalbody...)
	children = append(children, n.DecoratorList...)
	children = append(children, n.Targets...)
	children = append(children, n.Args...)
	children = append(children, n.Bases...)
	children = append(children, n.Keys...)
	children = append(children, n.Values...)
	children = append(children, n.Elts...)
	children = append(children, n.Comparators...)

	for _, kw := range n.Keywords {
		if kw != nil && kw.Value != nil {
			children = append(children, kw.Value)
		}
	}

	for _, h := range n.Handlers {
		if h != nil {
			if h.TypeNode != nil {
				children = append(children, h.TypeNode)
			}
			children = append(children, h.Body...)
		}
	}

	for _, it := range n.Items {
		if it != nil {
			if it.ContextExpr != nil {
				children = append(children, it.ContextExpr)
			}
			if it.OptionalVars != nil {
				children = append(children, it.OptionalVars)
			}
		}
	}

	return children
}

// Walk recursively traverses the AST in depth-first order.
// If fn returns false, traversal of children for that node is skipped.
func (n *ASTNode) Walk(fn func(node *ASTNode) bool) {
	if n == nil {
		return
	}
	if !fn(n) {
		return
	}
	for _, child := range n.GetChildren() {
		child.Walk(fn)
	}
}
