package cpg

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// builderStatementTypes lists the Python AST classes that represent
// statements. Any node whose "_type" is not listed here is modelled as an
// expression by builderNodeType.
var builderStatementTypes = map[string]bool{
	"Module":           true,
	"FunctionDef":      true,
	"AsyncFunctionDef": true,
	"ClassDef":         true,
	"Return":           true,
	"Delete":           true,
	"Assign":           true,
	"TypeAlias":        true,
	"AugAssign":        true,
	"AnnAssign":        true,
	"For":              true,
	"AsyncFor":         true,
	"While":            true,
	"If":               true,
	"With":             true,
	"AsyncWith":        true,
	"Match":            true,
	"Raise":            true,
	"Try":              true,
	"TryStar":          true,
	"Assert":           true,
	"Import":           true,
	"ImportFrom":       true,
	"Global":           true,
	"Nonlocal":         true,
	"Expr":             true,
	"Pass":             true,
	"Break":            true,
	"Continue":         true,
}

// builderScope identifies the lexical scope a CPG node belongs to. "id" is the
// node ID of the scope defining node (module, function or class definition).
type builderScope struct {
	name string
	id   string
}

// builderCallArg is one actual argument of a call site, either positional
// (index >= 0) or passed by keyword (name != "").
type builderCallArg struct {
	index int
	name  string
	node  *CPGNode
}

// builderCallSite records a call expression so it can be bound to a callee once
// every file of the graph has been converted.
type builderCallSite struct {
	callID     string
	filePath   string
	callee     string
	positional []builderCallArg
	keyword    []builderCallArg
	resolved   bool
}

// builderFuncInfo describes a function definition registered in the builder
// index and is used to connect call sites with their callee.
type builderFuncInfo struct {
	filePath   string
	fqn        string
	name       string
	defID      string
	paramNames []string
	params     []*CPGNode
	returns    []*CPGNode
}

// builderCallRef is a call expression with the CPG node created for it.
type builderCallRef struct {
	ast  *ASTNode
	node *CPGNode
}

// builderFileState carries the state of a single BuildFile invocation.
type builderFileState struct {
	b        *CPGBuilder
	g        *CodePropertyGraph
	filePath string
	module   string
	// nodeOf maps a raw AST node to the CPG node derived from it.
	nodeOf map[*ASTNode]*CPGNode
	// nodeByID keeps the node created for every node ID of this file. Two AST
	// nodes can share a position and a type (an Expr statement and its value,
	// an Attribute and the Name it qualifies); they then share one CPG node.
	nodeByID map[string]*CPGNode
	// created holds the nodes of this file in document (pre-order) order.
	created []*CPGNode
	// paramsOf maps a function definition node ID to its parameter nodes.
	paramsOf map[string][]*CPGNode
	// callRefs holds the call expressions of this file.
	callRefs []builderCallRef
}

// CPGBuilder converts Python AST modules into a unified Code Property Graph: it
// implements Layer 1 (unified node modelling), Layer 3 (intra-procedural CFG
// and DFG) and the inter-procedural call edges of the model.
type CPGBuilder struct {
	resolver *SymbolResolver

	funcIndex map[string][]*builderFuncInfo
	aliases   map[string]map[string]string
	calls     []*builderCallSite
}

// NewCPGBuilder creates a builder that uses the given resolver for cross-file
// symbol resolution. A nil resolver is replaced by an empty one, in which case
// only same-file symbols can be resolved.
func NewCPGBuilder(resolver *SymbolResolver) *CPGBuilder {
	if resolver == nil {
		resolver = NewSymbolResolver("")
	}
	b := &CPGBuilder{resolver: resolver}
	b.reset()
	return b
}

// reset clears the cross-file indexes so a builder can be reused.
func (b *CPGBuilder) reset() {
	b.funcIndex = make(map[string][]*builderFuncInfo)
	b.aliases = make(map[string]map[string]string)
	b.calls = nil
}

// Build parses every file path and converts it into the given graph. Call edge
// resolution runs once all files have been converted, so calls crossing file
// boundaries are bound regardless of the input order.
func (b *CPGBuilder) Build(g *CodePropertyGraph, filePaths []string) error {
	if g == nil {
		return errors.New("cpg builder requires a non-nil graph")
	}
	b.reset()
	for _, filePath := range filePaths {
		mod, err := ExtractAST(context.Background(), filePath)
		if err != nil {
			return err
		}
		if err := b.BuildFile(g, filePath, mod); err != nil {
			return err
		}
	}
	b.resolveCallSites(g)
	return nil
}

// BuildFile converts the AST of a single file into the graph. Every AST node
// becomes a CPG node, then control flow, data flow and call edges are laid out.
func (b *CPGBuilder) BuildFile(g *CodePropertyGraph, filePath string, mod *ASTModule) error {
	if g == nil {
		return errors.New("cpg builder requires a non-nil graph")
	}
	if mod == nil {
		return fmt.Errorf("cpg builder requires a non-nil AST for %s", filePath)
	}
	if b.funcIndex == nil || b.aliases == nil {
		b.reset()
	}

	s := &builderFileState{
		b:        b,
		g:        g,
		filePath: filePath,
		module:   resolverModulePath(b.resolver.workspaceRoot, filePath),
		nodeOf:   make(map[*ASTNode]*CPGNode),
		nodeByID: make(map[string]*CPGNode),
		paramsOf: make(map[string][]*CPGNode),
	}

	// The module itself is materialised as the root of the AST hierarchy.
	root := &ASTNode{Type: "Module", Lineno: 1, ColOffset: 0, Body: mod.Body}
	modScope := &builderScope{id: builderNodeID(filePath, root.Lineno, root.ColOffset, AST_MODULE)}
	modNode, err := s.createNode(root, modScope)
	if err != nil {
		return err
	}
	if err := s.buildChildren(root, modNode, modScope); err != nil {
		return err
	}

	s.linkStatements(mod.Body)
	s.buildDFG()
	s.collectFunctions()
	s.collectAliases()
	s.recordCallSites()
	b.resolveCallSites(g)
	return nil
}

// ---------------------------------------------------------------------------
// Layer 1: unified AST node modelling
// ---------------------------------------------------------------------------

// buildChildren creates the CPG node of every AST child of ast and links it to
// the parent with an AST_CHILD edge.
func (s *builderFileState) buildChildren(ast *ASTNode, parent *CPGNode, scope *builderScope) error {
	// A function or class definition opens a new lexical scope for its body.
	childScope := scope
	switch ast.Type {
	case "FunctionDef", "AsyncFunctionDef", "ClassDef":
		childScope = &builderScope{name: ast.Name, id: parent.NodeID}
	}
	// Formal parameters are not reachable through GetChildren, so they are
	// materialised explicitly as AST_PARAM nodes.
	if ast.Type == "FunctionDef" || ast.Type == "AsyncFunctionDef" {
		if err := s.buildParams(ast, parent, childScope); err != nil {
			return err
		}
	}
	for _, child := range ast.GetChildren() {
		childNode, err := s.createNode(child, childScope)
		if err != nil {
			return err
		}
		// A child sharing the position and type of its parent reuses the
		// parent node, so no self referencing hierarchy edge is emitted.
		if childNode.NodeID != parent.NodeID {
			s.addEdge(parent.NodeID, childNode.NodeID, AST_CHILD, nil)
		}
		if err := s.buildChildren(child, childNode, childScope); err != nil {
			return err
		}
	}
	return nil
}

// buildParams materialises the formal parameters of a function definition.
// The Python AST dump keeps no position information for arguments, so the
// definition position is used as the anchor and the parameter index supplies
// the column, which keeps every parameter node ID distinct.
func (s *builderFileState) buildParams(ast *ASTNode, parent *CPGNode, scope *builderScope) error {
	if ast.Arguments == nil {
		return nil
	}
	args := make([]*ASTArg, 0, len(ast.Arguments.Args)+2)
	args = append(args, ast.Arguments.Args...)
	args = append(args, ast.Arguments.Vararg, ast.Arguments.Kwarg)
	for i, arg := range args {
		if arg == nil {
			continue
		}
		name := arg.Arg
		if name == "" {
			name = arg.Name
		}
		node := &CPGNode{
			NodeID:         builderNodeID(s.filePath, ast.Lineno, ast.ColOffset+i, AST_PARAM),
			FilePath:       s.filePath,
			Line:           ast.Lineno,
			Col:            ast.ColOffset + i,
			NodeType:       AST_PARAM,
			CodeStr:        name,
			EnclosingScope: scope.name,
			ScopeID:        scope.id,
			SymbolName:     name,
			Attributes:     map[string]interface{}{"ast_type": "arg", "param_index": i},
		}
		if err := s.g.AddNode(node); err != nil {
			return err
		}
		s.nodeByID[node.NodeID] = node
		s.paramsOf[parent.NodeID] = append(s.paramsOf[parent.NodeID], node)
		s.addEdge(parent.NodeID, node.NodeID, AST_CHILD, nil)
	}
	return nil
}

// createNode derives the CPG node of one AST node and registers it in the
// graph. AST nodes sharing a position and a type share a single CPG node, and
// the same AST node is never converted twice.
func (s *builderFileState) createNode(ast *ASTNode, scope *builderScope) (*CPGNode, error) {
	if existing, ok := s.nodeOf[ast]; ok {
		return existing, nil
	}
	line, col := ast.Lineno, ast.ColOffset
	nodeType := builderNodeType(ast.Type)
	nodeID := builderNodeID(s.filePath, line, col, nodeType)
	if existing, ok := s.nodeByID[nodeID]; ok {
		s.nodeOf[ast] = existing
		return existing, nil
	}
	node := &CPGNode{
		NodeID:         nodeID,
		FilePath:       s.filePath,
		Line:           line,
		Col:            col,
		EndLine:        ast.EndLineno,
		EndCol:         ast.EndColOffset,
		NodeType:       nodeType,
		EnclosingScope: scope.name,
		ScopeID:        scope.id,
		Attributes:     map[string]interface{}{"ast_type": ast.Type},
		AST:            ast,
	}
	if code := builderSourceText(ast); code != "" {
		node.CodeStr = code
		node.Attributes["src"] = code
	}
	if symbol := builderSymbolName(ast); symbol != "" {
		node.SymbolName = symbol
	}
	if targets := builderAssignTargets(ast); len(targets) > 0 {
		node.Attributes["targets"] = targets
	}
	if err := s.g.AddNode(node); err != nil {
		return nil, err
	}
	s.nodeOf[ast] = node
	s.nodeByID[nodeID] = node
	s.created = append(s.created, node)
	if nodeType == AST_CALL {
		s.callRefs = append(s.callRefs, builderCallRef{ast: ast, node: node})
	}
	return node, nil
}

// builderNodeID renders the canonical node identifier of the CPG.
func builderNodeID(filePath string, line, col int, nodeType NodeType) string {
	return fmt.Sprintf("%s:%d:%d:%s", filePath, line, col, nodeType)
}

// builderNodeType maps a Python AST class name to its CPG node type.
func builderNodeType(astType string) NodeType {
	switch astType {
	case "FunctionDef", "AsyncFunctionDef":
		return AST_FUNC_DEF
	case "ClassDef":
		return AST_CLASS_DEF
	case "Call":
		return AST_CALL
	case "Assign", "AnnAssign", "AugAssign":
		return AST_ASSIGN
	case "Return":
		return AST_RETURN
	case "Import", "ImportFrom":
		return AST_IMPORT
	case "arg":
		return AST_PARAM
	case "If":
		return AST_IF
	case "For", "AsyncFor":
		return AST_FOR
	case "While":
		return AST_WHILE
	case "Try", "TryStar":
		return AST_TRY
	case "Expr":
		return AST_EXPR
	case "Module":
		return AST_MODULE
	}
	if builderStatementTypes[astType] {
		return AST_STMT
	}
	return AST_EXPR
}

// builderSymbolName returns the symbol a node defines or references.
func builderSymbolName(ast *ASTNode) string {
	switch ast.Type {
	case "Call":
		return ast.GetCallFuncName()
	case "FunctionDef", "AsyncFunctionDef", "ClassDef":
		return ast.Name
	case "arg":
		return ast.Name
	case "Assign", "AnnAssign", "AugAssign":
		if names := builderAssignTargets(ast); len(names) > 0 {
			return names[0]
		}
	}
	return ""
}

// builderAssignTargets returns the simple Name targets bound by an assignment.
func builderAssignTargets(ast *ASTNode) []string {
	switch ast.Type {
	case "Assign":
		var names []string
		for _, target := range ast.Targets {
			if target != nil && target.Type == "Name" && target.ID != "" {
				names = append(names, target.ID)
			}
		}
		return names
	case "AnnAssign", "AugAssign":
		if ast.Target != nil && ast.Target.Type == "Name" && ast.Target.ID != "" {
			return []string{ast.Target.ID}
		}
	}
	return nil
}

// builderTargetNames reads back the target names stored on an assignment node.
func builderTargetNames(node *CPGNode) []string {
	if node == nil || node.Attributes == nil {
		return nil
	}
	if names, ok := node.Attributes["targets"].([]string); ok {
		return names
	}
	return nil
}

// builderSourceText derives a short source-like rendering of an AST node where
// one can be recovered from the parsed representation.
func builderSourceText(ast *ASTNode) string {
	switch ast.Type {
	case "Module":
		return ""
	case "FunctionDef":
		return "def " + ast.Name + "(...)"
	case "AsyncFunctionDef":
		return "async def " + ast.Name + "(...)"
	case "ClassDef":
		return "class " + ast.Name
	case "Call":
		if name := ast.GetCallFuncName(); name != "" {
			return name + "(...)"
		}
		return "call(...)"
	case "Name":
		return ast.ID
	case "arg":
		return ast.Name
	case "Attribute":
		return ast.GetDottedName()
	case "Constant":
		if ast.ValueStr != "" {
			return ast.ValueStr
		}
		if ast.Literal != nil {
			return fmt.Sprint(ast.Literal)
		}
		return "None"
	case "Return":
		return "return"
	case "Assign", "AnnAssign", "AugAssign":
		if names := builderAssignTargets(ast); len(names) > 0 {
			return strings.Join(names, ", ") + " = ..."
		}
		return "assignment"
	case "Import":
		if names := ast.GetImportedNames(); len(names) > 0 {
			return "import " + strings.Join(names, ", ")
		}
		return "import"
	case "ImportFrom":
		target := ast.Module
		if ast.Level > 0 {
			target = strings.Repeat(".", ast.Level) + ast.Module
		}
		if names := ast.GetImportedNames(); len(names) > 0 {
			return "from " + target + " import " + strings.Join(names, ", ")
		}
		return "from " + target + " import ..."
	}
	return ast.Type
}

// ---------------------------------------------------------------------------
// Layer 3: intra-procedural control flow
// ---------------------------------------------------------------------------

// builderChildStatementLists returns the statement lists nested directly inside
// a statement.
func builderChildStatementLists(ast *ASTNode) [][]*ASTNode {
	lists := [][]*ASTNode{ast.Body, ast.Orelse, ast.Finalbody}
	for _, handler := range ast.Handlers {
		if handler != nil {
			lists = append(lists, handler.Body)
		}
	}
	return lists
}

// linkStatements lays out the control flow of one statement list and recurses
// into the nested lists of every statement.
func (s *builderFileState) linkStatements(stmts []*ASTNode) {
	for i, cur := range stmts {
		var next *ASTNode
		if i+1 < len(stmts) {
			next = stmts[i+1]
		}
		s.linkControl(cur, next)
		if next != nil {
			s.addASTEdge(cur, next, CFG_NEXT)
		}
		for _, nested := range builderChildStatementLists(cur) {
			s.linkStatements(nested)
		}
	}
}

// linkControl emits the branch, loop and exception edges of a single statement.
func (s *builderFileState) linkControl(cur, next *ASTNode) {
	switch cur.Type {
	case "If":
		if len(cur.Body) > 0 {
			s.addASTEdge(cur, cur.Body[0], CFG_BRANCH_TRUE)
		}
		if len(cur.Orelse) > 0 {
			s.addASTEdge(cur, cur.Orelse[0], CFG_BRANCH_FALSE)
		} else if next != nil {
			s.addASTEdge(cur, next, CFG_BRANCH_FALSE)
		}
	case "For", "AsyncFor", "While":
		if next != nil {
			s.addASTEdge(cur, next, CFG_LOOP_EXIT)
		}
	case "Try", "TryStar":
		for _, handler := range cur.Handlers {
			if handler != nil && len(handler.Body) > 0 {
				s.addASTEdge(cur, handler.Body[0], CFG_EXCEPT)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 3: intra-procedural data flow
// ---------------------------------------------------------------------------

// buildDFG connects every assignment to the later nodes of the same scope that
// load the assigned name. Definitions never cross a scope boundary.
func (s *builderFileState) buildDFG() {
	scopes := make(map[string][]*CPGNode)
	var order []string
	for _, node := range s.created {
		if node.ScopeID == "" {
			continue
		}
		if _, seen := scopes[node.ScopeID]; !seen {
			order = append(order, node.ScopeID)
		}
		scopes[node.ScopeID] = append(scopes[node.ScopeID], node)
	}

	for _, scopeID := range order {
		nodes := scopes[scopeID]
		loaded := make([]map[string]bool, len(nodes))
		for i, node := range nodes {
			loaded[i] = builderLoadedNames(node.AST)
		}
		for i, def := range nodes {
			if def.NodeType != AST_ASSIGN {
				continue
			}
			targets := builderTargetNames(def)
			if len(targets) == 0 {
				continue
			}
			for j := i + 1; j < len(nodes); j++ {
				use := nodes[j]
				for _, name := range targets {
					if !loaded[j][name] {
						continue
					}
					s.addEdge(def.NodeID, use.NodeID, DFG_DEF_USE, map[string]interface{}{"var": name})
				}
			}
		}
	}
}

// builderLoadedNames collects the identifiers a subtree reads.
func builderLoadedNames(ast *ASTNode) map[string]bool {
	if ast == nil {
		return nil
	}
	names := make(map[string]bool)
	ast.Walk(func(n *ASTNode) bool {
		if n.Type == "Name" && n.ID != "" && n.Ctx != "Store" && n.Ctx != "Del" {
			names[n.ID] = true
		}
		return true
	})
	return names
}

// ---------------------------------------------------------------------------
// Inter-procedural call edges
// ---------------------------------------------------------------------------

// collectFunctions registers every function definition of the current file in
// the builder index.
func (s *builderFileState) collectFunctions() {
	for _, def := range s.created {
		if def.NodeType != AST_FUNC_DEF || def.SymbolName == "" {
			continue
		}
		info := &builderFuncInfo{
			filePath: s.filePath,
			name:     def.SymbolName,
			defID:    def.NodeID,
			fqn:      s.b.resolver.FQN(s.module, def.SymbolName),
		}
		for _, param := range s.paramsOf[def.NodeID] {
			info.params = append(info.params, param)
			info.paramNames = append(info.paramNames, param.SymbolName)
		}
		for _, node := range s.created {
			if node.NodeType == AST_RETURN && node.ScopeID == def.NodeID {
				info.returns = append(info.returns, node)
			}
		}
		s.b.funcIndex[info.name] = append(s.b.funcIndex[info.name], info)
	}
}

// collectAliases records the local name bound by every import of the current
// file, so dotted callees can be expanded into fully-qualified names.
func (s *builderFileState) collectAliases() {
	aliases := make(map[string]string)
	for _, node := range s.created {
		if node.NodeType != AST_IMPORT || node.AST == nil {
			continue
		}
		ast := node.AST
		switch ast.Type {
		case "Import":
			for _, alias := range ast.Names {
				if alias == nil || alias.Name == "" {
					continue
				}
				if alias.AsName != "" {
					aliases[alias.AsName] = alias.Name
					continue
				}
				// "import pkg.util" binds the top-level name "pkg".
				head := strings.Split(alias.Name, ".")[0]
				aliases[head] = head
			}
		case "ImportFrom":
			base, ok := s.b.resolver.ResolveImport(s.filePath, ast.Module, ast.Level)
			if !ok {
				base = ast.Module
			}
			if base == "" {
				continue
			}
			for _, alias := range ast.Names {
				if alias == nil || alias.Name == "" || alias.Name == "*" {
					continue
				}
				local := alias.Name
				if alias.AsName != "" {
					local = alias.AsName
				}
				aliases[local] = base + "." + alias.Name
			}
		}
	}
	if len(aliases) > 0 {
		s.b.aliases[s.filePath] = aliases
	}
}

// recordCallSites stores the call expressions of the current file together with
// their argument nodes. It runs after the whole file has been converted so all
// argument nodes exist.
func (s *builderFileState) recordCallSites() {
	for _, ref := range s.callRefs {
		callee := ref.ast.GetCallFuncName()
		if callee == "" {
			continue
		}
		site := &builderCallSite{callID: ref.node.NodeID, filePath: s.filePath, callee: callee}
		for i, arg := range ref.ast.Args {
			if arg == nil {
				continue
			}
			if node, ok := s.nodeOf[arg]; ok {
				site.positional = append(site.positional, builderCallArg{index: i, node: node})
			}
		}
		for _, keyword := range ref.ast.Keywords {
			if keyword == nil || keyword.Value == nil {
				continue
			}
			if node, ok := s.nodeOf[keyword.Value]; ok {
				site.keyword = append(site.keyword, builderCallArg{name: keyword.Arg, node: node})
			}
		}
		s.b.calls = append(s.b.calls, site)
	}
}

// resolveCallSites binds every still unresolved call site to a callee and
// emits the CALL, CALL_ARG and CALL_RET edges.
func (b *CPGBuilder) resolveCallSites(g *CodePropertyGraph) {
	if g == nil {
		return
	}
	for _, site := range b.calls {
		if site.resolved {
			continue
		}
		callee := b.matchCallee(site)
		if callee == nil {
			continue
		}
		site.resolved = true
		b.emitCallEdges(g, site, callee)
	}
}

// matchCallee looks up the function a call site refers to. A definition in the
// same file wins, then a definition matching the import-aware fully-qualified
// name, then the only definition carrying the simple name.
func (b *CPGBuilder) matchCallee(site *builderCallSite) *builderFuncInfo {
	simple := builderSimpleName(site.callee)
	if simple == "" {
		return nil
	}
	candidates := b.funcIndex[simple]
	if len(candidates) == 0 {
		return nil
	}
	for _, candidate := range candidates {
		if candidate.filePath == site.filePath {
			return candidate
		}
	}
	if fqn := b.qualifiedCallee(site); fqn != "" {
		for _, candidate := range candidates {
			if candidate.fqn == fqn {
				return candidate
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return nil
}

// qualifiedCallee expands a dotted callee through the import aliases of the
// calling file, falling back to the literal dotted prefix.
func (b *CPGBuilder) qualifiedCallee(site *builderCallSite) string {
	parts := strings.Split(site.callee, ".")
	if len(parts) < 2 {
		return ""
	}
	head := parts[0]
	rest := strings.Join(parts[1:], ".")
	if aliases := b.aliases[site.filePath]; aliases != nil {
		if module := aliases[head]; module != "" {
			return b.resolver.FQN(module, rest)
		}
	}
	return b.resolver.FQN(strings.Join(parts[:len(parts)-1], "."), parts[len(parts)-1])
}

// emitCallEdges connects a resolved call site with its callee.
func (b *CPGBuilder) emitCallEdges(g *CodePropertyGraph, site *builderCallSite, callee *builderFuncInfo) {
	_ = g.AddEdge(&CPGEdge{SourceID: site.callID, TargetID: callee.defID, EdgeType: CALL})
	for _, arg := range site.positional {
		if arg.index < len(callee.params) {
			_ = g.AddEdge(&CPGEdge{
				SourceID: arg.node.NodeID,
				TargetID: callee.params[arg.index].NodeID,
				EdgeType: CALL_ARG,
				Metadata: map[string]interface{}{"index": arg.index},
			})
		}
	}
	for _, arg := range site.keyword {
		if index := builderParamIndex(callee, arg.name); index >= 0 {
			_ = g.AddEdge(&CPGEdge{
				SourceID: arg.node.NodeID,
				TargetID: callee.params[index].NodeID,
				EdgeType: CALL_ARG,
				Metadata: map[string]interface{}{"keyword": arg.name},
			})
		}
	}
	for _, ret := range callee.returns {
		_ = g.AddEdge(&CPGEdge{SourceID: ret.NodeID, TargetID: site.callID, EdgeType: CALL_RET})
	}
}

// builderParamIndex returns the position of a named parameter, or -1.
func builderParamIndex(info *builderFuncInfo, name string) int {
	for i, param := range info.paramNames {
		if param == name {
			return i
		}
	}
	return -1
}

// builderSimpleName returns the last component of a dotted name.
func builderSimpleName(dotted string) string {
	if index := strings.LastIndex(dotted, "."); index >= 0 {
		return dotted[index+1:]
	}
	return dotted
}

// ---------------------------------------------------------------------------
// Edge helpers
// ---------------------------------------------------------------------------

// addASTEdge connects the CPG nodes of two AST nodes when both exist.
func (s *builderFileState) addASTEdge(src, dst *ASTNode, edgeType EdgeType) {
	srcNode, ok := s.nodeOf[src]
	if !ok {
		return
	}
	dstNode, ok := s.nodeOf[dst]
	if !ok {
		return
	}
	s.addEdge(srcNode.NodeID, dstNode.NodeID, edgeType, nil)
}

// addEdge appends a directed edge to the graph. Endpoints are always non-empty
// here, so an insertion cannot fail.
func (s *builderFileState) addEdge(srcID, dstID string, edgeType EdgeType, metadata map[string]interface{}) {
	if srcID == "" || dstID == "" {
		return
	}
	_ = s.g.AddEdge(&CPGEdge{
		SourceID: srcID,
		TargetID: dstID,
		EdgeType: edgeType,
		Metadata: metadata,
	})
}
