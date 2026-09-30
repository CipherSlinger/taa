package cpg

import (
	"sort"
	"strings"
)

// This file implements layer 5 of the Code Property Graph: an inter-procedural,
// worklist (breadth first) taint engine. It starts from every source node of
// the graph and propagates taint along the data flow, call and microservice
// boundary edges until a sink is reached, producing evidence whose fields
// mirror the production taint violation schema one for one.

// Taint trajectory step types.
const (
	taintStepSource         = "SOURCE"
	taintStepInterProcCall  = "INTER_PROC_CALL"
	taintStepMicroEgress    = "MICROSERVICE_EGRESS"
	taintStepMicroIngress   = "MICROSERVICE_INGRESS"
	taintStepDFGPropagation = "DFG_PROPAGATION"
	taintStepSink           = "SINK"
)

// Taint source and sink families.
const (
	taintFamilyEnv          = "ENV_001"
	taintFamilyFile         = "FIL_001"
	taintFamilyRawData      = "RAW_DATA"
	taintFamilyCommand      = "CMD_001"
	taintFamilyNetwork      = "NET_001"
	taintFamilyExfiltration = "EXF_001"
)

// Sink categories, resolved before the source family is taken into account.
const (
	taintSinkCategoryCommand = "command"
	taintSinkCategoryNetwork = "network"
)

// taintMicroservicePrefix marks every microservice boundary edge type.
const taintMicroservicePrefix = "MICROSERVICE_"

// taintDefaultMaxHops is the default path budget of the engine.
const taintDefaultMaxHops = 50

// taintLiftMaxDepth bounds the ancestor walk performed when a boundary edge
// lands on an expression rather than on the statement binding it.
const taintLiftMaxDepth = 8

// taintEnvCallNames are the callees reading the process environment.
var taintEnvCallNames = map[string]bool{
	"os.environ.get": true,
	"os.getenv":      true,
}

// taintFileCallNames are the callees opening or reading a file.
var taintFileCallNames = map[string]bool{
	"open": true,
}

// taintFileCallSuffixes are the callee suffixes reading a file resource.
var taintFileCallSuffixes = []string{".read_text", ".read_bytes", ".readlines"}

// taintRawDataCallNames are the callees loading a raw data set.
var taintRawDataCallNames = map[string]bool{
	"pd.read_csv":     true,
	"pandas.read_csv": true,
	"np.load":         true,
	"numpy.load":      true,
	"torch.load":      true,
}

// taintCommandCallNames are the callees executing an operating system command.
var taintCommandCallNames = map[string]bool{
	"os.system":               true,
	"os.popen":                true,
	"subprocess.Popen":        true,
	"subprocess.run":          true,
	"subprocess.call":         true,
	"subprocess.check_output": true,
	"subprocess.check_call":   true,
	"commands.getoutput":      true,
	"eval":                    true,
	"exec":                    true,
	"pty.spawn":               true,
	"paramiko.exec_command":   true,
}

// taintCommandCallPrefixes are the callee prefixes executing a process image.
var taintCommandCallPrefixes = []string{"os.exec", "os.spawn"}

// taintNetworkCallNames are the fully qualified network callees.
var taintNetworkCallNames = map[string]bool{
	"urllib.request.urlopen": true,
	"requests.request":       true,
	"httpx.request":          true,
}

// taintNetworkCallPrefixes are the module prefixes marking an outbound network
// call.
var taintNetworkCallPrefixes = []string{"requests.", "httpx.", "socket."}

// taintSanitizerCallNames are the callees that neutralise a tainted value.
var taintSanitizerCallNames = map[string]bool{
	"hashlib.sha256": true,
	"hashlib.sha1":   true,
	"hashlib.md5":    true,
	"hashlib.sha512": true,
	"hmac.new":       true,
}

// taintTraversalEdges is the single inventory of the edges the worklist
// follows, mapped to the evidence step type each renders as.
//
// One table rather than a set plus a classifier: an edge type cannot be
// traversable without also being classifiable, so adding an edge means adding
// one line here instead of editing two lists and hoping they agree.
var taintTraversalEdges = map[EdgeType]string{
	DFG_DEF_USE:           taintStepDFGPropagation,
	CALL_ARG:              taintStepInterProcCall,
	CALL_RET:              taintStepInterProcCall,
	CALL:                  taintStepInterProcCall,
	MICROSERVICE_PAYLOAD:  taintStepMicroIngress,
	MICROSERVICE_HTTP:     taintStepMicroIngress,
	MICROSERVICE_RESPONSE: taintStepMicroIngress,
}

// TaintStep mirrors the production evidence schema field for field: one hop of
// a taint trajectory, from a source towards a sink.
type TaintStep struct {
	Step           int
	Type           string
	File           string
	Line           int
	Code           string
	EnclosingScope string
	EdgeType       string
}

// TaintViolation mirrors the production evidence schema field for field: a
// complete source to sink taint trajectory.
type TaintViolation struct {
	SourceID           string
	SinkID             string
	SourceFamily       string
	SinkFamily         string
	Steps              []TaintStep
	CrossFile          bool
	AcrossMicroservice bool
}

// InterProceduralTaintEngine propagates taint from every source node of a graph
// with a breadth first worklist. The visited set is keyed by the pair (node,
// source), so the same node can still be reached from a different source and
// recursive cycles terminate.
type InterProceduralTaintEngine struct {
	// MaxHops bounds the number of edges a single path may traverse. A path
	// that needs more hops yields no violation.
	MaxHops int
}

// NewInterProceduralTaintEngine creates an engine with the default path budget.
func NewInterProceduralTaintEngine() *InterProceduralTaintEngine {
	return &InterProceduralTaintEngine{MaxHops: taintDefaultMaxHops}
}

// taintWorkItem is one pending node of the worklist together with the source it
// was reached from and the trajectory that leads to it.
type taintWorkItem struct {
	nodeID   string
	sourceID string
	family   string
	hops     int
	steps    []TaintStep
}

// FindViolations returns every taint violation of the graph. Violations are
// deduplicated on (source, sink, sink family) and sorted deterministically.
func (e *InterProceduralTaintEngine) FindViolations(g *CodePropertyGraph) []*TaintViolation {
	if g == nil {
		return nil
	}

	maxHops := taintDefaultMaxHops
	if e != nil && e.MaxHops > 0 {
		maxHops = e.MaxHops
	}

	sources := taintCollectSources(g)
	if len(sources) == 0 {
		return nil
	}

	// Prime the worklist with every source. The source node is keyed with
	// itself as the reaching source, so two sources sharing a node are visited
	// once each.
	visited := make(map[string]bool)
	queue := make([]taintWorkItem, 0, len(sources))
	for _, source := range sources {
		key := taintVisitKey(source.node.NodeID, source.node.NodeID)
		if visited[key] {
			continue
		}
		visited[key] = true
		queue = append(queue, taintWorkItem{
			nodeID:   source.node.NodeID,
			sourceID: source.node.NodeID,
			family:   source.family,
			steps:    []TaintStep{taintSourceStep(source.node)},
		})
	}

	found := make(map[string]bool)
	var violations []*TaintViolation

	// Whether a node sanitises depends only on the node, and the graph does not
	// change during the traversal, so each node's answer is computed once
	// instead of once per work item that reaches it.
	sanitized := make(map[*CPGNode]bool)
	isSanitizer := func(node *CPGNode) bool {
		if cached, ok := sanitized[node]; ok {
			return cached
		}
		result := taintIsSanitizer(node)
		sanitized[node] = result
		return result
	}

	for head := 0; head < len(queue); head++ {
		item := queue[head]
		node, ok := g.GetNode(item.nodeID)
		if !ok {
			continue
		}

		// A sink closes every path that reaches it. The path is not cut here:
		// the value handed to a sink can still flow further.
		if sinkFamily := taintSinkFamilyFor(node, item.family); sinkFamily != "" {
			key := taintViolationKey(item.sourceID, node.NodeID, sinkFamily)
			if !found[key] {
				found[key] = true
				violations = append(violations, taintNewViolation(item, node, sinkFamily))
			}
		}

		if item.hops >= maxHops || isSanitizer(node) {
			continue
		}

		// enqueue records one traversed edge: the reached node and, when a
		// boundary edge lands on an expression, the statement binding it.
		enqueue := func(target *CPGNode, edge *CPGEdge) {
			if target == nil {
				return
			}
			key := taintVisitKey(target.NodeID, item.sourceID)
			if visited[key] {
				return
			}
			visited[key] = true

			steps := make([]TaintStep, len(item.steps), len(item.steps)+1)
			copy(steps, item.steps)
			steps = append(steps, taintTraversalStep(item, node, edge, target))

			queue = append(queue, taintWorkItem{
				nodeID:   target.NodeID,
				sourceID: item.sourceID,
				family:   item.family,
				hops:     item.hops + 1,
				steps:    steps,
			})
		}

		for _, edge := range g.GetSuccessors(item.nodeID) {
			if edge == nil {
				continue
			}
			if _, ok := taintTraversalEdges[edge.EdgeType]; !ok {
				continue
			}
			target, ok := g.GetNode(edge.TargetID)
			if !ok {
				continue
			}
			enqueue(target, edge)
			if taintIsBoundaryEdge(edge.EdgeType) {
				// The inbound payload is bound by the enclosing statement, so
				// the handler data flow is entered through it.
				if lift := taintBoundaryLift(g, target); lift != nil {
					enqueue(lift, edge)
				}
			}
		}
	}

	if len(violations) == 0 {
		return nil
	}
	sort.Slice(violations, func(i, j int) bool {
		left, right := violations[i], violations[j]
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.SinkID != right.SinkID {
			return left.SinkID < right.SinkID
		}
		return left.SinkFamily < right.SinkFamily
	})
	return violations
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// taintSource is a source node together with the family it was classified as.
// The family is decided once, where the node is found, rather than recomputed
// by every caller that needs it.
type taintSource struct {
	node   *CPGNode
	family string
}

// taintCollectSources returns every source node of the graph ordered by node ID
// so that the worklist is deterministic regardless of map iteration order.
func taintCollectSources(g *CodePropertyGraph) []taintSource {
	var sources []taintSource
	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		family := taintSourceFamily(node)
		if family == "" {
			continue
		}
		sources = append(sources, taintSource{node: node, family: family})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].node.NodeID < sources[j].node.NodeID })
	return sources
}

// taintSourceFamily reports the source family a node belongs to, or "" when the
// node is not a source. A node is a source when its AST subtree reads an
// environment variable, opens or reads a file, or loads a raw data set; the
// statement binding such an expression is a source as well, which is what
// carries the taint into the data flow. When the AST is absent the symbol name
// of the node is matched instead.
func taintSourceFamily(node *CPGNode) string {
	if node == nil {
		return ""
	}
	if node.AST == nil {
		return taintSourceFamilyOfName(node.SymbolName)
	}

	family := ""
	node.AST.Walk(func(n *ASTNode) bool {
		if n == nil {
			return true
		}
		candidate := taintSourceFamilyOfAST(n)
		if taintSourceFamilyRank(candidate) > taintSourceFamilyRank(family) {
			family = candidate
		}
		return family != taintFamilyEnv
	})
	return family
}

// taintSourceFamilyOfAST matches a single AST node against the source rules.
func taintSourceFamilyOfAST(n *ASTNode) string {
	if n == nil {
		return ""
	}
	switch n.Type {
	case "Call":
		return taintSourceFamilyOfName(n.GetCallFuncName())
	case "Subscript":
		if n.Value != nil && n.Value.GetDottedName() == "os.environ" {
			return taintFamilyEnv
		}
	}
	return ""
}

// taintSourceFamilyOfName matches a dotted callee or symbol name against the
// source callees.
func taintSourceFamilyOfName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if taintEnvCallNames[name] {
		return taintFamilyEnv
	}
	if taintFileCallNames[name] {
		return taintFamilyFile
	}
	for _, suffix := range taintFileCallSuffixes {
		if strings.HasSuffix(name, suffix) {
			return taintFamilyFile
		}
	}
	if taintRawDataCallNames[name] {
		return taintFamilyRawData
	}
	return ""
}

// taintSourceFamilyRank orders the families so that a node matching several
// source rules reports the most specific one.
func taintSourceFamilyRank(family string) int {
	switch family {
	case taintFamilyEnv:
		return 3
	case taintFamilyFile:
		return 2
	case taintFamilyRawData:
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Sinks and sanitizers
// ---------------------------------------------------------------------------

// taintSinkCategory reports whether a node is a command sink, a network sink or
// no sink at all. Only the node itself is inspected, never its subtree, so that
// a statement merely containing a sink call is not reported as one.
func taintSinkCategory(node *CPGNode) string {
	if node == nil {
		return ""
	}
	name := ""
	if node.AST != nil {
		name = node.AST.GetCallFuncName()
	}
	if name == "" {
		name = node.SymbolName
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}

	if taintCommandCallNames[name] {
		return taintSinkCategoryCommand
	}
	for _, prefix := range taintCommandCallPrefixes {
		if strings.HasPrefix(name, prefix) {
			return taintSinkCategoryCommand
		}
	}
	if taintNetworkCallNames[name] {
		return taintSinkCategoryNetwork
	}
	for _, prefix := range taintNetworkCallPrefixes {
		if strings.HasPrefix(name, prefix) {
			return taintSinkCategoryNetwork
		}
	}
	return ""
}

// taintSinkFamilyFor resolves the reported sink family of a node. A command
// sink is always CMD_001. A network sink reached from an environment or file
// source escalates to an exfiltration and is NET_001 otherwise.
func taintSinkFamilyFor(node *CPGNode, sourceFamily string) string {
	switch taintSinkCategory(node) {
	case taintSinkCategoryCommand:
		return taintFamilyCommand
	case taintSinkCategoryNetwork:
		if sourceFamily == taintFamilyEnv || sourceFamily == taintFamilyFile {
			return taintFamilyExfiltration
		}
		return taintFamilyNetwork
	}
	return ""
}

// taintIsSanitizer reports whether a path must stop at the node. A node is a
// sanitizer when its AST subtree performs a neutralizing transformation: either
// the call itself or the statement that binds its result, which is what the
// following reads of the bound name would otherwise propagate.
func taintIsSanitizer(node *CPGNode) bool {
	if node == nil {
		return false
	}
	if node.AST == nil {
		return taintSanitizerCallNames[node.SymbolName]
	}

	sanitized := false
	node.AST.Walk(func(n *ASTNode) bool {
		if sanitized {
			return false
		}
		if n != nil && n.Type == "Call" && taintSanitizerCallNames[n.GetCallFuncName()] {
			sanitized = true
			return false
		}
		return true
	})
	return sanitized
}

// ---------------------------------------------------------------------------
// Traversal helpers
// ---------------------------------------------------------------------------

// taintIsBoundaryEdge reports whether an edge crosses a service boundary.
func taintIsBoundaryEdge(edgeType EdgeType) bool {
	return strings.HasPrefix(string(edgeType), taintMicroservicePrefix)
}

// taintVisitKey is the visited set key: a node is visited once per source.
func taintVisitKey(nodeID, sourceID string) string {
	return nodeID + "\x00" + sourceID
}

// taintViolationKey deduplicates the reported violations.
func taintViolationKey(sourceID, sinkID, sinkFamily string) string {
	return sourceID + "\x00" + sinkID + "\x00" + sinkFamily
}

// taintSourceStep renders the first step of a trajectory.
func taintSourceStep(node *CPGNode) TaintStep {
	return TaintStep{
		Step:           1,
		Type:           taintStepSource,
		File:           node.FilePath,
		Line:           node.Line,
		Code:           node.CodeStr,
		EnclosingScope: node.EnclosingScope,
	}
}

// taintTraversalStep renders the step of a node reached through one edge.
func taintTraversalStep(item taintWorkItem, from *CPGNode, edge *CPGEdge, target *CPGNode) TaintStep {
	return TaintStep{
		Step:           len(item.steps) + 1,
		Type:           taintTraversalStepType(edge.EdgeType, from, target),
		File:           target.FilePath,
		Line:           target.Line,
		Code:           target.CodeStr,
		EnclosingScope: target.EnclosingScope,
		EdgeType:       string(edge.EdgeType),
	}
}

// taintTraversalStepType classifies a traversed edge into an evidence step
// type. A boundary edge leaving the file of the current node is an egress, one
// staying inside it an ingress.
func taintTraversalStepType(edgeType EdgeType, from, target *CPGNode) string {
	stepType, ok := taintTraversalEdges[edgeType]
	if !ok {
		return taintStepDFGPropagation
	}
	if stepType == taintStepMicroIngress && target != nil && from != nil && target.FilePath != from.FilePath {
		return taintStepMicroEgress
	}
	return stepType
}

// taintNewViolation assembles the evidence of a source to sink path. The last
// step of the path becomes the sink step.
func taintNewViolation(item taintWorkItem, sink *CPGNode, sinkFamily string) *TaintViolation {
	steps := make([]TaintStep, len(item.steps))
	copy(steps, item.steps)
	steps[len(steps)-1].Type = taintStepSink

	violation := &TaintViolation{
		SourceID:     item.sourceID,
		SinkID:       sink.NodeID,
		SourceFamily: item.family,
		SinkFamily:   sinkFamily,
		Steps:        steps,
	}
	for _, step := range steps {
		if step.File != steps[0].File {
			violation.CrossFile = true
		}
		if taintIsBoundaryEdge(EdgeType(step.EdgeType)) {
			violation.AcrossMicroservice = true
		}
	}
	return violation
}

// taintBoundaryLift resolves the statement a boundary edge hands its payload to:
// the nearest enclosing node that is either an assignment, which stores the
// payload in a local variable, or a sink call, which consumes it directly. It
// returns nil when the node has no such ancestor.
func taintBoundaryLift(g *CodePropertyGraph, node *CPGNode) *CPGNode {
	if g == nil || node == nil {
		return nil
	}

	seen := map[string]bool{node.NodeID: true}
	level := []*CPGNode{node}
	for depth := 0; depth < taintLiftMaxDepth && len(level) > 0; depth++ {
		var next []*CPGNode
		for _, candidate := range level {
			for _, edge := range g.GetPredecessors(candidate.NodeID) {
				if edge == nil || edge.EdgeType != AST_CHILD {
					continue
				}
				parent, ok := g.GetNode(edge.SourceID)
				if !ok || parent == nil || seen[parent.NodeID] {
					continue
				}
				seen[parent.NodeID] = true
				if parent.NodeType == AST_ASSIGN || taintSinkCategory(parent) != "" {
					return parent
				}
				next = append(next, parent)
			}
		}
		level = next
	}
	return nil
}
