package cpg

import (
	"errors"
	"fmt"
	"sync"
)

// NodeType represents the structural or semantic category of a CPG node.
type NodeType string

const (
	// AST layer node types
	AST_MODULE    NodeType = "AST_MODULE"
	AST_STMT      NodeType = "AST_STMT"
	AST_EXPR      NodeType = "AST_EXPR"
	AST_CALL      NodeType = "AST_CALL"
	AST_ASSIGN    NodeType = "AST_ASSIGN"
	AST_FUNC_DEF  NodeType = "AST_FUNC_DEF"
	AST_CLASS_DEF NodeType = "AST_CLASS_DEF"
	AST_RETURN    NodeType = "AST_RETURN"
	AST_PARAM     NodeType = "AST_PARAM"
	AST_IMPORT    NodeType = "AST_IMPORT"
	AST_IF        NodeType = "AST_IF"
	AST_FOR       NodeType = "AST_FOR"
	AST_WHILE     NodeType = "AST_WHILE"
	AST_TRY       NodeType = "AST_TRY"

	// Microservice boundary node types
	MICROSERVICE_CLIENT   NodeType = "MICROSERVICE_CLIENT"
	MICROSERVICE_ENDPOINT NodeType = "MICROSERVICE_ENDPOINT"
)

// EdgeType represents the relational or semantic category of an edge connecting CPG nodes.
type EdgeType string

const (
	// AST hierarchy
	AST_CHILD EdgeType = "AST_CHILD"

	// CFG (Control Flow Graph)
	CFG_NEXT         EdgeType = "CFG_NEXT"
	CFG_BRANCH_TRUE  EdgeType = "CFG_BRANCH_TRUE"
	CFG_BRANCH_FALSE EdgeType = "CFG_BRANCH_FALSE"
	CFG_LOOP_EXIT    EdgeType = "CFG_LOOP_EXIT"
	CFG_EXCEPT       EdgeType = "CFG_EXCEPT"

	// DFG (Data Flow Graph)
	DFG_DEF_USE EdgeType = "DFG_DEF_USE"

	// Inter-procedural Call Graph
	CALL     EdgeType = "CALL"
	CALL_ARG EdgeType = "CALL_ARG"
	CALL_RET EdgeType = "CALL_RET"

	// Microservice boundary edges
	MICROSERVICE_HTTP     EdgeType = "MICROSERVICE_HTTP"
	MICROSERVICE_PAYLOAD  EdgeType = "MICROSERVICE_PAYLOAD"
	MICROSERVICE_RESPONSE EdgeType = "MICROSERVICE_RESPONSE"
)

// CPGNode represents a single vertex in the Code Property Graph.
type CPGNode struct {
	NodeID         string                 `json:"node_id"`
	FilePath       string                 `json:"file_path"`
	Line           int                    `json:"line"`
	Col            int                    `json:"col"`
	EndLine        int                    `json:"end_line"`
	EndCol         int                    `json:"end_col"`
	NodeType       NodeType               `json:"node_type"`
	CodeStr        string                 `json:"code_str"`
	EnclosingScope string                 `json:"enclosing_scope,omitempty"`
	ScopeID        string                 `json:"scope_id,omitempty"`
	SymbolName     string                 `json:"symbol_name,omitempty"`
	Attributes     map[string]interface{} `json:"attributes,omitempty"`

	// AST holds the raw syntax tree node this CPG node was derived from.
	// It is intentionally excluded from JSON serialization because it is an
	// in-memory analysis aid, not report evidence.
	AST *ASTNode `json:"-"`
}

// CPGEdge represents a directed connection between two nodes in the Code Property Graph.
type CPGEdge struct {
	SourceID string                 `json:"source_id"`
	TargetID string                 `json:"target_id"`
	EdgeType EdgeType               `json:"edge_type"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CodePropertyGraph stores the combined graph representation with inverted indices.
type CodePropertyGraph struct {
	mu sync.RWMutex

	nodes         map[string]*CPGNode
	adjOut        map[string][]*CPGEdge
	adjIn         map[string][]*CPGEdge
	fileLineIndex map[string]map[int][]*CPGNode
	symbolIndex   map[string][]*CPGNode
	typeIndex     map[NodeType][]*CPGNode
}

// NewCodePropertyGraph creates an initialized, thread-safe CodePropertyGraph instance.
func NewCodePropertyGraph() *CodePropertyGraph {
	return &CodePropertyGraph{
		nodes:         make(map[string]*CPGNode),
		adjOut:        make(map[string][]*CPGEdge),
		adjIn:         make(map[string][]*CPGEdge),
		fileLineIndex: make(map[string]map[int][]*CPGNode),
		symbolIndex:   make(map[string][]*CPGNode),
		typeIndex:     make(map[NodeType][]*CPGNode),
	}
}

// AddNode adds a new node to the graph and populates all relevant inverted indices.
func (g *CodePropertyGraph) AddNode(node *CPGNode) error {
	if node == nil {
		return errors.New("cannot add nil node to CPG")
	}
	if node.NodeID == "" {
		return errors.New("node ID cannot be empty")
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if node.Attributes == nil {
		node.Attributes = make(map[string]interface{})
	}

	g.nodes[node.NodeID] = node

	// File and line index
	if node.FilePath != "" && node.Line > 0 {
		fileMap, ok := g.fileLineIndex[node.FilePath]
		if !ok {
			fileMap = make(map[int][]*CPGNode)
			g.fileLineIndex[node.FilePath] = fileMap
		}
		fileMap[node.Line] = append(fileMap[node.Line], node)
	}

	// Symbol index
	if node.SymbolName != "" {
		g.symbolIndex[node.SymbolName] = append(g.symbolIndex[node.SymbolName], node)
	}

	// Type index
	if node.NodeType != "" {
		g.typeIndex[node.NodeType] = append(g.typeIndex[node.NodeType], node)
	}

	return nil
}

// AddEdge adds a directed edge to the graph.
func (g *CodePropertyGraph) AddEdge(edge *CPGEdge) error {
	if edge == nil {
		return errors.New("cannot add nil edge to CPG")
	}
	if edge.SourceID == "" || edge.TargetID == "" {
		return fmt.Errorf("invalid edge endpoints: %s -> %s", edge.SourceID, edge.TargetID)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if edge.Metadata == nil {
		edge.Metadata = make(map[string]interface{})
	}

	g.adjOut[edge.SourceID] = append(g.adjOut[edge.SourceID], edge)
	g.adjIn[edge.TargetID] = append(g.adjIn[edge.TargetID], edge)
	return nil
}

// GetNode retrieves a node by its ID.
func (g *CodePropertyGraph) GetNode(nodeID string) (*CPGNode, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	n, found := g.nodes[nodeID]
	return n, found
}

// GetSuccessors returns all outgoing edges from the specified node.
func (g *CodePropertyGraph) GetSuccessors(nodeID string) []*CPGEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := g.adjOut[nodeID]
	if len(edges) == 0 {
		return nil
	}
	res := make([]*CPGEdge, len(edges))
	copy(res, edges)
	return res
}

// GetPredecessors returns all incoming edges to the specified node.
func (g *CodePropertyGraph) GetPredecessors(nodeID string) []*CPGEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := g.adjIn[nodeID]
	if len(edges) == 0 {
		return nil
	}
	res := make([]*CPGEdge, len(edges))
	copy(res, edges)
	return res
}

// FindNodesAtLine returns all nodes located at the specified file and line.
func (g *CodePropertyGraph) FindNodesAtLine(filePath string, line int) []*CPGNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	fileMap, ok := g.fileLineIndex[filePath]
	if !ok {
		return nil
	}
	nodes := fileMap[line]
	if len(nodes) == 0 {
		return nil
	}
	res := make([]*CPGNode, len(nodes))
	copy(res, nodes)
	return res
}

// FindNodesBySymbol returns all nodes matching the given symbol name.
func (g *CodePropertyGraph) FindNodesBySymbol(symbol string) []*CPGNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := g.symbolIndex[symbol]
	if len(nodes) == 0 {
		return nil
	}
	res := make([]*CPGNode, len(nodes))
	copy(res, nodes)
	return res
}

// FindNodesByType returns all nodes of the given NodeType.
func (g *CodePropertyGraph) FindNodesByType(nodeType NodeType) []*CPGNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := g.typeIndex[nodeType]
	if len(nodes) == 0 {
		return nil
	}
	res := make([]*CPGNode, len(nodes))
	copy(res, nodes)
	return res
}

// CountNodes returns the total number of nodes in the graph.
func (g *CodePropertyGraph) CountNodes() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// CountEdges returns the total number of edges in the graph.
func (g *CodePropertyGraph) CountEdges() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, edges := range g.adjOut {
		count += len(edges)
	}
	return count
}

// GetAllNodes returns a slice of all nodes in the graph.
func (g *CodePropertyGraph) GetAllNodes() []*CPGNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*CPGNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// GetAllEdges returns a slice of all directed edges in the graph.
func (g *CodePropertyGraph) GetAllEdges() []*CPGEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := make([]*CPGEdge, 0)
	for _, outList := range g.adjOut {
		edges = append(edges, outList...)
	}
	return edges
}
