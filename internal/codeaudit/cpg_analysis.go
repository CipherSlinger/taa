package codeaudit

import (
	"fmt"
	"sort"

	"taa/internal/codeaudit/cpg"
)

// EngineNameCPG names the graph engine in the Engine field of a finding it
// synthesized. It is not a selectable Tier 1 engine: the CPG pass is not an
// alternative to semgrep or the regex table, it is what runs after one of them
// has found something.
const EngineNameCPG = "cpg"

// CrossServiceRuleID is the rule id of the synthesized system-level finding.
const CrossServiceRuleID = "taa-cross-service-rce"

const (
	// cpgMaxFiles bounds how many files one graph pass parses. The AST bridge
	// starts a parser per file, so this is the control that bounds the pass;
	// the node ceiling below is checked after the fact.
	cpgMaxFiles = 400
	// cpgMaxNodes is the point past which the taint traversal is skipped
	// entirely. It is a budget guard rather than a memory guard: by the time a
	// graph this large exists the memory has already been spent, and the file
	// ceiling is what keeps that from happening. What this prevents is a
	// pathological graph making the fixed-point traversal the slow part of an
	// import.
	cpgMaxNodes = 50000
)

// enrichFindingsWithCPG runs the on-demand graph pass and folds its results into
// the findings a Tier 1 engine produced.
//
// The pass is triggered by findings rather than run unconditionally, because
// most imports are clean and the graph is the expensive part of the pipeline. A
// scan with nothing to explain returns here immediately, which is what keeps a
// clean package on the millisecond path.
//
// Only cross-file and cross-microservice flows are acted on. A source and a sink
// in one function is already fully described by that function's own context, and
// rewriting the context of a single-file finding would make the Tier 2 prompt
// depend on which engine produced it - the one difference the non-inferiority
// measurement must be free of. What the graph adds is precisely what a local
// view cannot show: a value that leaves one file or one service and arrives at a
// sink in another.
func enrichFindingsWithCPG(dir string, targets []string, findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	pythonFiles := pythonTargets(targets)
	if len(pythonFiles) == 0 {
		return findings
	}

	graph, err := buildAnalysisGraph(dir, pythonFiles)
	if err != nil || graph == nil || graph.CountNodes() == 0 {
		// The graph is an enrichment, not a gate. A pass that cannot be built
		// leaves the Tier 1 findings exactly as they were rather than failing a
		// scan that already succeeded.
		return findings
	}

	bridge := cpg.NewMicroserviceBoundaryBridge()
	bridge.BridgeBoundaries(graph)

	if graph.CountNodes() > cpgMaxNodes {
		return findings
	}

	violations := cpg.NewInterProceduralTaintEngine().FindViolations(graph)
	if len(violations) == 0 {
		return findings
	}

	slicer := cpg.NewCPGEvidenceSlicer()

	byLocation := make(map[string][]int, len(findings))
	for i, f := range findings {
		key := findingLocation(f.File, f.Line)
		byLocation[key] = append(byLocation[key], i)
	}

	synthesized := make(map[string]bool)
	for _, v := range violations {
		// A flow that stays inside one file adds nothing a local context does
		// not already carry.
		if !v.CrossFile && !v.AcrossMicroservice {
			continue
		}

		trajectory := slicer.FormatTrajectory(v, graph)
		trace := toTaintTrace(v)

		for _, step := range v.Steps {
			for _, idx := range byLocation[findingLocation(step.File, step.Line)] {
				attachCPGEvidence(&findings[idx], trajectory, trace, v)
			}
		}

		key := findingLocation(v.SinkID, 0)
		if !v.AcrossMicroservice || synthesized[key] {
			continue
		}
		if f, ok := synthesizeCrossServiceFinding(v, trajectory, trace); ok {
			synthesized[key] = true
			findings = append(findings, f)
		}
	}

	return findings
}

// attachCPGEvidence records a trajectory on a finding the flow passes through.
func attachCPGEvidence(f *Finding, trajectory string, trace []TaintStep, v *cpg.TaintViolation) {
	if f.CPGEvidence == "" {
		f.CPGEvidence = trajectory
	}
	if len(f.TaintTrace) == 0 {
		f.TaintTrace = trace
	}
	f.IsCrossFile = f.IsCrossFile || v.CrossFile
	f.IsMicroservice = f.IsMicroservice || v.AcrossMicroservice
}

// synthesizeCrossServiceFinding turns a boundary-crossing execution flow into a
// finding of its own.
//
// Neither Tier 1 engine can report this, and neither should: each of them sees
// one file, and in each file the code is unremarkable. A client that posts a
// payload read from the environment and a handler that runs what it receives are
// two ordinary halves of one defect, and the defect only exists in the join.
//
// The severity is HIGH because that is the level the gate blocks on. A level of
// its own would read as more severe and block nothing.
func synthesizeCrossServiceFinding(v *cpg.TaintViolation, trajectory string, trace []TaintStep) (Finding, bool) {
	if v.SinkFamily != "CMD_001" || (v.SourceFamily != "ENV_001" && v.SourceFamily != "FIL_001") {
		return Finding{}, false
	}
	if len(v.Steps) == 0 {
		return Finding{}, false
	}

	sink := v.Steps[len(v.Steps)-1]
	return Finding{
		File:           sink.File,
		Line:           sink.Line,
		RuleID:         CrossServiceRuleID,
		Category:       "execution",
		Severity:       SeverityHigh,
		Description:    "A sensitive value read in one service reaches a command execution sink in another",
		CodeSnippet:    sink.Code,
		ContextAfter:   trajectory,
		IsCrossFile:    true,
		IsMicroservice: true,
		CPGEvidence:    trajectory,
		TaintTrace:     trace,
		Engine:         EngineNameCPG,
		RuleFamily:     CrossServiceRuleID,
	}, true
}

// buildAnalysisGraph parses the files the graph pass covers and links them.
func buildAnalysisGraph(dir string, pythonFiles []string) (*cpg.CodePropertyGraph, error) {
	resolver := cpg.NewSymbolResolver(dir)
	if err := resolver.Scan(); err != nil {
		return nil, fmt.Errorf("scan workspace for symbols: %w", err)
	}

	graph := cpg.NewCodePropertyGraph()
	if err := cpg.NewCPGBuilder(resolver).Build(graph, pythonFiles); err != nil {
		return nil, fmt.Errorf("build graph: %w", err)
	}
	return graph, nil
}

// pythonTargets selects the files the AST layer can parse, in walk order.
//
// The order is kept and only the first cpgMaxFiles are taken, so the cap is
// deterministic: a scan that hits it takes the same files every time and two
// reports stay comparable.
func pythonTargets(targets []string) []string {
	var out []string
	for _, t := range targets {
		if isPythonSource(t) {
			out = append(out, t)
		}
	}
	if len(out) > cpgMaxFiles {
		out = out[:cpgMaxFiles]
	}
	return out
}

// toTaintTrace copies the graph engine's steps onto the report's schema. The two
// are separate types on purpose - the report's is a wire contract and the
// engine's is free to change - so the copy is explicit and field by field, and a
// field added on one side is a compile error rather than a silent omission.
func toTaintTrace(v *cpg.TaintViolation) []TaintStep {
	trace := make([]TaintStep, 0, len(v.Steps))
	for _, s := range v.Steps {
		trace = append(trace, TaintStep{
			Step:           s.Step,
			Type:           s.Type,
			File:           s.File,
			Line:           s.Line,
			Code:           s.Code,
			EnclosingScope: s.EnclosingScope,
			EdgeType:       s.EdgeType,
		})
	}
	return trace
}

// findingLocation keys a finding by where it is, for matching a trajectory step
// back onto the finding it passes through.
func findingLocation(file string, line int) string {
	return fmt.Sprintf("%s:%d", cleanAbs(file), line)
}

// sortFindings orders findings by file, then line, then rule.
//
// The order has to be total and independent of the run, because the cap keeps
// the first N: an order that varied would make a truncated scan keep a different
// set each time and two reports would stop being comparable.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}
