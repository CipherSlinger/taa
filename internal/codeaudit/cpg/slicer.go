package cpg

import (
	"fmt"
	"strings"
)

// This file implements layer 6 of the Code Property Graph: PDG pruning and
// evidence compression. It turns a raw taint violation into the short, causal
// trajectory that the deep audit report renders.

// taintTrajectoryHeader is the contract header of a rendered trajectory. It is
// byte identical to the design document and must not be reworded.
const taintTrajectoryHeader = "[Deep Audit Inter-Procedural Taint Trajectory]"

// taintStepElided marks the synthetic step rendered in place of the steps that
// evidence compression dropped. It only ever appears inside the slicer.
const taintStepElided = "ELIDED"

// taintTrajectoryElisionLabel renders the elision marker line.
const taintTrajectoryElisionLabel = "intermediate steps elided"

// taintTrajectoryNoCode is rendered when a step carries no source text.
const taintTrajectoryNoCode = "(no code)"

// Default rendering budget of a trajectory.
const (
	taintTrajectoryMaxSteps = 7
	taintTrajectoryMaxChars = 1200
	taintTrajectoryCodeCap  = 80
)

// CPGEvidenceSlicer prunes a taint trajectory down to its causal chain and
// renders it as text evidence.
type CPGEvidenceSlicer struct {
	// maxSteps is the number of steps a rendered trajectory may keep.
	maxSteps int
	// maxCode is the number of characters a rendered code excerpt may keep
	// before the trajectory falls back to a shorter excerpt.
	maxCode int
	// maxChars is the character budget of the rendered trajectory.
	maxChars int
}

// NewCPGEvidenceSlicer creates a slicer with the default rendering budget.
func NewCPGEvidenceSlicer() *CPGEvidenceSlicer {
	return &CPGEvidenceSlicer{
		maxSteps: taintTrajectoryMaxSteps,
		maxCode:  taintTrajectoryCodeCap,
		maxChars: taintTrajectoryMaxChars,
	}
}

// FormatTrajectory renders the pruned causal chain of a violation:
//
//	[Deep Audit Inter-Procedural Taint Trajectory]
//	Source: ENV_001 (os.environ.get('API_KEY')) in service_a/loader.py:12
//	  ↳ [DFG_DEF_USE] api_key = os.environ.get('API_KEY') in service_a/loader.py:12
//	  ↳ [SINK: CMD_001] subprocess.run(cmd, shell=True) in service_b/executor.py:48
//
// The graph resolves the code excerpt of a step that carries no source text.
// The rendered text always stays under the character budget.
func (s *CPGEvidenceSlicer) FormatTrajectory(v *TaintViolation, g *CodePropertyGraph) string {
	if v == nil || len(v.Steps) == 0 {
		return ""
	}
	if s == nil {
		s = NewCPGEvidenceSlicer()
	}

	steps := s.pruneTrajectory(v, g)
	text := s.renderTrajectory(v, steps, s.maxCode)
	// The trajectory still does not fit: shorten every code excerpt until it
	// does.
	for cap := s.maxCode; len(text) > s.maxChars && cap > 8; {
		cap /= 2
		text = s.renderTrajectory(v, steps, cap)
	}
	return text
}

// ---------------------------------------------------------------------------
// PDG pruning and compression
// ---------------------------------------------------------------------------

// pruneTrajectory drops the data flow steps that add no causal information and
// compresses what is left to the step budget.
//
// An intermediate DFG step is a pure local temporary when its code does not
// reference a call, so the statement only renames a value inside a file whose
// inter-procedural hops are already part of the trajectory. The source, the
// sink and every call or boundary step are always kept.
func (s *CPGEvidenceSlicer) pruneTrajectory(v *TaintViolation, g *CodePropertyGraph) []TaintStep {
	steps := v.Steps
	if len(steps) <= 1 {
		return steps
	}

	covered := make(map[string]bool)
	for _, step := range steps {
		if step.Type == taintStepInterProcCall || strings.HasPrefix(step.Type, taintMicroservicePrefix) {
			covered[step.File] = true
		}
	}

	kept := make([]TaintStep, 0, len(steps))
	for i, step := range steps {
		if i == 0 || i == len(steps)-1 {
			kept = append(kept, step)
			continue
		}
		if step.Type == taintStepDFGPropagation && covered[step.File] && !taintStepReferencesCall(g, step) {
			continue
		}
		kept = append(kept, step)
	}

	return taintCompressSteps(kept, s.maxSteps)
}

// taintStepReferencesCall reports whether a step references an inter-procedural
// call, judged from the evidence code and, when it carries none, from the node
// registered at the step position.
func taintStepReferencesCall(g *CodePropertyGraph, step TaintStep) bool {
	code := strings.TrimSpace(step.Code)
	if code == "" {
		code = taintNodeCodeAt(g, step)
	}
	return strings.Contains(code, "(")
}

// taintNodeCodeAt returns the code of the CPG node registered at the position
// of a step.
func taintNodeCodeAt(g *CodePropertyGraph, step TaintStep) string {
	if g == nil {
		return ""
	}
	for _, node := range g.FindNodesAtLine(step.File, step.Line) {
		if node != nil && node.CodeStr != "" {
			return node.CodeStr
		}
	}
	return ""
}

// taintCompressSteps keeps at most maxSteps steps: the first, the last and
// evenly spaced steps in between. The dropped steps collapse into one elision
// marker placed where the first of them was.
func taintCompressSteps(steps []TaintStep, maxSteps int) []TaintStep {
	if maxSteps < 3 || len(steps) <= maxSteps {
		return steps
	}

	keep := map[int]bool{0: true, len(steps) - 1: true}
	inner := maxSteps - 2
	for i := 1; i <= inner; i++ {
		index := i * (len(steps) - 1) / (inner + 1)
		if index < 1 {
			index = 1
		}
		if index > len(steps)-2 {
			index = len(steps) - 2
		}
		keep[index] = true
	}

	elided := len(steps) - len(keep)
	out := make([]TaintStep, 0, len(keep)+1)
	markerEmitted := false
	for i, step := range steps {
		if keep[i] {
			out = append(out, step)
			continue
		}
		if markerEmitted {
			continue
		}
		markerEmitted = true
		out = append(out, TaintStep{
			Step: step.Step,
			Type: taintStepElided,
			Code: fmt.Sprintf("%d %s", elided, taintTrajectoryElisionLabel),
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// renderTrajectory renders the header, the source line and one line per
// remaining step, truncating every code excerpt to cap characters.
func (s *CPGEvidenceSlicer) renderTrajectory(v *TaintViolation, steps []TaintStep, cap int) string {
	var b strings.Builder
	b.WriteString(taintTrajectoryHeader)
	b.WriteString("\n")
	fmt.Fprintf(&b, "Source: %s (%s) in %s:%d",
		v.SourceFamily, taintCodeExcerpt(steps[0].Code, cap), steps[0].File, steps[0].Line)

	for i := 1; i < len(steps); i++ {
		step := steps[i]
		if step.Type == taintStepElided {
			fmt.Fprintf(&b, "\n  ↳ [... %s ...]", step.Code)
			continue
		}
		label := step.EdgeType
		if step.Type == taintStepSink {
			label = "SINK: " + v.SinkFamily
		}
		fmt.Fprintf(&b, "\n  ↳ [%s] %s in %s:%d",
			label, taintCodeExcerpt(step.Code, cap), step.File, step.Line)
	}
	return b.String()
}

// taintCodeExcerpt renders one code excerpt: single line, trimmed and capped at
// the given number of characters with a trailing ellipsis.
func taintCodeExcerpt(code string, cap int) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return taintTrajectoryNoCode
	}
	code = strings.Join(strings.Fields(code), " ")
	if cap <= 0 {
		return code
	}
	runes := []rune(code)
	if len(runes) <= cap {
		return code
	}
	return strings.TrimRight(string(runes[:cap]), " ") + "..."
}
