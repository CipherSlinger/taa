package controller

import "strings"

// applyDepsEnv injects the active dependency directory into the training environment: it
// sets TAA_DEPS_DIR and PREPENDS the deps dir to PYTHONPATH (rather than overwriting it),
// so PYTHONPATH entries supplied by the platform in runtimeConfig.env are preserved.
//
// An empty depsDir means no dependency package is active; in that case a copy is returned
// unchanged and no key is injected. This is where the guarantee "the training environment
// is byte-for-byte unchanged when no dependency package has been imported" is anchored.
//
// When the platform supplies no (or only blank) PYTHONPATH, the deps dir is set alone -- never
// followed by ':' -- so no empty entry can put the working directory on sys.path.
//
// Both the depsDir argument and any existing PYTHONPATH value are whitespace-trimmed before use.
//
// It returns a new map and never mutates the input.
func applyDepsEnv(env map[string]string, depsDir string) map[string]string {
	out := make(map[string]string, len(env)+2)
	for k, v := range env {
		out[k] = v
	}
	depsDir = strings.TrimSpace(depsDir)
	if depsDir == "" {
		return out
	}

	out["TAA_DEPS_DIR"] = depsDir
	if existing := strings.TrimSpace(out["PYTHONPATH"]); existing != "" {
		out["PYTHONPATH"] = depsDir + ":" + existing
	} else {
		out["PYTHONPATH"] = depsDir
	}
	return out
}
