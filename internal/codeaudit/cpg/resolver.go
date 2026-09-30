package cpg

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// resolverSkipDirs lists directory names that never hold importable Python
// modules of the analysed workspace and are therefore skipped while scanning.
var resolverSkipDirs = map[string]bool{
	".git":         true,
	"__pycache__":  true,
	"node_modules": true,
	"vendor":       true,
	"target":       true,
	"bin":          true,
}

// SymbolResolver indexes the importable Python modules of a workspace and
// resolves import statements into fully-qualified module paths. It implements
// Layer 2 (cross-file symbol resolution) of the Code Property Graph.
//
// The index is empty until Scan is called; every lookup on an unscanned
// resolver simply reports "not found".
type SymbolResolver struct {
	workspaceRoot string
	modules       map[string]string // fully-qualified module path -> absolute file path
}

// NewSymbolResolver creates a resolver rooted at the given workspace directory.
// Call Scan to build the module index before resolving imports.
func NewSymbolResolver(workspaceRoot string) *SymbolResolver {
	return &SymbolResolver{
		workspaceRoot: workspaceRoot,
		modules:       make(map[string]string),
	}
}

// Scan recursively walks the workspace root and indexes every Python file as an
// importable module: "pkg/util.py" registers "pkg.util" and "pkg/__init__.py"
// registers the package "pkg" itself. Machine generated and vendored
// directories (see resolverSkipDirs) are ignored.
func (r *SymbolResolver) Scan() error {
	r.modules = make(map[string]string)
	if r.workspaceRoot == "" {
		return nil
	}
	root := r.workspaceRoot
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && resolverSkipDirs[entry.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".py") {
			return nil
		}
		module := resolverModulePath(root, path)
		if module == "" {
			return nil
		}
		if _, exists := r.modules[module]; !exists {
			r.modules[module] = path
		}
		return nil
	})
}

// LookupModule returns the absolute path of the file that defines the given
// fully-qualified module path.
func (r *SymbolResolver) LookupModule(module string) (string, bool) {
	if r == nil || module == "" {
		return "", false
	}
	path, ok := r.modules[module]
	return path, ok
}

// ResolveImport resolves a Python import statement to a fully-qualified module
// path.
//
// level == 0 is an absolute import and "module" is returned unchanged.
// level >= 1 is a relative import following Python semantics: level 1 refers to
// the package the importing file lives in ("from . import x"), level 2 to its
// parent package ("from ..util import y") and so on. For relative imports the
// resolved module is the base package joined with "module" when "module" is
// non-empty (ImportFrom) and is the base package itself when "module" is empty.
//
// The boolean reports whether the resolved module is registered in the
// workspace index; the module path is always returned when it could be
// computed, so external and standard library imports stay usable.
func (r *SymbolResolver) ResolveImport(currentFile, module string, level int) (string, bool) {
	if level <= 0 {
		if module == "" {
			return "", false
		}
		_, ok := r.LookupModule(module)
		return module, ok
	}

	parts, ok := resolverPackageParts(r.workspaceRoot, currentFile)
	if !ok {
		return "", false
	}
	up := level - 1
	if up > len(parts) {
		return "", false
	}
	resolved := strings.Join(parts[:len(parts)-up], ".")
	if module != "" {
		if resolved == "" {
			resolved = module
		} else {
			resolved = resolved + "." + module
		}
	}
	if resolved == "" {
		return "", false
	}
	_, registered := r.LookupModule(resolved)
	return resolved, registered
}

// FQN joins a module path and a symbol name into a fully-qualified name.
func (r *SymbolResolver) FQN(module, name string) string {
	switch {
	case module == "":
		return name
	case name == "":
		return module
	default:
		return module + "." + name
	}
}

// resolverModulePath converts a file path into the module path it defines.
// "pkg/util.py" yields "pkg.util" and "pkg/__init__.py" yields the package
// "pkg". It returns an empty string when the file lies outside the root or does
// not yield an importable module name.
func resolverModulePath(root, filePath string) string {
	parts, ok := resolverPackageParts(root, filePath)
	if !ok {
		return ""
	}
	base := strings.TrimSuffix(filepath.Base(filePath), ".py")
	if base == "" || base == "__init__" {
		return strings.Join(parts, ".")
	}
	return strings.Join(append(parts, base), ".")
}

// resolverPackageParts returns the package components of the directory holding
// filePath, relative to root. Relative paths are interpreted against root. It
// returns false when filePath does not live below root.
func resolverPackageParts(root, filePath string) ([]string, bool) {
	if root == "" || filePath == "" {
		return nil, false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, false
	}
	absFile := filePath
	if !filepath.IsAbs(absFile) {
		absFile = filepath.Join(absRoot, absFile)
	}
	rel, err := filepath.Rel(absRoot, filepath.Dir(absFile))
	if err != nil {
		return nil, false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, false
	}
	if rel == "." {
		return nil, true
	}
	var parts []string
	for _, segment := range strings.Split(filepath.ToSlash(rel), "/") {
		if segment == "" || segment == "." {
			continue
		}
		parts = append(parts, segment)
	}
	return parts, true
}
