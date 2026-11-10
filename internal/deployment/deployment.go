// Package deployment identifies which deployment shape this TAA process runs
// in: the first userspace process of a CSV2 initrd, or the entrypoint of a
// container image.
//
// The shape only decides where model work executes, never a security verdict,
// so it is a deployment fact rather than a trust root. It is taken from an
// explicit marker exported by the starter script when one is present, and only
// inferred from the root mount when the marker is missing. The inference is
// deliberately one-sided and logged as a warning: a missing marker means some
// starter script forgot the export, which an operator should fix rather than
// have silently papered over.
package deployment

import (
	"fmt"
	"os"
	"strings"
)

// EnvVar is the marker the starter scripts export before launching TAA.
// Environment does not cross mount or PID namespaces, so the initrd process and
// any container process can never inherit each other's value.
const EnvVar = "TAA_DEPLOYMENT"

// mountInfoPath is where the kernel publishes the caller's mount table. It is
// read from the calling process, so a container sees its own root overlaid at
// "/" while the initrd sees the ramfs there.
const mountInfoPath = "/proc/self/mountinfo"

// rootFSTypeInitrd is the fstype of the guest init root: the ramfs the initrd
// unpacked into. A container root is an overlay, so this single value separates
// the two shapes.
const rootFSTypeInitrd = "rootfs"

// Shape is the deployment shape of the running process.
type Shape int

const (
	// Unknown means neither the marker nor the root mount yielded a decision.
	// Callers must treat it as "do not change behaviour" rather than guessing.
	Unknown Shape = iota
	// Initrd is the CSV2 initrd path: TAA starts before kata-agent, from the
	// measured init script, in the guest init namespaces.
	Initrd
	// Container is the image entrypoint path: the supervisor starts TAA inside
	// the container's own namespaces.
	Container
)

func (s Shape) String() string {
	switch s {
	case Initrd:
		return "initrd"
	case Container:
		return "container"
	default:
		return "unknown"
	}
}

// Result carries the decision plus everything that went into it, so startup can
// report it to the console and the platform without a second lookup.
type Result struct {
	Shape      Shape
	Explicit   bool   // the marker was set and valid
	Marker     string // the raw marker value, kept for the log line
	RootFSType string // fstype of the root mount, empty when unreadable
	Inferred   bool   // the shape came from the mount, not the marker
	Warning    string // non-empty when the decision needs operator attention
}

// Source names where the shape came from.
func (r Result) Source() string {
	switch {
	case r.Explicit:
		return "explicit marker"
	case r.Inferred:
		return "inferred from root mount"
	default:
		return "undetermined"
	}
}

// Detect decides the deployment shape of the current process. A marker value
// that is neither empty nor one of the two known shapes is an error: it can
// only come from a typo in a starter script, and silently guessing past it
// would hide exactly the misconfiguration this marker exists to expose.
func Detect() (Result, error) {
	return detect(os.Getenv(EnvVar), os.ReadFile)
}

// detect is Detect with its two inputs injected, so tests can cover the marker
// and mount table combinations without touching the host.
func detect(marker string, readFile func(string) ([]byte, error)) (Result, error) {
	res := Result{Marker: marker}
	switch strings.ToLower(strings.TrimSpace(marker)) {
	case "":
		// Fall through to inference below.
	case "initrd":
		res.Shape = Initrd
		res.Explicit = true
	case "container":
		res.Shape = Container
		res.Explicit = true
	default:
		return res, fmt.Errorf("invalid %s value %q: want %q or %q", EnvVar, marker, "initrd", "container")
	}

	if data, err := readFile(mountInfoPath); err == nil {
		res.RootFSType = parseRootFSType(string(data))
	}

	if res.Explicit {
		// The marker wins. The mount only corroborates it: a disagreement means
		// the kernel view and the starter script disagree about where this process
		// lives, which is worth reporting but not worth overriding the deployment's
		// own statement.
		if res.RootFSType != "" && !fstypeAgrees(res.Shape, res.RootFSType) {
			res.Warning = fmt.Sprintf("%s=%s but the root mount fstype is %q; keeping the marker",
				EnvVar, res.Shape, res.RootFSType)
		}
		return res, nil
	}

	if res.RootFSType == "" {
		res.Warning = fmt.Sprintf("%s is not set and the root mount fstype could not be read; shape undetermined", EnvVar)
		return res, nil
	}
	if res.RootFSType == rootFSTypeInitrd {
		res.Shape = Initrd
	} else {
		res.Shape = Container
	}
	res.Inferred = true
	res.Warning = fmt.Sprintf("%s is not set; inferred %q from the root mount fstype %q",
		EnvVar, res.Shape, res.RootFSType)
	return res, nil
}

// fstypeAgrees reports whether a root mount fstype is consistent with the
// given shape.
func fstypeAgrees(shape Shape, fstype string) bool {
	switch shape {
	case Initrd:
		return fstype == rootFSTypeInitrd
	case Container:
		return fstype != rootFSTypeInitrd
	default:
		return true
	}
}

// parseRootFSType returns the fstype of the mount whose root and mount point
// are both "/". mountinfo lines read, before the " - " separator: id, parent,
// major:minor, root, mountpoint, mount options, optional fields; the fstype is
// the first field after it. Empty means no root line was found.
func parseRootFSType(data string) string {
	for _, line := range strings.Split(data, "\n") {
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		pre := strings.Fields(line[:sep])
		post := strings.Fields(line[sep+len(" - "):])
		if len(pre) < 5 || len(post) < 1 {
			continue
		}
		if pre[3] == "/" && pre[4] == "/" {
			return post[0]
		}
	}
	return ""
}
