package execenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultProcRoot is where the kernel publishes its process view. A TAA
	// process always reads its own view here, so every path below is in the
	// namespace TAA itself runs in.
	defaultProcRoot = "/proc"

	// rootFSTypeInitrd is the fstype of the guest init root. A container's own
	// root is an overlay, so this value separates the two.
	rootFSTypeInitrd = "rootfs"

	// probeTimeout bounds the namespace probe. It only runs /bin/sh to exit, so
	// anything slower means the container is wedged.
	probeTimeout = 15 * time.Second
)

// probeContainer verifies that a discovered namespace is a usable container:
// the shell starts inside it and its root is writable. It is a variable so
// tests can replace it; production always uses the nsenter implementation.
var probeContainer = probeContainerNSEnter

// Options controls discovery.
type Options struct {
	// ProcRoot overrides the procfs root. Empty means /proc; tests point it at
	// a fixture tree.
	ProcRoot string
	// ContainerID disambiguates when several containers are found. It is
	// matched against the container root's mount path and the overlay upperdir.
	ContainerID string
	// Paths is the container-side contract. The zero value means
	// DefaultContainerPaths, which is what the packaged images follow; a caller
	// that overrides one field must fill the rest, since Paths is taken whole.
	Paths Paths
}

// candidate is one distinct container mount namespace found in the scan.
type candidate struct {
	pid  int
	ns   string
	root mountEntry // the candidate's own root mount line
}

// Discover finds the container this TAA process should execute models in.
//
// The scan does not rely on any Kata path convention: a container's own root
// mount is visible in its mountinfo with its own device number, and that same
// device is mounted in TAA's namespace at the container's rootfs path. Matching
// on the device number is what makes the lookup survive a layout change inside
// Kata. The path-suffix match is a logged fallback, never the first choice.
//
// Discovery never guesses: several candidates without a configured
// ContainerID is an error, not a coin flip, because running the model in the
// wrong container would silently use the wrong image's runtime.
func Discover(ctx context.Context, opts Options) (*ContainerTarget, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	procRoot := opts.ProcRoot
	if procRoot == "" {
		procRoot = defaultProcRoot
	}

	selfNS, err := os.Readlink(filepath.Join(procRoot, "self", "ns", "mnt"))
	if err != nil {
		return nil, fmt.Errorf("read own mount namespace: %w", err)
	}

	candidates, err := scanNamespaces(procRoot, selfNS)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no container mount namespace found under %s", procRoot)
	}

	if len(candidates) > 1 && opts.ContainerID != "" {
		candidates = filterByContainerID(candidates, opts.ContainerID)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no container matching %q was found", opts.ContainerID)
	}
	if len(candidates) > 1 {
		pids := make([]string, 0, len(candidates))
		for _, c := range candidates {
			pids = append(pids, strconv.Itoa(c.pid))
		}
		return nil, fmt.Errorf("found %d candidate containers (pids %s); set an explicit container id to choose one",
			len(candidates), strings.Join(pids, ", "))
	}
	chosen := candidates[0]

	selfData, err := os.ReadFile(filepath.Join(procRoot, "self", "mountinfo"))
	if err != nil {
		return nil, fmt.Errorf("read own mount table: %w", err)
	}
	rootFS, exact := resolveRootFS(parseMountInfo(string(selfData)), chosen.root)
	if rootFS == "" {
		return nil, fmt.Errorf("the container root (device %s, fstype %s) is not mounted in TAA's namespace",
			chosen.root.MajorMinor, chosen.root.FSType)
	}
	if !exact {
		// The fallback found nothing with a matching device, so the container's
		// rootfs path was guessed from the Kata convention. It still has to pass
		// the probe below, but the warning says how it was chosen.
		fmt.Fprintf(os.Stderr, "WARNING: container root resolved by path suffix, not by device %s: %s\n",
			chosen.root.MajorMinor, rootFS)
	}
	if info, err := os.Stat(rootFS); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("container root %s is not a directory", rootFS)
	}

	if err := probeContainer(ctx, procRoot, chosen.pid, rootFS); err != nil {
		return nil, err
	}

	paths := opts.Paths
	if paths == (Paths{}) {
		paths = DefaultContainerPaths()
	}

	return newContainerTarget(procRoot, chosen.pid, rootFS, paths), nil
}

// scanNamespaces walks /proc and returns one candidate per distinct mount
// namespace whose root is not the initrd's ramfs.
func scanNamespaces(procRoot, selfNS string) ([]*candidate, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoot, err)
	}

	seen := map[string]bool{}
	var candidates []*candidate
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join(procRoot, entry.Name(), "ns", "mnt"))
		if err != nil {
			// The process exited between the directory listing and the read.
			continue
		}
		if ns == selfNS || seen[ns] {
			continue
		}
		seen[ns] = true

		data, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "mountinfo"))
		if err != nil {
			continue
		}
		root, ok := rootMount(parseMountInfo(string(data)))
		if !ok || root.FSType == rootFSTypeInitrd {
			continue
		}
		candidates = append(candidates, &candidate{pid: pid, ns: ns, root: root})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].pid < candidates[j].pid })
	return candidates, nil
}

// filterByContainerID keeps the candidates whose root mount path or overlay
// upperdir names the given container id.
func filterByContainerID(candidates []*candidate, id string) []*candidate {
	var kept []*candidate
	for _, c := range candidates {
		if strings.Contains(c.ns, id) ||
			strings.Contains(c.root.SuperOptions, "upperdir="+"/run/kata-containers/"+id+"/") {
			kept = append(kept, c)
		}
	}
	return kept
}

// resolveRootFS finds the path where TAA's namespace sees the container root.
// It first looks for a mount of the container root's device, which is layout
// independent, and falls back to the Kata "…/rootfs" path convention with the
// boolean set to false.
func resolveRootFS(selfMounts []mountEntry, containerRoot mountEntry) (string, bool) {
	var sameDevice []mountEntry
	for _, m := range selfMounts {
		if m.MajorMinor == containerRoot.MajorMinor && m.FSType == containerRoot.FSType {
			sameDevice = append(sameDevice, m)
		}
	}
	if len(sameDevice) > 0 {
		// The container root is the one mounted at root "/"; a bind of the same
		// device elsewhere is possible but not the root.
		for _, m := range sameDevice {
			if m.Root == "/" {
				return m.MountPoint, true
			}
		}
		return sameDevice[0].MountPoint, true
	}
	for _, m := range selfMounts {
		if strings.HasSuffix(m.MountPoint, "/rootfs") {
			return m.MountPoint, false
		}
	}
	return "", false
}

// probeContainerNSEnter starts a shell in the container's mount namespace and
// checks that the container root can be written through TAA's own view of it.
func probeContainerNSEnter(ctx context.Context, _ string, pid int, rootFS string) error {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	cmd := nsenterShell(probeCtx, pid, "exit 0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("probe the container at pid %d: %w (output: %q)", pid, err, strings.TrimSpace(string(out)))
	}

	probeDir := filepath.Join(rootFS, "opt", "taa")
	if info, err := os.Stat(probeDir); err != nil || !info.IsDir() {
		// The image has no /opt/taa yet; Prepare creates it. Writing at the
		// container root still proves the overlay is writable from TAA's view.
		probeDir = rootFS
	}
	file, err := os.CreateTemp(probeDir, ".taa-probe-")
	if err != nil {
		return fmt.Errorf("container root is not writable (%s): %w", probeDir, err)
	}
	name := file.Name()
	file.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove the container probe file %s: %w", name, err)
	}
	return nil
}
