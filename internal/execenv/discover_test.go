package execenv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures reproduce the two root lines measured on 2026-11-10 in a live
// CSV2 guest: the init namespace sees the initrd's ramfs at "/", while the
// container namespace sees its own overlay, and the same overlay device is
// mounted in the init namespace at the container's rootfs path.
const (
	selfMountInfoOneContainer = "1 1 0:2 / / rw - rootfs rootfs rw,size=9669488k\n" +
		"22 1 0:29 / /run/kata-containers/abc/rootfs rw - overlay overlay " +
		"rw,lowerdir=/run/kata-containers/abc/rootfs,upperdir=/run/kata-containers/abc/rootfs,workdir=/w\n"

	containerMountInfoABC = "1 63 0:29 / / rw - overlay overlay " +
		"rw,lowerdir=/run/kata-containers/abc/rootfs,upperdir=/run/kata-containers/abc/rootfs,workdir=/w\n"

	selfMountInfoTwoContainers = selfMountInfoOneContainer +
		"23 1 0:30 / /run/kata-containers/def/rootfs rw - overlay overlay " +
		"rw,lowerdir=/run/kata-containers/def/rootfs,upperdir=/run/kata-containers/def/rootfs,workdir=/w2\n"

	containerMountInfoDEF = "1 64 0:30 / / rw - overlay overlay " +
		"rw,lowerdir=/run/kata-containers/def/rootfs,upperdir=/run/kata-containers/def/rootfs,workdir=/w2\n"
)

func stubProbe(t *testing.T) {
	t.Helper()
	original := probeContainer
	probeContainer = func(context.Context, string, int, string) error { return nil }
	t.Cleanup(func() { probeContainer = original })
}

// buildProcTree creates a procfs-shaped fixture: regular files for mountinfo
// and symlinks for namespace entries.
func buildProcTree(t *testing.T, files, links map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for path, target := range links {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestDiscoverFindsTheSingleContainer(t *testing.T) {
	stubProbe(t)
	rootFS := t.TempDir()
	proc := buildProcTree(t,
		map[string]string{
			"208/mountinfo": containerMountInfoABC,
			"208/cmdline":   "python3\x00train.py\x00",
			"300/mountinfo": containerMountInfoABC,
			"300/cmdline":   "sleep\x00100\x00",
		},
		map[string]string{
			"self/ns/mnt": "mnt:[111]",
			"208/ns/mnt":  "mnt:[222]",
			"300/ns/mnt":  "mnt:[222]", // same container, second process
		})
	// self/mountinfo names /run/kata-containers/abc/rootfs; point it at a real
	// directory so the existence check passes.
	if err := os.MkdirAll(filepath.Join(rootFS, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Rewrite the self mount table to use the fixture root as the mount point.
	if err := os.WriteFile(filepath.Join(proc, "self", "mountinfo"),
		[]byte("1 1 0:2 / / rw - rootfs rootfs rw,size=9669488k\n"+
			"22 1 0:29 / "+rootFS+"/rootfs rw - overlay overlay rw,upperdir="+rootFS+"/rootfs\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	target, err := Discover(context.Background(), Options{ProcRoot: proc})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if target.PID() != 208 && target.PID() != 300 {
		t.Fatalf("PID=%d, want one of the container's processes", target.PID())
	}
	if target.RootFS() != filepath.Join(rootFS, "rootfs") {
		t.Fatalf("RootFS=%q, want %q", target.RootFS(), filepath.Join(rootFS, "rootfs"))
	}
	if target.Name() != "container" {
		t.Fatalf("Name=%q", target.Name())
	}
}

func TestDiscoverWithoutAContainer(t *testing.T) {
	stubProbe(t)
	proc := buildProcTree(t,
		map[string]string{
			"self/mountinfo": "1 1 0:2 / / rw - rootfs rootfs rw,size=9669488k\n",
			"208/mountinfo":  "1 63 0:2 / / rw - rootfs rootfs rw\n", // a process still in the init root
		},
		map[string]string{
			"self/ns/mnt": "mnt:[111]",
			"208/ns/mnt":  "mnt:[222]",
		})

	_, err := Discover(context.Background(), Options{ProcRoot: proc})
	if err == nil || !strings.Contains(err.Error(), "no container") {
		t.Fatalf("got %v, want a no-container error", err)
	}
}

func TestDiscoverRefusesAmbiguity(t *testing.T) {
	stubProbe(t)
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "def"), 0o755); err != nil {
		t.Fatal(err)
	}
	self := "1 1 0:2 / / rw - rootfs rootfs rw\n" +
		"22 1 0:29 / " + base + "/abc rw - overlay overlay rw,upperdir=/run/kata-containers/abc/rootfs\n" +
		"23 1 0:30 / " + base + "/def rw - overlay overlay rw,upperdir=/run/kata-containers/def/rootfs\n"
	proc := buildProcTree(t,
		map[string]string{
			"self/mountinfo": self,
			"208/mountinfo":  containerMountInfoABC,
			"208/cmdline":    "python3\x00train.py\x00",
			"400/mountinfo":  containerMountInfoDEF,
			"400/cmdline":    "python3\x00train.py\x00",
		},
		map[string]string{
			"self/ns/mnt": "mnt:[111]",
			"208/ns/mnt":  "mnt:[222]",
			"400/ns/mnt":  "mnt:[333]",
		})

	_, err := Discover(context.Background(), Options{ProcRoot: proc})
	if err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Fatalf("got %v, want an ambiguity error", err)
	}

	target, err := Discover(context.Background(), Options{ProcRoot: proc, ContainerID: "def"})
	if err != nil {
		t.Fatalf("Discover with an id: %v", err)
	}
	if target.PID() != 400 {
		t.Fatalf("PID=%d, want the container named by the id (400)", target.PID())
	}

	if _, err := Discover(context.Background(), Options{ProcRoot: proc, ContainerID: "missing"}); err == nil {
		t.Fatal("an id that matches nothing must fail, not fall back to a guess")
	}
}

func TestResolveRootFS(t *testing.T) {
	self := parseMountInfo(selfMountInfoOneContainer)
	root := parseMountInfo(containerMountInfoABC)[0]

	if got, exact := resolveRootFS(self, root); !exact || got != "/run/kata-containers/abc/rootfs" {
		t.Fatalf("(%q, %v), want the device match", got, exact)
	}

	// No mount carries the device: the Kata path convention is all that is left,
	// and the caller has to say so.
	other := parseMountInfo("1 63 0:99 / / rw - overlay overlay rw\n")[0]
	if got, exact := resolveRootFS(self, other); exact || got != "/run/kata-containers/abc/rootfs" {
		t.Fatalf("(%q, %v), want the suffix fallback", got, exact)
	}

	if got, exact := resolveRootFS(parseMountInfo("1 1 0:2 / / rw - rootfs rootfs rw\n"), other); got != "" || exact {
		t.Fatalf("(%q, %v), want no match", got, exact)
	}
}

func TestParseMountInfo(t *testing.T) {
	entries := parseMountInfo("22 1 0:21 / /media/my\\040disk rw - ext4 /dev/sda1 rw\n" +
		"malformed line\n" +
		"23 1 0:22 / /sys rw - sysfs sysfs rw,seclabel\n")
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].MountPoint != "/media/my disk" {
		t.Fatalf("escaped mount point not decoded: %q", entries[0].MountPoint)
	}
	if entries[1].FSType != "sysfs" || entries[1].SuperOptions != "rw,seclabel" {
		t.Fatalf("unexpected entry: %#v", entries[1])
	}
}

// Measured on 2026-11-10 in a live CSV2 guest: kdevtmpfs, a kernel thread, lives
// in its own mount namespace whose root is a devtmpfs. A scan that classifies a
// namespace only by "its root is not the initrd's ramfs" counts it as a second
// container, and discovery then refuses to choose and the task falls back to
// running in the initrd.
func TestDiscoverIgnoresKernelThreadNamespaces(t *testing.T) {
	stubProbe(t)
	rootFS := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootFS, "rootfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	proc := buildProcTree(t,
		map[string]string{
			"208/mountinfo": containerMountInfoABC,
			"208/cmdline":   "python3\x00train.py\x00",
			// A kernel thread has an empty cmdline, and kdevtmpfs' namespace root
			// is a devtmpfs rather than the initrd's rootfs.
			"18/mountinfo": "6 5 0:5 / / rw,relatime - devtmpfs devtmpfs rw,size=9669488k\n",
		},
		map[string]string{
			"self/ns/mnt": "mnt:[111]",
			"208/ns/mnt":  "mnt:[222]",
			"18/ns/mnt":   "mnt:[333]",
		})
	if err := os.WriteFile(filepath.Join(proc, "self", "mountinfo"),
		[]byte("1 1 0:2 / / rw - rootfs rootfs rw,size=9669488k\n"+
			"22 1 0:29 / "+rootFS+"/rootfs rw - overlay overlay rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	target, err := Discover(context.Background(), Options{ProcRoot: proc})
	if err != nil {
		t.Fatalf("a kernel-thread namespace must not make discovery ambiguous: %v", err)
	}
	if target.PID() != 208 {
		t.Fatalf("PID=%d, want the container's process (208)", target.PID())
	}
}

// The container id is on the path TAA sees the root at, not on the overlay's
// own upperdir, which carries a layer id instead. Pinning containerId has to
// work with the measured layout.
func TestFilterByContainerIDUsesTheResolvedRootPath(t *testing.T) {
	stubProbe(t)
	base := filepath.Join(t.TempDir(), "run", "kata-containers")
	for _, id := range []string{"c5a2012e0d1b", "def"} {
		if err := os.MkdirAll(filepath.Join(base, id, "rootfs"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	layerOverlay := "1 63 0:29 / / rw - overlay overlay rw," +
		"lowerdir=/run/kata-containers/image/layers/7," +
		"upperdir=/run/kata-containers/image/overlay/2b9378f17c27/upperdir," +
		"workdir=/run/kata-containers/image/overlay/2b9378f17c27/workdir,uuid=on\n"
	self := "1 1 0:2 / / rw - rootfs rootfs rw\n" +
		"22 1 0:29 / " + base + "/c5a2012e0d1b/rootfs rw - overlay overlay rw\n" +
		"23 1 0:30 / " + base + "/def/rootfs rw - overlay overlay rw\n"
	proc := buildProcTree(t,
		map[string]string{
			"self/mountinfo": self,
			"208/mountinfo":  layerOverlay,
			"208/cmdline":    "python3\x00train.py\x00",
			"400/mountinfo":  strings.ReplaceAll(layerOverlay, "0:29", "0:30"),
			"400/cmdline":    "python3\x00train.py\x00",
		},
		map[string]string{
			"self/ns/mnt": "mnt:[111]",
			"208/ns/mnt":  "mnt:[222]",
			"400/ns/mnt":  "mnt:[333]",
		})

	target, err := Discover(context.Background(), Options{ProcRoot: proc, ContainerID: "c5a2012e0d1b"})
	if err != nil {
		t.Fatalf("Discover with a container id: %v", err)
	}
	if target.PID() != 208 {
		t.Fatalf("PID=%d, want the container whose root path carries the id (208)", target.PID())
	}
}
