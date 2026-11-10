package deployment

import (
	"os"
	"strings"
	"testing"
)

// The two fixtures are the root lines measured on 2026-11-10 in a live CSV2
// guest: the init namespace sees the initrd's ramfs, while a container reads
// its own overlaid root from the same file path.
const (
	initRootLine      = "1 1 0:2 / / rw - rootfs rootfs rw,size=9669488k\n"
	containerRootLine = "1 63 0:29 / / rw - overlay overlay rw,lowerdir=/run/kata-containers/abc/rootfs," +
		"upperdir=/run/kata-containers/abc/rootfs,workdir=/run/kata-containers/abc/work\n"
)

func readerFor(content string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return []byte(content), nil }
}

func failingReader(string) ([]byte, error) {
	return nil, os.ErrNotExist
}

func TestDetectExplicitMarker(t *testing.T) {
	cases := []struct {
		marker string
		want   Shape
	}{
		{"initrd", Initrd},
		{"container", Container},
		{"  Container\n", Container},
	}
	for _, c := range cases {
		got, err := detect(c.marker, failingReader)
		if err != nil {
			t.Fatalf("marker %q: unexpected error: %v", c.marker, err)
		}
		if !got.Explicit || got.Shape != c.want {
			t.Fatalf("marker %q: got shape=%v explicit=%v, want %v explicit", c.marker, got.Shape, got.Explicit, c.want)
		}
		if got.Warning != "" {
			t.Fatalf("marker %q: unexpected warning: %s", c.marker, got.Warning)
		}
		if got.Source() != "explicit marker" {
			t.Fatalf("marker %q: source=%q", c.marker, got.Source())
		}
	}
}

func TestDetectRejectsUnknownMarker(t *testing.T) {
	// A typo must fail loudly: this marker is set by the starter script, so a
	// value nobody understands means that script is wrong.
	_, err := detect("initrd ", failingReader) // trailing space at a non-trim boundary is fine
	if err != nil {
		t.Fatalf("whitespace should be trimmed, got error: %v", err)
	}
	if _, err := detect("Init-rd", failingReader); err == nil {
		t.Fatal("expected an error for an unknown marker value")
	}
}

func TestDetectInfersFromRootMount(t *testing.T) {
	cases := []struct {
		name     string
		mounts   string
		want     Shape
		wantWarn bool
	}{
		{"initrd ramfs", initRootLine, Initrd, true},
		{"container overlay", containerRootLine, Container, true},
	}
	for _, c := range cases {
		got, err := detect("", readerFor(c.mounts))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", c.name, err)
		}
		if got.Explicit {
			t.Fatalf("%s: inferred result must not be explicit", c.name)
		}
		if !got.Inferred || got.Shape != c.want {
			t.Fatalf("%s: got shape=%v inferred=%v, want %v", c.name, got.Shape, got.Inferred, c.want)
		}
		if c.wantWarn != (got.Warning != "") {
			t.Fatalf("%s: warning=%q", c.name, got.Warning)
		}
	}
}

func TestDetectUndeterminedWithoutMarkerOrMountInfo(t *testing.T) {
	got, err := detect("", failingReader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Shape != Unknown || got.Explicit || got.Inferred {
		t.Fatalf("got %+v, want Unknown", got)
	}
	if got.Warning == "" {
		t.Fatal("an undetermined shape must carry a warning")
	}
	if got.Source() != "undetermined" {
		t.Fatalf("source=%q", got.Source())
	}
}

func TestDetectWarnsOnMarkerMountDisagreement(t *testing.T) {
	// The marker still wins, but the disagreement must be visible.
	got, err := detect("initrd", readerFor(containerRootLine))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Shape != Initrd {
		t.Fatalf("marker should win, got %v", got.Shape)
	}
	if !strings.Contains(got.Warning, "overlay") {
		t.Fatalf("warning should name the observed fstype, got %q", got.Warning)
	}

	got, err = detect("container", readerFor(initRootLine))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Shape != Container || got.Warning == "" {
		t.Fatalf("got %+v, want Container with a warning", got)
	}
}

func TestParseRootFSType(t *testing.T) {
	// The root line is normally first, but the parser must not depend on that.
	mixed := "22 1 0:21 / /proc rw - proc proc rw\n" +
		"23 1 0:22 / /sys rw - sysfs sysfs rw\n" +
		containerRootLine
	if got := parseRootFSType(mixed); got != "overlay" {
		t.Fatalf("got %q, want overlay", got)
	}
	if got := parseRootFSType("garbage\n\n"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := parseRootFSType(""); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
