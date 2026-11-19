package mock

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The console describes one machine: its address, the memory left and the Pods
// running on it. Which machine that is comes from the probe (host_probe.go) —
// this process's own /proc/meminfo and kubectl by default, or a Hygon host
// reached over SSH when the mock does not run beside the cluster.
//
// Everything in this file is display material. A missing kubectl or an
// unreadable /proc degrades one row of the panel; it never fails a request
// that the console needs for anything else.

const (
	hostStatusTTL      = 4 * time.Second
	hostKubectlTimeout = 8 * time.Second
	// hostPodTableLimit bounds one response. A host running more Pods than this
	// has a console panel that is already unusable, and an unbounded payload on a
	// 5-second poll is worse than a truncated list.
	hostPodTableLimit = 200
	// hostPodCollectLimit bounds what the cache holds. It is deliberately far
	// above the display limit: the table is filtered by namespace per request, and
	// truncating before filtering would drop a namespace entirely just because
	// other namespaces filled the first 200 rows.
	hostPodCollectLimit = 5000
)

// hostPod is one Pod as the cluster reports it. Only fields the panel renders
// are kept: the raw object is large and almost all of it is noise here.
type hostPod struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Phase      string `json:"phase"`
	Ready      string `json:"ready"`
	Node       string `json:"node"`
	PodIP      string `json:"podIp"`
	Restarts   int    `json:"restarts"`
	AgeSeconds int64  `json:"ageSeconds"`
}

// hostMemory is the kernel's accounting of the host's physical memory.
// AvailableBytes is MemAvailable, not MemFree: the page cache counts as
// available and MemFree alone would make an idle host look exhausted.
type hostMemory struct {
	TotalBytes     uint64  `json:"totalBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsedBytes      uint64  `json:"usedBytes"`
	UsedPercent    float64 `json:"usedPercent"`
}

// hostPodNamespace is one row of the namespace filter: what to show in the
// dropdown and how many Pods it holds.
type hostPodNamespace struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// hostStatus is one poll's answer about the host.
//
// PodCount and Namespaces describe the whole cluster, while Pods and
// PodsTruncated describe the current filter. Splitting them is what lets the
// table shrink to one namespace without the counts changing.
type hostStatus struct {
	HostIP        string             `json:"hostIp"`
	HostIPs       []string           `json:"hostIps"`
	Hostname      string             `json:"hostname"`
	Target        hostTarget         `json:"target"`
	Memory        hostMemory         `json:"memory"`
	MemoryError   string             `json:"memoryError,omitempty"`
	Pods          []hostPod          `json:"pods"`
	PodsError     string             `json:"podsError,omitempty"`
	PodsTruncated bool               `json:"podsTruncated,omitempty"`
	PodCount      int                `json:"podCount"`
	Namespaces    []hostPodNamespace `json:"namespaces"`
	Namespace     string             `json:"namespace,omitempty"`
	CollectedAt   string             `json:"collectedAt"`
}

// hostSnapshot is what the cache holds: the whole cluster, unfiltered. The
// namespace filter is applied per request on top of it, so switching namespaces
// costs no kubectl call.
type hostSnapshot struct {
	HostIP      string
	HostIPs     []string
	Hostname    string
	Target      hostTarget
	Memory      hostMemory
	MemoryError string
	Pods        []hostPod
	PodsError   string
	CollectedAt string
}

// hostProbeSource is the one place the active probe changes. The config picks
// the starting probe; the console can point the panel at another host with its
// own credentials while the mock runs. Readers take the probe and its
// generation together: a snapshot is only valid for the generation that
// produced it, so numbers read from the previous machine are never served under
// the new machine's label.
type hostProbeSource struct {
	mu         sync.RWMutex
	probe      hostProbe
	generation uint64
}

func newHostProbeSource(probe hostProbe) *hostProbeSource {
	if probe == nil {
		probe = localHostProbe{}
	}
	return &hostProbeSource{probe: probe}
}

func (s *hostProbeSource) current() (hostProbe, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.probe, s.generation
}

func (s *hostProbeSource) currentGeneration() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// swap installs a probe and returns the generation that now identifies it.
func (s *hostProbeSource) swap(probe hostProbe) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probe = probe
	s.generation++
	return s.generation
}

// hostStatusCache keeps the probe off the polling path. The console polls every
// few seconds and each browser tab polls independently, so without a short TTL
// one page left open would fork a kubectl process per viewer per interval.
//
// The collection also runs off the request path: a local kubectl answers in
// milliseconds, but an SSH probe pays a handshake and a remote kubectl, and one
// that has lost the host would otherwise stall every poll for its whole budget.
// A poll past the TTL gets the last good snapshot and starts one background
// refresh; the next poll picks up the result.
type hostStatusCache struct {
	mu     sync.Mutex
	source *hostProbeSource
	grace  time.Duration
	ttl    time.Duration
	at     time.Time
	last   hostSnapshot
	// gen is the source generation last describes. A fresh cache has never
	// published anything, and at is zero then, so the pair is unambiguous.
	gen      uint64
	now      func() time.Time
	inFlight bool
	// refresh is a field so a test can make collection synchronous.
	refresh func()
}

// hostStatusGrace is how long a snapshot may be served after its TTL while a
// background refresh runs. Only a collection that outlasts it makes a poll wait.
const hostStatusGrace = 30 * time.Second

func newHostStatusCache(probe hostProbe, ttl time.Duration) *hostStatusCache {
	c := &hostStatusCache{source: newHostProbeSource(probe), ttl: ttl, grace: hostStatusGrace, now: time.Now}
	c.refresh = c.collect
	return c
}

func (c *hostStatusCache) get() hostSnapshot {
	c.mu.Lock()
	probe, gen := c.source.current()
	// A snapshot from another source is not a slow answer to this one: it
	// describes a different machine. Read the new source now instead of serving
	// the old machine's numbers under the new label.
	if gen != c.gen {
		c.inFlight = true
		c.mu.Unlock()
		return c.collectNow(probe, gen)
	}
	age := c.now().Sub(c.at)
	switch {
	case !c.at.IsZero() && age < c.ttl:
		// Fresh enough: answer now.
		snapshot := c.last
		c.mu.Unlock()
		return snapshot
	case !c.at.IsZero() && age < c.ttl+c.grace:
		// Stale but still inside the grace window: answer now and refresh
		// behind the answer.
		c.startRefreshLocked()
		snapshot := c.last
		c.mu.Unlock()
		return snapshot
	}
	// Cold start, or the last answer is too old to pass off as current. One
	// caller collects; a concurrent poll gets whatever is there rather than
	// queueing a second probe behind the first.
	if c.inFlight {
		snapshot := c.last
		c.mu.Unlock()
		return snapshot
	}
	c.inFlight = true
	c.mu.Unlock()
	c.refresh()
	c.mu.Lock()
	snapshot := c.last
	c.mu.Unlock()
	return snapshot
}

// startRefreshLocked launches one background collection, never two at once.
// The caller holds the lock.
func (c *hostStatusCache) startRefreshLocked() {
	if c.inFlight {
		return
	}
	c.inFlight = true
	go c.refresh()
}

// collect reads the probe and replaces the snapshot. It takes the lock only to
// publish, so a request reading the previous snapshot is never blocked behind
// an SSH handshake.
func (c *hostStatusCache) collect() {
	probe, gen := c.source.current()
	snapshot := collectHostSnapshot(probe)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight = false
	if gen != c.source.currentGeneration() {
		// The source changed while this read ran. Publishing it would put one
		// machine's numbers under another machine's label, which is the whole
		// failure this seam exists to prevent.
		return
	}
	c.last = snapshot
	c.gen = gen
	c.at = c.now()
}

// collectNow reads the source synchronously and publishes the result if the
// source is still the one that was asked for. It is used when no snapshot may
// be served — a cold start, a source that has just changed — and by the handler
// that changes the source, so the click that switches hosts gets the new
// machine's numbers, or the reason they could not be read, in its own response.
func (c *hostStatusCache) collectNow(probe hostProbe, gen uint64) hostSnapshot {
	snapshot := collectHostSnapshot(probe)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inFlight = false
	if gen == c.source.currentGeneration() {
		c.last = snapshot
		c.gen = gen
		c.at = c.now()
	}
	return snapshot
}

// setProbe points the panel at another machine and reads it immediately. The
// previous snapshot is dropped rather than kept as a fallback: it belongs to a
// machine the panel no longer names.
func (c *hostStatusCache) setProbe(probe hostProbe) hostSnapshot {
	if probe == nil {
		probe = localHostProbe{}
	}
	return c.collectNow(probe, c.source.swap(probe))
}

// hostStatusHandler serves the host panel. It is a plain console endpoint, not
// a TAA route: nothing here is addressed to an instance.
//
// ?namespace=<name> narrows the Pod table. Filtering here rather than in the
// browser keeps every workspace's counts consistent and stops a 5000-row cluster
// from being serialized on every 5-second poll of every open tab.
func hostStatusHandler(cache *hostStatusCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
		writeEnvelope(w, http.StatusOK, "success", cache.get().forNamespace(namespace), 0)
	}
}

// hostTargetRequest is the console's SSH connection form. The password is
// accepted here and nowhere else: it is not logged, not stored on disk, not
// echoed back, and lives only inside the probe it was used to build until
// another target replaces that probe.
type hostTargetRequest struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
}

// hostTargetHandler points the host panel at the machine named in the request,
// or back at this machine when no host is given.
//
// The endpoint exists because the mock and the Hygon host are not always the
// same machine, and the person holding that host's credentials is the one
// looking at the page. The source is runtime state on purpose: it is not
// persisted, so a restart returns to the configured target.
//
// Same-origin only: another page open in the operator's browser must not be
// able to make this process open an SSH connection.
func hostTargetHandler(cache *hostStatusCache, extraOptions string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOriginRequest(r) {
			writeEnvelope(w, http.StatusForbidden, "只接受控制台页面的请求", nil, 1)
			return
		}
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		var req hostTargetRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "请求体不是有效的 JSON", nil, 1)
			return
		}
		host := strings.TrimSpace(req.Host)
		var probe hostProbe
		if host == "" {
			probe = localHostProbe{}
		} else {
			spec := host
			if user := strings.TrimSpace(req.User); user != "" {
				spec = user + "@" + host
			}
			built, err := newSSHHostProbe(spec, req.Password, extraOptions)
			if err != nil {
				writeEnvelope(w, http.StatusBadRequest, "SSH 目标无效: "+err.Error(), nil, 1)
				return
			}
			probe = built
		}
		// The response carries the first read from the new source, so the click
		// that switched gets either the new numbers or the reason they are
		// unreadable without waiting for the next poll.
		writeEnvelope(w, http.StatusOK, "success", cache.setProbe(probe).forNamespace(""), 0)
	}
}

// sameOriginRequest accepts a request that did not come from another origin. A
// non-browser client sends no Origin and is allowed: the mock is an operator
// tool on a trusted network, and the check is aimed at a page in the operator's
// own browser, not at curl.
func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	return originMatchesHost(origin, r.Host)
}

// forNamespace projects the snapshot onto one namespace. An empty or unknown
// namespace means "all", which is what an operator gets before choosing one and
// what a remembered namespace falls back to once its Pods are gone.
func (s hostSnapshot) forNamespace(namespace string) hostStatus {
	status := hostStatus{
		HostIP:      s.HostIP,
		HostIPs:     s.HostIPs,
		Hostname:    s.Hostname,
		Target:      s.Target,
		Memory:      s.Memory,
		MemoryError: s.MemoryError,
		PodsError:   s.PodsError,
		PodCount:    len(s.Pods),
		Namespace:   namespace,
		CollectedAt: s.CollectedAt,
	}
	status.Namespaces = namespaceCounts(s.Pods)
	if namespace != "" {
		known := false
		for _, ns := range status.Namespaces {
			if ns.Name == namespace {
				known = true
				break
			}
		}
		// A remembered namespace whose Pods have all gone falls back to all, so
		// the panel never shows "0 个" while the host is plainly busy.
		if !known {
			status.Namespace = ""
			namespace = ""
		}
	}

	filtered := make([]hostPod, 0, len(s.Pods))
	for _, pod := range s.Pods {
		if namespace == "" || pod.Namespace == namespace {
			filtered = append(filtered, pod)
		}
	}
	if len(filtered) > hostPodTableLimit {
		filtered = filtered[:hostPodTableLimit]
		status.PodsTruncated = true
	}
	status.Pods = filtered
	return status
}

// namespaceCounts lists the namespaces present, largest first, then by name.
// The largest first because the filter's first use is "show me the busy one".
func namespaceCounts(pods []hostPod) []hostPodNamespace {
	counts := make(map[string]int)
	for _, pod := range pods {
		counts[pod.Namespace]++
	}
	out := make([]hostPodNamespace, 0, len(counts))
	for name, count := range counts {
		out = append(out, hostPodNamespace{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func collectHostSnapshot(probe hostProbe) hostSnapshot {
	// No deadline here: each probe read carries its own budget (the local
	// kubectl timeout, the SSH probe's connect and total timeouts), so a slow
	// memory read cannot eat the Pod list's allowance.
	ctx := context.Background()
	snapshot := hostSnapshot{
		Target:      probe.Describe(),
		HostIPs:     hostIPs(),
		CollectedAt: time.Now().Format(time.RFC3339),
	}
	if len(snapshot.HostIPs) > 0 {
		snapshot.HostIP = snapshot.HostIPs[0]
	}
	// The address and name the panel shows are the machine the operator reaches,
	// which is not this process's own once the panel reads a host over SSH. The
	// local hostname is deliberately not used there: showing this machine's name
	// beside a remote address is the same mislabel the probe exists to end.
	if snapshot.Target.Mode == "ssh" && snapshot.Target.Host != "" {
		remoteHost := hostOfTarget(snapshot.Target.Host)
		snapshot.HostIP = remoteHost
		snapshot.HostIPs = []string{remoteHost}
		snapshot.Hostname = remoteHost
	} else {
		if name, err := os.Hostname(); err == nil {
			snapshot.Hostname = name
		}
	}
	mem, err := probe.Memory(ctx)
	if err != nil {
		snapshot.MemoryError = err.Error()
	} else {
		snapshot.Memory = mem
	}
	// Pods are read with no namespace: the snapshot holds the whole cluster and
	// forNamespace filters it per request, so switching the dropdown costs no
	// probe. A remote read is expensive enough that this matters more.
	pods, err := probe.Pods(ctx, "")
	if err != nil {
		snapshot.PodsError = err.Error()
	}
	snapshot.Pods = pods
	return snapshot
}

// hostOfTarget drops the "user@" half of an SSH destination for display.
func hostOfTarget(target string) string {
	if at := strings.LastIndex(target, "@"); at >= 0 && at < len(target)-1 {
		return target[at+1:]
	}
	return target
}

// hostIPs returns the host's non-loopback IPv4 addresses, best first.
//
// The order matters because the console prefills its address field with the
// first entry. A machine that carries a Kubernetes pod network, a container
// bridge and a VPN has several addresses and only one of them is the one an
// operator types into TAA's PLATFORM_IP, so the classic host ranges are ranked
// above everything else and the CGNAT range (Tailscale) is ranked last.
func hostIPs() []string {
	addrs := localIPv4Addrs()
	out := make([]string, 0, len(addrs))
	for _, text := range addrs {
		if text == "127.0.0.1" {
			continue
		}
		out = append(out, text)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return hostIPRank(out[i]) < hostIPRank(out[j])
	})
	return out
}

// hostIPRank is the sort key for hostIPs: 0 is the most likely platform
// address, larger numbers less likely.
func hostIPRank(address string) int {
	ip := net.ParseIP(address).To4()
	if ip == nil {
		return 9
	}
	switch {
	case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
		// The cluster's own management range on these hosts.
		return 0
	case ip[0] == 192 && ip[1] == 168:
		return 1
	case ip[0] == 10:
		return 2
	case ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127:
		// CGNAT, which is where Tailscale puts its interface.
		return 4
	default:
		return 3
	}
}

var (
	errUnsupportedPlatform = errors.New("当前系统不支持读取宿主机内存")
	errNoMemoryInfo        = errors.New("/proc/meminfo 中没有 MemTotal")
)

// readHostMemory parses MemTotal and MemAvailable out of /proc/meminfo.
//
// The values are in kB by the kernel's own definition (1024 bytes) regardless
// of the field name, so the conversion is a plain shift.
func readHostMemory() (hostMemory, error) {
	if runtime.GOOS != "linux" {
		return hostMemory{}, errUnsupportedPlatform
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return hostMemory{}, err
	}
	return parseHostMemory(string(data))
}

// parseHostMemory reads the fields the panel renders out of /proc/meminfo. It is
// shared with the SSH probe, which fetches the same file from the far side: the
// kernel's format is the part both ends agree on.
func parseHostMemory(text string) (hostMemory, error) {
	var mem hostMemory
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			mem.TotalBytes = value * 1024
		case "MemAvailable:":
			mem.AvailableBytes = value * 1024
		}
	}
	if mem.TotalBytes == 0 {
		return hostMemory{}, errNoMemoryInfo
	}
	if mem.AvailableBytes > mem.TotalBytes {
		mem.AvailableBytes = mem.TotalBytes
	}
	mem.UsedBytes = mem.TotalBytes - mem.AvailableBytes
	mem.UsedPercent = float64(mem.UsedBytes) * 100 / float64(mem.TotalBytes)
	return mem, nil
}

// listHostPods asks kubectl for the Pods on the host. An empty namespace means
// every namespace, which is what the panel shows by default: the console's own
// TAA and TEE-LLM Pods live in the platform namespace, not in "default".
//
// Failure is returned rather than swallowed: "no Pods" and "kubectl is not
// installed" look identical in an empty table, and they call for different
// operator action.
func listHostPods(ctx context.Context, namespace string) ([]hostPod, error) {
	ctx, cancel := context.WithTimeout(ctx, hostKubectlTimeout)
	defer cancel()
	args := []string{"get", "pods", "-o", "json"}
	if strings.TrimSpace(namespace) != "" {
		args = append(args, "-n", strings.TrimSpace(namespace))
	} else {
		args = append(args, "-A")
	}
	out, err := exec.CommandContext(ctx, "kubectl", args...).Output()
	if err != nil {
		return nil, describeKubectlError(err)
	}
	return parseKubePods(out)
}

type kubePodList struct {
	Items []struct {
		Metadata struct {
			Name              string `json:"name"`
			Namespace         string `json:"namespace"`
			CreationTimestamp string `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			NodeName   string `json:"nodeName"`
			Containers []struct {
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			PodIP             string `json:"podIP"`
			ContainerStatuses []struct {
				Ready        bool `json:"ready"`
				RestartCount int  `json:"restartCount"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func parseKubePods(raw []byte) ([]hostPod, error) {
	var list kubePodList
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	now := time.Now()
	pods := make([]hostPod, 0, len(list.Items))
	for _, item := range list.Items {
		pod := hostPod{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Phase:     item.Status.Phase,
			Node:      item.Spec.NodeName,
			PodIP:     item.Status.PodIP,
		}
		ready := 0
		for _, cs := range item.Status.ContainerStatuses {
			if cs.Ready {
				ready++
			}
			if cs.RestartCount > pod.Restarts {
				pod.Restarts = cs.RestartCount
			}
		}
		pod.Ready = strconv.Itoa(ready) + "/" + strconv.Itoa(len(item.Spec.Containers))
		if started, err := time.Parse(time.RFC3339, item.Metadata.CreationTimestamp); err == nil {
			pod.AgeSeconds = int64(now.Sub(started).Seconds())
			if pod.AgeSeconds < 0 {
				pod.AgeSeconds = 0
			}
		}
		pods = append(pods, pod)
	}
	sort.SliceStable(pods, func(i, j int) bool {
		if pods[i].Namespace != pods[j].Namespace {
			return pods[i].Namespace < pods[j].Namespace
		}
		return pods[i].Name < pods[j].Name
	})
	if len(pods) > hostPodCollectLimit {
		pods = pods[:hostPodCollectLimit]
	}
	return pods, nil
}

// describeKubectlError turns an exec failure into the two facts the panel needs:
// whether kubectl exists, and what it said. The command's own stderr is the
// useful half - a refused connection and a missing kubeconfig read very
// differently to an operator.
func describeKubectlError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		msg := strings.TrimSpace(string(exitErr.Stderr))
		if msg == "" {
			msg = exitErr.Error()
		}
		return &hostStatusError{msg: "kubectl 执行失败: " + firstLine(msg)}
	}
	return &hostStatusError{msg: "kubectl 不可用: " + firstLine(err.Error())}
}

func firstLine(text string) string {
	text = strings.TrimSpace(text)
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		text = strings.TrimSpace(text[:idx])
	}
	if len(text) > 300 {
		text = text[:300] + "…"
	}
	return text
}

// hostStatusError carries a message already written for the operator, so the
// handler does not have to re-word an exec error.
type hostStatusError struct{ msg string }

func (e *hostStatusError) Error() string { return e.msg }
