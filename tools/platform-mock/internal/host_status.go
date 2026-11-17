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

// The console runs next to the machine it drives: the mock lives on the Hygon
// host, so the host facts it shows (address, memory left, the Pods that exist)
// are read here rather than collected from a remote agent. Two sources are used,
// both local and read-only: the kernel's own /proc/meminfo and kubectl.
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
	Memory      hostMemory
	MemoryError string
	Pods        []hostPod
	PodsError   string
	CollectedAt string
}

// hostStatusCache keeps kubectl off the polling path. The console polls every
// few seconds and each browser tab polls independently, so without a short TTL
// one page left open would fork a kubectl process per viewer per interval.
type hostStatusCache struct {
	mu        sync.Mutex
	namespace string
	ttl       time.Duration
	at        time.Time
	last      hostSnapshot
	now       func() time.Time
}

func newHostStatusCache(namespace string, ttl time.Duration) *hostStatusCache {
	return &hostStatusCache{namespace: namespace, ttl: ttl, now: time.Now}
}

func (c *hostStatusCache) get() hostSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.at.IsZero() && now.Sub(c.at) < c.ttl {
		return c.last
	}
	c.last = collectHostSnapshot(c.namespace)
	c.at = now
	return c.last
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

// forNamespace projects the snapshot onto one namespace. An empty or unknown
// namespace means "all", which is what an operator gets before choosing one and
// what a remembered namespace falls back to once its Pods are gone.
func (s hostSnapshot) forNamespace(namespace string) hostStatus {
	status := hostStatus{
		HostIP:      s.HostIP,
		HostIPs:     s.HostIPs,
		Hostname:    s.Hostname,
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

func collectHostSnapshot(namespace string) hostSnapshot {
	snapshot := hostSnapshot{
		HostIPs:     hostIPs(),
		CollectedAt: time.Now().Format(time.RFC3339),
	}
	if len(snapshot.HostIPs) > 0 {
		snapshot.HostIP = snapshot.HostIPs[0]
	}
	if name, err := os.Hostname(); err == nil {
		snapshot.Hostname = name
	}
	mem, err := readHostMemory()
	if err != nil {
		snapshot.MemoryError = err.Error()
	} else {
		snapshot.Memory = mem
	}
	pods, err := listHostPods(namespace, hostKubectlTimeout)
	if err != nil {
		snapshot.PodsError = err.Error()
	}
	snapshot.Pods = pods
	return snapshot
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
	var mem hostMemory
	for _, line := range strings.Split(string(data), "\n") {
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
func listHostPods(namespace string, timeout time.Duration) ([]hostPod, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
