package mock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const instancesDirName = "instances"

var (
	errInstanceNotFound = errors.New("指定的 dockerId 不存在")
	errNoInstance       = errors.New("no TAA instance registered yet")
)

// legacyStateFiles are the files the single-instance layout kept in the state
// directory root. Migration moves them into one instance directory.
var legacyStateFiles = []string{
	"register-state.json",
	"report-state.json",
	"reportRes-state.json",
	"reportModelImport-state.json",
	"reportAudit-state.json",
	"reportProgress-state.json",
	"modelLog-state.json",
	"taaLog-state.json",
}

type instanceMeta struct {
	DockerID  string `json:"dockerId"`
	TaaTarget string `json:"taaTarget,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// instanceStores bundles the eight persisted stores that belong to one TAA
// instance. The store types are reused unchanged: only the directory differs,
// so every existing file format keeps working.
type instanceStores struct {
	mu       sync.RWMutex
	dockerID string
	dir      string
	meta     instanceMeta

	register          *registerStateStore
	reportResourceRes *reportStateStore
	reportRes         *reportStateStore
	reportModelImport *reportStateStore
	reportAudit       *reportStateStore
	progress          *progressStateStore
	modelLog          *modelLogStore
	taaLog            *taaLogStore
}

// instanceDirName derives the directory from the dockerId. The hash keeps
// arbitrary ids (path separators included) from escaping the instances root.
func instanceDirName(dockerID string) string {
	if dockerID == "" {
		return "i-legacy"
	}
	sum := sha256.Sum256([]byte(dockerID))
	return "i-" + hex.EncodeToString(sum[:])[:16]
}

func newInstanceStores(dir, dockerID string) *instanceStores {
	now := time.Now().Format(time.RFC3339)
	return &instanceStores{
		dockerID:          dockerID,
		dir:               dir,
		meta:              instanceMeta{DockerID: dockerID, CreatedAt: now, UpdatedAt: now},
		register:          newRegisterStateStore(dir),
		reportResourceRes: newReportStateStore(dir),
		reportRes:         newReportStateStore(dir, "reportRes-state.json"),
		reportModelImport: newReportStateStore(dir, "reportModelImport-state.json"),
		reportAudit:       newReportStateStore(dir, "reportAudit-state.json"),
		progress:          newProgressStateStore(dir),
		modelLog:          newModelLogStore(dir, 2000),
		taaLog:            newTaaLogStore(dir, 2000),
	}
}

func loadInstanceStores(dir, dockerID string) *instanceStores {
	b := newInstanceStores(dir, dockerID)
	meta, err := loadJSONFile[instanceMeta](filepath.Join(dir, "instance.json"))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load instance metadata from %s failed: %v", dir, err)
		}
		return b
	}
	if meta.DockerID != "" {
		b.dockerID = meta.DockerID
	}
	b.meta = meta
	if b.meta.CreatedAt == "" {
		b.meta.CreatedAt = time.Now().Format(time.RFC3339)
	}
	if b.meta.UpdatedAt == "" {
		b.meta.UpdatedAt = b.meta.CreatedAt
	}
	return b
}

func (b *instanceStores) target() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.meta.TaaTarget
}

// setTarget records the address TAA registered from. The address is kept in
// instance.json, not in register-state.json, so a console reset of the register
// card does not silently break outbound traffic.
func (b *instanceStores) setTarget(target string) {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	b.mu.Lock()
	if b.meta.TaaTarget == target {
		b.mu.Unlock()
		return
	}
	b.meta.TaaTarget = target
	b.meta.UpdatedAt = time.Now().Format(time.RFC3339)
	meta := b.meta
	b.mu.Unlock()
	b.saveMeta(meta)
}

func (b *instanceStores) saveMeta(meta instanceMeta) {
	if b.dir == "" {
		return
	}
	if err := os.MkdirAll(b.dir, 0o755); err != nil {
		log.Printf("create instance directory %s failed: %v", b.dir, err)
		return
	}
	if err := saveJSONFile(filepath.Join(b.dir, "instance.json"), meta); err != nil {
		log.Printf("save instance metadata to %s failed: %v", b.dir, err)
	}
}

// instanceManager owns the per-dockerId bundles. Its map is guarded by mu;
// each bundle's stores keep their own locks.
type instanceManager struct {
	mu      sync.RWMutex
	root    string
	cfg     Config
	byID    map[string]*instanceStores
	scanned bool

	staticTarget     string
	discoveredTarget string
}

func newInstanceManager(stateDir string, cfg Config) *instanceManager {
	m := &instanceManager{
		root:         stateDir,
		cfg:          cfg,
		byID:         make(map[string]*instanceStores),
		staticTarget: strings.TrimRight(strings.TrimSpace(cfg.TAATarget), "/"),
	}
	if m.root != "" {
		m.migrateLegacy()
		if err := os.MkdirAll(filepath.Join(m.root, instancesDirName), 0o755); err != nil {
			log.Printf("create instances directory under %s failed: %v", m.root, err)
		}
		m.scan()
	}
	if m.staticTarget == "" {
		m.discoveredTarget = discoverTAAAddr(cfg.TAAPod, cfg.TAANS, strings.TrimSpace(cfg.TAAPort))
	}
	return m
}

func (m *instanceManager) migrateLegacy() {
	instRoot := filepath.Join(m.root, instancesDirName)
	if _, err := os.Stat(instRoot); err == nil {
		for _, name := range legacyStateFiles {
			if _, statErr := os.Stat(filepath.Join(m.root, name)); statErr == nil {
				log.Printf("legacy state file %s is ignored because %s already exists", name, instRoot)
			}
		}
		return
	}

	found := false
	for _, name := range legacyStateFiles {
		if _, err := os.Stat(filepath.Join(m.root, name)); err == nil {
			found = true
			break
		}
	}
	if !found {
		return
	}

	dockerID := ""
	if state, err := loadJSONFile[registerState](filepath.Join(m.root, "register-state.json")); err == nil {
		dockerID = strings.TrimSpace(state.DockerID)
	}
	dir := filepath.Join(instRoot, instanceDirName(dockerID))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("create migration directory %s failed: %v", dir, err)
		return
	}
	for _, name := range legacyStateFiles {
		src := filepath.Join(m.root, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(dir, name)); err != nil {
			log.Printf("migrate legacy state file %s failed: %v", src, err)
		}
	}
	b := newInstanceStores(dir, dockerID)
	now := time.Now().Format(time.RFC3339)
	b.meta.CreatedAt = now
	b.meta.UpdatedAt = now
	b.saveMeta(b.meta)
	log.Printf("migrated legacy single-instance state into %s (dockerId=%q)", dir, dockerID)
}

func (m *instanceManager) scan() {
	entries, err := os.ReadDir(filepath.Join(m.root, instancesDirName))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("scan instances failed: %v", err)
		}
		m.scanned = true
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(m.root, instancesDirName, entry.Name())
		meta, err := loadJSONFile[instanceMeta](filepath.Join(dir, "instance.json"))
		if err != nil {
			log.Printf("skip instance directory %s without readable instance.json: %v", dir, err)
			continue
		}
		b := loadInstanceStores(dir, meta.DockerID)
		m.byID[b.dockerID] = b
	}
	m.scanned = true
}

func (m *instanceManager) getOrCreate(dockerID string) *instanceStores {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.byID[dockerID]; ok {
		return b
	}
	dir := ""
	if m.root != "" {
		dir = filepath.Join(m.root, instancesDirName, instanceDirName(dockerID))
	}
	b := newInstanceStores(dir, dockerID)
	b.saveMeta(b.meta)
	m.byID[dockerID] = b
	return b
}

func (m *instanceManager) lookup(dockerID string) *instanceStores {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byID[dockerID]
}

func (m *instanceManager) list() []*instanceStores {
	m.mu.RLock()
	bundles := make([]*instanceStores, 0, len(m.byID))
	for _, b := range m.byID {
		bundles = append(bundles, b)
	}
	m.mu.RUnlock()
	sort.SliceStable(bundles, func(i, j int) bool {
		return instanceLess(bundles[i], bundles[j])
	})
	return bundles
}

func instanceLess(a, b *instanceStores) bool {
	sa, sb := a.register.get(), b.register.get()
	if sa.Accepted != sb.Accepted {
		return sa.Accepted
	}
	if sa.Received != sb.Received {
		return sa.Received
	}
	if sa.ReceivedAt != sb.ReceivedAt {
		return sa.ReceivedAt > sb.ReceivedAt
	}
	return a.dockerID < b.dockerID
}

func (m *instanceManager) defaultBundle() *instanceStores {
	bundles := m.list()
	if len(bundles) == 0 {
		return nil
	}
	return bundles[0]
}

func (m *instanceManager) defaultID() string {
	if b := m.defaultBundle(); b != nil {
		return b.dockerID
	}
	return ""
}

// instanceForWrite picks the bundle an inbound callback writes to. New
// instances are created only by registration; a callback from an id the mock
// has never registered falls back to the legacy bundle instead of creating a
// directory per spoofed id.
func (m *instanceManager) instanceForWrite(dockerID string, accepted bool) *instanceStores {
	if accepted && dockerID != "" {
		return m.getOrCreate(dockerID)
	}
	if b := m.lookup(dockerID); b != nil {
		return b
	}
	return m.getOrCreate("")
}

func requestedDockerID(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return strings.TrimSpace(r.URL.Query().Get("dockerId"))
}

func (m *instanceManager) resolve(r *http.Request) (*instanceStores, error) {
	if id := requestedDockerID(r); id != "" {
		if b := m.lookup(id); b != nil {
			return b, nil
		}
		return nil, errInstanceNotFound
	}
	if b := m.defaultBundle(); b != nil {
		return b, nil
	}
	return nil, errNoInstance
}

// resolveLenient is for the console endpoints that must answer before any TAA
// has registered (the readiness probe is one). An explicitly unknown dockerId
// is still an error; only the "nothing registered yet" case degrades to the
// empty legacy bundle.
func (m *instanceManager) resolveLenient(r *http.Request) (*instanceStores, error) {
	b, err := m.resolve(r)
	if err == errNoInstance {
		return m.getOrCreate(""), nil
	}
	return b, err
}

// targetFor resolves the outbound address for one instance.
//
// Precedence, in order: a single instance with -taa-target keeps the old static
// address; otherwise the address derived from that instance's registration;
// then the static target; then Pod discovery. An instance never borrows another
// instance's address.
func (m *instanceManager) targetFor(requestedID string) (string, string, error) {
	var b *instanceStores
	if requestedID != "" {
		b = m.lookup(requestedID)
		if b == nil {
			return "", "", errInstanceNotFound
		}
	} else {
		b = m.defaultBundle()
	}

	if b != nil {
		id := b.dockerID
		if len(m.list()) <= 1 && m.staticTarget != "" {
			return id, m.staticTarget, nil
		}
		if target := b.target(); target != "" {
			return id, target, nil
		}
		if m.staticTarget != "" {
			return id, m.staticTarget, nil
		}
		if m.discoveredTarget != "" {
			return id, m.discoveredTarget, nil
		}
		return id, "", fmt.Errorf("TAA 地址未配置: 实例 %q 没有推导地址，且未设置 -taa-target 或 -taa-pod", id)
	}

	if m.staticTarget != "" {
		return "", m.staticTarget, nil
	}
	if m.discoveredTarget != "" {
		return "", m.discoveredTarget, nil
	}
	return "", "", errNoInstance
}
