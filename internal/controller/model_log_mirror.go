package controller

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// mirrorInterval is how often the model's log and progress files are copied
// from where the target wrote them into the directories TAA watches. It is a
// copy interval, not a poll of the model: the reporter keeps its own cadence,
// and half a second is short enough that the platform view lags the model by
// less than one report.
const mirrorInterval = 500 * time.Millisecond

// logMirror copies the model's log directory and progress file from the
// execution target's view into TAA's own directories.
//
// Only a non-local target needs it: when the model runs inside a container its
// files are written under the container root, while the report watcher tails
// TAA's paths. The mirror never fails a task - a model that trained correctly
// did so whether or not its log could be copied - so every failure is a
// warning, reported once per distinct message.
type logMirror struct {
	srcLogDir, dstLogDir     string
	srcProgress, dstProgress string
	warn                     func(format string, args ...any)
	ctx                      context.Context
	cancel                   context.CancelFunc
	done                     chan struct{}
	stopOnce                 sync.Once

	mu           sync.Mutex
	offsets      map[string]int64
	lastProgress []byte
	lastWarn     string
}

// startLogMirror starts mirroring and returns the handle. It returns nil when
// source and destination are the same path, which is the local target: there
// is nothing to mirror and copying a file onto itself would truncate it.
func startLogMirror(parent context.Context, srcLogDir, dstLogDir, srcProgress, dstProgress string, warn func(string, ...any)) *logMirror {
	if srcLogDir == dstLogDir && srcProgress == dstProgress {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	m := &logMirror{
		srcLogDir:   srcLogDir,
		dstLogDir:   dstLogDir,
		srcProgress: srcProgress,
		dstProgress: dstProgress,
		warn:        warn,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
		offsets:     map[string]int64{},
	}
	go m.run()
	return m
}

// Stop performs a final sync and stops the goroutine. It is safe to call more
// than once and from the deferred path as well as the normal one.
func (m *logMirror) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		m.cancel()
		<-m.done
	})
}

func (m *logMirror) run() {
	defer close(m.done)
	ticker := time.NewTicker(mirrorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			m.sync()
			return
		case <-ticker.C:
			m.sync()
		}
	}
}

// sync mirrors one round: appended log bytes, then the progress file.
func (m *logMirror) sync() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.syncLogDir(); err != nil {
		m.warnOnce(err)
	}
	if err := m.syncProgress(); err != nil {
		m.warnOnce(err)
	}
}

// warnOnce reports a mirror failure, but only when the message changes: the
// loop runs twice a second and a missing directory would otherwise fill the
// platform log channel.
func (m *logMirror) warnOnce(err error) {
	msg := err.Error()
	if msg == m.lastWarn {
		return
	}
	m.lastWarn = msg
	if m.warn != nil {
		m.warn("镜像容器侧训练日志失败: %v", err)
	}
}

// syncLogDir appends whatever the model wrote since the last round. Files are
// matched by name and tracked by offset, so a log that only grows is copied
// once. A file that shrank was rewritten, and its offset restarts at zero so
// the destination follows the file rather than keeping a stale prefix.
func (m *logMirror) syncLogDir() error {
	entries, err := os.ReadDir(m.srcLogDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(m.dstLogDir, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if !info.Mode().IsRegular() {
			// A symlink or device in the log directory is not something the
			// mirror follows: it only ever copies the bytes the model wrote.
			continue
		}
		srcPath := filepath.Join(m.srcLogDir, entry.Name())
		offset := m.offsets[entry.Name()]
		if info.Size() < offset {
			offset = 0
		}
		if info.Size() == offset {
			continue
		}
		written, err := appendFrom(srcPath, filepath.Join(m.dstLogDir, entry.Name()), offset)
		if err != nil {
			return err
		}
		m.offsets[entry.Name()] = offset + written
	}
	return nil
}

// appendFrom copies src[start:] onto the end of dst and returns the byte count.
func appendFrom(src, dst string, start int64) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	if _, err := in.Seek(start, io.SeekStart); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, in)
	if err != nil {
		out.Close()
		return n, err
	}
	return n, out.Close()
}

// syncProgress replaces the destination with the source in one rename, so a
// reader never sees a half-written progress file. The content is compared
// first: the model rewrites the file often and a no-op must stay a no-op.
func (m *logMirror) syncProgress() error {
	data, err := os.ReadFile(m.srcProgress)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if bytes.Equal(data, m.lastProgress) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.dstProgress), 0o755); err != nil {
		return err
	}
	tmp := m.dstProgress + ".mirror-tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.dstProgress); err != nil {
		os.Remove(tmp)
		return err
	}
	m.lastProgress = data
	return nil
}
