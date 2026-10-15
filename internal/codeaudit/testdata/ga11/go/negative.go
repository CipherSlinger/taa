// Negative control for the Go TAA rule pack: an ordinary service helper that
// must produce zero findings from any of the thirteen families the pack covers.
//
// It is a near miss on purpose. Each family represented here carries its sink
// call shape - the same API calls the positive sample makes - with an argument
// chosen to fail that family's predicate, so a rule whose predicate is dropped
// starts matching this file instead of staying silent. Benign code that never
// makes the call at all cannot see a widening; a near miss can.
//
//   - taa-env-secret-go: os.Getenv and os.LookupEnv on names ("HOME", "PORT")
//     that miss the sensitive-keyword alternation.
//   - taa-fil-probe-go: os.Open, os.OpenFile, os.ReadFile and two-argument
//     filepath.Join on application paths, where no path and no base name
//     satisfies the credential-file alternation.
//   - taa-per-backdoor-go: the persistence write's shape - a path built under
//     the home directory and handed to os.WriteFile - naming no start-up file.
//   - taa-emb-data-dump-go: os.WriteFile, a buffer's Write and an encoder's
//     Encode on a payload whose name misses the dataset-name alternation.
//   - taa-emb-copy-export-go: os.Rename, os.Link and io.Copy whose destination
//     misses the export-directory alternation.
//   - taa-emb-log-dump-go: fmt.Println, log.Println and log.Printf on a value
//     whose name misses the dataset-name alternation.
//   - taa-emb-stego-weight-go: the weights artefact on one line and the
//     transform step it would have to share a line with on another.
//
// Six families are absent, and they have to be, because this file must not
// fire. taa-cmd-exec-go, taa-net-general-go, taa-net-socket-go, taa-dyn-eval-go
// and taa-obf-exec-go match the bare sink call with any argument at all, so no
// benign form of one of them exists to write. Every sink of
// taa-secret-exfiltration-go is also a pattern of those two network rules, so a
// call that would exercise it comes back as one of their findings either way.
// Those six are what this file cannot test - stated rather than hidden; a
// predicate added to one of them shows up only in the positive sample.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// settings is what the helper resolves at start-up: the directory it works in
// and the paths it reads and writes.
type settings struct {
	home    string
	logPath string
	config  string
	state   string
}

// loadSettings reads the environment and the service's own configuration file.
// Both environment reads are bare names - a home directory and a port - so the
// secret-keyword predicate goes unmet.
func loadSettings() settings {
	s := settings{
		home:    os.Getenv("HOME"),
		logPath: filepath.Join(os.Getenv("HOME"), "manifest.json"),
		config:  "config/app.yaml",
		state:   "state/app.json",
	}
	if port, ok := os.LookupEnv("PORT"); ok {
		log.Printf("listening on %s", port)
	}
	if raw, err := os.ReadFile(s.config); err == nil {
		s.state = string(bytes.TrimSpace(raw))
	}
	return s
}

// checkPaths opens the two paths the service works with. Each is a state or log
// path, so no argument here names a credential file.
func checkPaths(s settings) error {
	f, err := os.Open(s.logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := os.OpenFile(s.state, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	return out.Close()
}

// installHook writes the start-up script the service runs on boot, into the
// directory it owns under the home directory. The shape is the persistence
// write the backdoor family looks for; the name it lands under belongs to the
// service, so no start-up file is named on the line.
func installHook(s settings) error {
	target := filepath.Join(s.home, "start-hook.sh")
	return os.WriteFile(target, []byte("#!/bin/sh\nexec service --foreground\n"), 0o755)
}

// publish moves a finished report into place, keeps the previous one beside it
// and streams a copy of the report out. None of the destinations names an
// export directory.
func publish(dst string) error {
	src := dst + ".tmp"
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	if err := os.Link(src, dst+".prev"); err != nil {
		return err
	}
	out, err := os.Create(filepath.Join(filepath.Dir(dst), "summary.csv"))
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, os.Stdin)
	return err
}

// saveSnapshot writes the in-memory snapshot out, buffers a copy of it and
// encodes that copy to the sidecar. The payload is a snapshot throughout, so no
// name here is a dataset name.
func saveSnapshot(snap []byte, dst string) error {
	buf := new(bytes.Buffer)
	if _, err := buf.Write(snap); err != nil {
		return err
	}
	if err := os.WriteFile(dst, snap, 0o644); err != nil {
		return err
	}
	enc := json.NewEncoder(buf)
	return enc.Encode(snap)
}

// writeWeights stores the weights artefact the loader handed it as raw bytes.
// There is no transform step on this line, and the encoder in saveSnapshot is a
// function away from the artefact.
func writeWeights(weights []byte, dst string) error {
	return os.WriteFile(dst, weights, 0o644)
}

func main() {
	s := loadSettings()
	if err := checkPaths(s); err != nil {
		log.Fatalf("check paths: %v", err)
	}
	if err := installHook(s); err != nil {
		log.Fatalf("install hook: %v", err)
	}
	if err := publish("state/snapshot.bin"); err != nil {
		log.Println(err)
		return
	}
	snap := []byte(s.state)
	if err := saveSnapshot(snap, "state/snapshot.bin"); err != nil {
		log.Fatalf("save snapshot: %v", err)
	}
	if err := writeWeights(snap, "state/model.bin"); err != nil {
		log.Fatalf("write weights: %v", err)
	}
	fmt.Println("service ready")
}
