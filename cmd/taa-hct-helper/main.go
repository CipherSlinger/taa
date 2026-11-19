package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/CipherSlinger/teeaudit/hctproto"
)

const buildID = "taa-hct-helper-1"

func main() {
	serve := flag.Bool("serve", false, "serve the HCT request protocol on stdin/stdout")
	selftest := flag.Bool("selftest", false, "run known-answer tests against libhct and exit")
	showVersion := flag.Bool("version", false, "print the libhct version and exit")
	accel := flag.String("accel", "sw", "HCT acceleration backend: sw or ccp (ccp falls back to sw when unavailable)")
	flag.Parse()

	if !*serve && !*selftest && !*showVersion {
		fmt.Fprintln(os.Stderr, "usage: taa-hct-helper --serve | --selftest | --version [--accel sw|ccp]")
		os.Exit(2)
	}

	eng, err := newEngine(*accel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taa-hct-helper: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	switch {
	case *showVersion:
		fmt.Println(eng.Version())
	case *selftest:
		if err := runSelfTest(eng, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "taa-hct-helper: selftest failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("SELFTEST PASS")
	case *serve:
		watchParentDeath()
		watchSignals()
		out := bufio.NewWriterSize(os.Stdout, 64<<10)
		srv := newServer(eng, func(h hctproto.Header, payload []byte) error {
			if err := hctproto.WriteFrame(out, h, payload); err != nil {
				return err
			}
			return out.Flush()
		})
		err := srv.serve(os.Stdin)
		srv.freeStreams()
		if err != nil && !isClosedPipe(err) {
			fmt.Fprintf(os.Stderr, "taa-hct-helper: serve: %v\n", err)
			os.Exit(1)
		}
	}
}

func isClosedPipe(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EPIPE)
}

// watchParentDeath exits when TAA closes the other end of fd 3. That fd is
// inherited through the explicit dynamic loader, so it also works when the
// helper is launched as `ld-linux ... taa-hct-helper --serve`.
func watchParentDeath() {
	f := os.NewFile(3, "parent-death")
	if f == nil {
		return
	}
	fi, err := f.Stat()
	if err != nil {
		return // fd 3 is not open (manual run)
	}
	// TAA always hands us a pipe. Require one explicitly: initialising the CCP
	// backend can leave an unrelated fd open, and watching that would make the
	// helper exit as soon as the descriptor reads EOF.
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return
	}
	go func() {
		var b [1]byte
		_, _ = f.Read(b[:])
		os.Exit(0)
	}()
}

func watchSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		os.Exit(0)
	}()
}
