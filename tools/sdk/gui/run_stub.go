//go:build !windows

package main

import "fmt"

func run() {
	fmt.Println(`teecrypto 图形界面仅支持 Windows。请使用: CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui" -o teecrypto-gui.exe ./cmd/teecrypto-gui`)
}
