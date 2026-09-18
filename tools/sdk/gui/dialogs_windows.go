//go:build windows

package main

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	comdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
	procGetSaveFileNameW = comdlg32.NewProc("GetSaveFileNameW")

	procSHBrowseForFolderW   = shell32.NewProc("SHBrowseForFolderW")
	procSHGetPathFromIDListW = shell32.NewProc("SHGetPathFromIDListW")
)

const (
	ofnHideReadOnly    = 0x00000004
	ofnOverwritePrompt = 0x00000002
	ofnFileMustExist   = 0x00001000
	ofnPathMustExist   = 0x00000800

	bifReturnOnlyFSDirs = 0x00000001
	bifEditBox          = 0x00000010
)

type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

type browseInfo struct {
	hwndOwner      uintptr
	pidlRoot       uintptr
	pszDisplayName *uint16
	lpszTitle      *uint16
	ulFlags        uint32
	lpfn           uintptr
	lParam         uintptr
	iImage         int32
}

func utf16Ptr(value string) *uint16 {
	ptr, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		ptr, _ = syscall.UTF16PtrFromString(strings.ReplaceAll(value, "\x00", ""))
	}
	return ptr
}

func openFileDlg(owner uintptr, title, filter string) string {
	buf := make([]uint16, 2048)
	ofn := openFileName{
		lStructSize: uint32(unsafe.Sizeof(openFileName{})),
		hwndOwner:   owner,
		lpstrFilter: utf16Ptr(filter),
		lpstrFile:   &buf[0],
		nMaxFile:    uint32(len(buf)),
		flags:       ofnFileMustExist | ofnPathMustExist | ofnHideReadOnly,
		lpstrTitle:  utf16Ptr(title),
	}
	ret, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func saveFileDlg(owner uintptr, title, filter, defaultName string, forceEncExtension bool) string {
	buf := make([]uint16, 2048)
	if defaultName != "" {
		copy(buf, syscall.StringToUTF16(defaultName))
	}
	ofn := openFileName{
		lStructSize: uint32(unsafe.Sizeof(openFileName{})),
		hwndOwner:   owner,
		lpstrFilter: utf16Ptr(filter),
		lpstrFile:   &buf[0],
		nMaxFile:    uint32(len(buf)),
		flags:       ofnOverwritePrompt | ofnPathMustExist | ofnHideReadOnly,
		lpstrTitle:  utf16Ptr(title),
	}
	ret, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return ""
	}
	path := syscall.UTF16ToString(buf)
	if forceEncExtension && !strings.HasSuffix(strings.ToLower(path), ".enc") {
		path += ".enc"
	}
	return path
}

func openFolderDlg(owner uintptr, title string) string {
	bi := browseInfo{
		hwndOwner: owner,
		lpszTitle: utf16Ptr(title),
		ulFlags:   bifReturnOnlyFSDirs | bifEditBox,
	}

	pidl, _, _ := procSHBrowseForFolderW.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return ""
	}
	defer func() {
		// Free the PIDL
		ole32 := syscall.NewLazyDLL("ole32.dll")
		procCoTaskMemFree := ole32.NewProc("CoTaskMemFree")
		procCoTaskMemFree.Call(pidl)
	}()

	buf := make([]uint16, 260) // MAX_PATH
	ret, _, _ := procSHGetPathFromIDListW.Call(pidl, uintptr(unsafe.Pointer(&buf[0])))
	if ret == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}
