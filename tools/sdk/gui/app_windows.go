//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	windowTitle = "格物平台加密工具 v1.0"
	windowClass = "TeeCryptoWindow"

	swShow = 5

	csVRedraw = 0x0001
	csHRedraw = 0x0002

	colorWindow = 5

	wmCreate         = 0x0001
	wmDestroy        = 0x0002
	wmSize           = 0x0005
	wmPaint          = 0x000F
	wmCommand        = 0x0111
	wmCtlColorStatic = 0x0138
	wmCtlColorBtn    = 0x0135
	wmCtlColorEdit   = 0x0133
	wmCtlColorDlg    = 0x0134
	wmLButtonDown    = 0x0201
	wmLButtonUp      = 0x0202
	wmMouseMove      = 0x0200
	wmKeyDown        = 0x0100
	wmChar           = 0x0102
	wmTimer          = 0x0113
	wmSetCursor      = 0x0020
	wmGetMinMaxInfo  = 0x0024
	wmEraseBkgnd     = 0x0014
	wmMouseWheel     = 0x020A
	wmDrawItem       = 0x002B
	wmMouseLeave     = 0x02A3
	wmMouseHover     = 0x02A1
	wmDropFiles      = 0x0233
	wmNotify         = 0x004E

	// Edit control notifications
	enChange = 0x0300 // EN_CHANGE - text changed

	// Tab control messages
	tcmInsertItem = 0x1304
	tcmGetCurSel  = 0x130B
	tcmSetCurSel  = 0x130C
	tcnSelChange  = 0xFFFFFE02 // TCN_SELCHANGE notification

	// Button control messages
	bmGetCheck = 0x00F0

	// Window long offsets
	gwlUserData = -21 // GWLP_USERDATA (for 64-bit)

	wsExComposited = 0x02000000

	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsMaximizeBox  = 0x00010000
	wsThickFrame   = 0x00040000
	wsClipChildren = 0x02000000

	vkControl = 0x11
	vkEscape  = 0x1B

	// WM_NCHITTEST return values
	htClient = 1
)

const wsOverlappedWindow = wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsMaximizeBox | wsThickFrame | wsClipChildren

var (
	user32                     = syscall.NewLazyDLL("user32.dll")
	kernel32                   = syscall.NewLazyDLL("kernel32.dll")
	ole32                      = syscall.NewLazyDLL("ole32.dll")
	gdi32Main                  = syscall.NewLazyDLL("gdi32.dll")
	procRegisterClassW         = user32.NewProc("RegisterClassW")
	procCreateWindowExW        = user32.NewProc("CreateWindowExW")
	procDefWindowProcW         = user32.NewProc("DefWindowProcW")
	procShowWindow             = user32.NewProc("ShowWindow")
	procUpdateWindow           = user32.NewProc("UpdateWindow")
	procGetMessageW            = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessageW       = user32.NewProc("DispatchMessageW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procGetClientRect          = user32.NewProc("GetClientRect")
	procGetWindowRect          = user32.NewProc("GetWindowRect")
	procScreenToClient         = user32.NewProc("ScreenToClient")
	procClientToScreen         = user32.NewProc("ClientToScreen")
	procWindowFromPoint        = user32.NewProc("WindowFromPoint")
	procChildWindowFromPoint   = user32.NewProc("ChildWindowFromPoint")
	procChildWindowFromPointEx = user32.NewProc("ChildWindowFromPointEx")
	procMapWindowPoints        = user32.NewProc("MapWindowPoints")
	procTrackMouseEvent        = user32.NewProc("TrackMouseEvent")
	procSetProcessDPIAware     = user32.NewProc("SetProcessDPIAware")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procMessageBoxW            = user32.NewProc("MessageBoxW")
	procGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
	procCoInitializeEx         = ole32.NewProc("CoInitializeEx")
	procSetTimer               = user32.NewProc("SetTimer")
	procKillTimer              = user32.NewProc("KillTimer")
	procGetKeyState            = user32.NewProc("GetKeyState")
	procBeginPaint             = user32.NewProc("BeginPaint")
	procEndPaint               = user32.NewProc("EndPaint")
	procValidateRect           = user32.NewProc("ValidateRect")
	procSetBkColor             = gdi32Main.NewProc("SetBkColor")
	procSetTextColor           = gdi32Main.NewProc("SetTextColor")
	procSetBkMode              = gdi32Main.NewProc("SetBkMode")
	procCreateSolidBrush       = gdi32Main.NewProc("CreateSolidBrush")
	procGetSysColorBrush       = user32.NewProc("GetSysColorBrush")
	procGetStockObject         = gdi32Main.NewProc("GetStockObject")
	procFillRect               = user32.NewProc("FillRect")
	procGetTextExtentPoint32W  = gdi32Main.NewProc("GetTextExtentPoint32W")
	procTextOutW               = gdi32Main.NewProc("TextOutW")
	procSetWindowLongPtr       = user32.NewProc("SetWindowLongPtrW")
	procGetWindowLongPtr       = user32.NewProc("GetWindowLongPtrW")
	procGetFileAttributesW     = kernel32.NewProc("GetFileAttributesW")
	procGetParent              = user32.NewProc("GetParent")
	procCallWindowProc         = user32.NewProc("CallWindowProcW")

	// Progress bar
	procInitCommonControlsEx = user32.NewProc("InitCommonControlsEx")

	// Drag and drop
	procDragAcceptFiles = shell32.NewProc("DragAcceptFiles")
	procDragQueryFileW  = shell32.NewProc("DragQueryFileW")
	procDragFinish      = shell32.NewProc("DragFinish")
)

var (
	shell32 = syscall.NewLazyDLL("shell32.dll")
)

// Global white brush for label backgrounds
var whiteBrush uintptr

type paintStruct struct {
	hdc         uintptr
	fErase      int32
	rcPaint     rect
	fRestore    int32
	fIncUpdate  int32
	rgbReserved [32]byte
}

type point struct {
	x int32
	y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type rect struct {
	left   int32
	top    int32
	right  int32
	bottom int32
}

type minMaxInfo struct {
	ptReserved    point
	ptMaxSize     point
	ptMaxPosition point
	ptMinTrackSize point
	ptMaxTrackSize point
}

type wndClassEx struct {
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
}

// TCITEM structure for Tab Control
type tcItem struct {
	mask        uint32
	dwState     uint32
	dwStateMask uint32
	pszText     *uint16
	cchTextMax  int32
	iImage      int32
	lParam      uintptr
}

// app holds the application state
type app struct {
	hInstance  uintptr
	hwnd       uintptr
	encResult  *FileArtifact
	resultInfo string // File info text for result display

	// Native control handles
	hwndFileInput       uintptr
	hwndPublicKey       uintptr
	hwndPrivateKey      uintptr
	hwndBrowseBtn       uintptr
	hwndBrowseFolderBtn uintptr
	hwndEncryptBtn      uintptr
	hwndDecryptBtn   uintptr
	hwndSaveBtn      uintptr
	hwndFileIcon     uintptr
	hwndKeyPanel     uintptr
	hwndFilePanel    uintptr
	hwndStatusLabel  uintptr
	hwndImportPubBtn uintptr
	hwndImportPrvBtn uintptr
	hwndSavePubBtn   uintptr // Save public key
	hwndSavePrvBtn   uintptr // Save private key
	hwndGenKeyBtn    uintptr
	hwndKeyTitle     uintptr // "密钥管理" section title
	hwndFileTitle    uintptr // "加密管理" section title
	hwndSeparator    uintptr // Gray horizontal line between PEM and file sections
	hwndFileLabel    uintptr
	hwndPubLabel     uintptr
	hwndPrvLabel     uintptr
	hwndStatusMsg    uintptr
	hwndProgressBar  uintptr // Progress bar for operations

	// View switch buttons
	hwndEncryptViewBtn     uintptr // Switch to encrypt/decrypt view
	hwndAttestationViewBtn uintptr // Switch to attestation view
	currentView            int     // Current view (0=encrypt/decrypt, 1=attestation)

	// Attestation controls
	hwndAttestationPanel  uintptr // Panel for attestation controls
	hwndReportFileLabel   uintptr // Report file label
	hwndReportFileInput   uintptr // Report file path input
	hwndReportBrowseBtn   uintptr // Browse button for report file
	hwndVerifyChainCheck  uintptr // Checkbox for certificate chain verification
	hwndVerifyBtn         uintptr // Verify button
	hwndAttestationTable  uintptr // Attestation field table (ListView)

	// All controls are now native Win32
	cursorOn bool

	// Scaled fonts (recreated on resize)
	uiFont      uintptr // Microsoft YaHei UI for labels/buttons
	pemFont     uintptr // Consolas for PEM text/technical controls
	lastFontPx  int32   // last computed font pixel size (avoid redundant recreation)
}

var currentApp *app

func run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialize COM
	procCoInitializeEx.Call(0, 2) // COINIT_APARTMENTTHREADED

	// Enable DPI awareness
	procSetProcessDPIAware.Call()

	hInstance := getModuleHandle()
	a := &app{hInstance: hInstance}
	currentApp = a

	registerWindowClass(hInstance)
	a.hwnd = createMainWindow(hInstance)
	if a.hwnd == 0 {
		messageBox(0, "创建主窗口失败", "错误", 0x10)
		return
	}

	createWindowIcon(a.hwnd)
	procShowWindow.Call(a.hwnd, swShow)
	procUpdateWindow.Call(a.hwnd)
	messageLoop()
}

func registerWindowClass(hInstance uintptr) {
	className := utf16PtrStr(windowClass)
	// Create solid brush with VS Code light theme background (#F3F3F3)
	whiteBrush, _, _ = procCreateSolidBrush.Call(0x00FFFFFF) // 真正的白色
	wc := wndClassEx{
		// CS_HREDRAW|CS_VREDRAW removed: they force full-window repaint on every resize
		// pixel, causing heavy flicker. Child controls are repositioned by MoveWindow
		// (with bRepaint=TRUE) in layoutControls, so the parent doesn't need to redraw them.
		style:         0,
		lpfnWndProc:   syscall.NewCallback(windowProc),
		hInstance:     hInstance,
		hCursor:       loadCursor(),
		hbrBackground: whiteBrush,
		lpszClassName: className,
	}
	procRegisterClassW.Call(uintptr(unsafe.Pointer(&wc)))
}

func createMainWindow(hInstance uintptr) uintptr {
	className := utf16PtrStr(windowClass)
	title := utf16PtrStr(windowTitle)

	// Get primary monitor dimensions
	screenW, _, _ := procGetSystemMetrics.Call(0) // SM_CXSCREEN
	screenH, _, _ := procGetSystemMetrics.Call(1) // SM_CYSCREEN
	sw := int32(screenW)
	sh := int32(screenH)

	// Window size: width 40%, height 60% of screen, clamped to a usable minimum
	w := sw * 40 / 100
	h := sh * 60 / 100
	if w < 800 {
		w = 800
	}
	if h < 580 {
		h = 580
	}

	// Center on screen
	x := (sw - w) / 2
	y := (sh - h) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}

	hwnd, _, _ := procCreateWindowExW.Call(
		0, // No extended styles — WS_EX_COMPOSITED removed: it breaks WM_NCHITTEST on the sizing frame
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow, // includes WS_THICKFRAME for resizable border + WS_MAXIMIZEBOX
		uintptr(x), uintptr(y),
		uintptr(w), uintptr(h),
		0, 0, hInstance, 0,
	)
	return hwnd
}

func loadCursor() uintptr {
	h, _, _ := user32.NewProc("LoadCursorW").Call(0, 32512)
	return h
}

func getModuleHandle() uintptr {
	h, _, _ := procGetModuleHandleW.Call(0)
	return h
}

func messageBox(parent uintptr, text string, title string, flags uintptr) {
	procMessageBoxW.Call(parent, uintptr(unsafe.Pointer(utf16PtrStr(text))), uintptr(unsafe.Pointer(utf16PtrStr(title))), flags)
}

func utf16PtrStr(value string) *uint16 {
	ptr, _ := syscall.UTF16PtrFromString(value)
	return ptr
}

func messageLoop() {
	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func windowProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	a := currentApp

	switch message {
	case wmCreate:
		a.onCreate(hwnd)
		return 0

	case wmDestroy:
		a.onDestroy()
		procPostQuitMessage.Call(0)
		return 0

	case wmSize:
		a.onSize(hwnd)
		return 0

	case wmPaint:
		a.onPaint(hwnd)
		return 0

	case wmEraseBkgnd:
		// Explicitly fill the client area with white.
		// Returning 0 relies on the class brush fallback, which doesn't work
		// reliably with WS_EX_COMPOSITED (DWM composition buffer stays black).
		if whiteBrush != 0 {
			var r rect
			procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
			procFillRect.Call(wParam, uintptr(unsafe.Pointer(&r)), whiteBrush)
		}
		return 1

	case wmSetCursor:
		// Only override cursor in the client area.
		// For non-client area (sizing borders, caption, etc.), let DefWindowProc
		// set the appropriate system cursor (resize cursors on borders, etc.).
		hitTest := int32(lParam & 0xFFFF)
		if hitTest == htClient {
			setArrowCursor()
			return 1 // Handled
		}
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
		return ret

	case wmDropFiles:
		// Handle file drop
		a.onDropFiles(wParam)
		return 0

	case wmTimer:
		// Blink cursor
		a.cursorOn = !a.cursorOn
		return 0

	case wmCommand:
		// Handle native control notifications
		ctrlID := uint32(wParam & 0xFFFF)
		notification := uint32(wParam >> 16)
		ctrlHwnd := lParam
		a.onCommand(ctrlID, notification, ctrlHwnd)
		return 0

	case wmCtlColorStatic:
		// Set white background for static controls (labels)
		return handleCtlColorStatic(wParam)

	case wmCtlColorBtn:
		// Check if this is a GROUPBOX or a push button
		// GROUPBOX should have white background, push buttons should have gray
		ctrlHwnd := lParam
		style, _, _ := procGetWindowLongPtr.Call(ctrlHwnd, uintptr(uint64(0xFFFFFFFFFFFFFFF0))) // GWL_STYLE = -16
		// Button type is in the low 4 bits of style
		// BS_GROUPBOX = 0x07, BS_PUSHBUTTON = 0x00
		buttonType := style & 0x0F
		if buttonType == bsGroupBox {
			// GROUPBOX - white background
			return handleCtlColorStatic(wParam)
		} else {
			// Push button - gray background
			return handleCtlColor(wParam)
		}

	case wmCtlColorDlg:
		// Set light gray background for dialog controls
		return handleCtlColor(wParam)

	case wmCtlColorEdit:
		// Handle edit control colors (for validation feedback)
		// wParam = HDC, lParam = HWND
		return handleCtlColorEdit(lParam, wParam)

	case wmGetMinMaxInfo:
		// Enforce minimum window size so layout stays usable
		mmi := (*minMaxInfo)(unsafe.Pointer(lParam))
		mmi.ptMinTrackSize.x = 600
		mmi.ptMinTrackSize.y = 450
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return ret
}

func (a *app) onCreate(hwnd uintptr) {
	a.hwnd = hwnd // Set hwnd early so createControls can use it

	var r rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	w := r.right
	h := r.bottom

	// whiteBrush already created in registerWindowClass

	// Create UI controls
	a.createControls(w, h)

	// Set scaled fonts for all controls (also called on every resize)
	a.updateFonts(w)

	// Ensure all buttons are enabled and force redraw
	enableControl(a.hwndBrowseBtn, true)
	enableControl(a.hwndBrowseFolderBtn, true)
	enableControl(a.hwndEncryptBtn, true)
	enableControl(a.hwndDecryptBtn, true)
	enableControl(a.hwndImportPubBtn, true)
	enableControl(a.hwndImportPrvBtn, true)
	enableControl(a.hwndGenKeyBtn, true)
	enableControl(a.hwndSaveBtn, true)

	// Force redraw of all buttons to trigger WM_DRAWITEM
	procInvalidateRect.Call(a.hwndBrowseBtn, 0, 1)
	procInvalidateRect.Call(a.hwndBrowseFolderBtn, 0, 1)
	procInvalidateRect.Call(a.hwndEncryptBtn, 0, 1)
	procInvalidateRect.Call(a.hwndDecryptBtn, 0, 1)
	procInvalidateRect.Call(a.hwndImportPubBtn, 0, 1)
	procInvalidateRect.Call(a.hwndImportPrvBtn, 0, 1)
	procInvalidateRect.Call(a.hwndGenKeyBtn, 0, 1)
	procInvalidateRect.Call(a.hwndSaveBtn, 0, 1)

	// Register window to accept dropped files
	procDragAcceptFiles.Call(hwnd, 1)

	// Set up timer for cursor blink (500ms)
	procSetTimer.Call(hwnd, 1, 500, 0)
}

// handleCtlColor sets VS Code light theme colors for button and dialog controls
func handleCtlColor(hdc uintptr) uintptr {
	// VS Code light theme colors (BGR format for Win32)
	// Background: #F3F3F3 -> BGR: 0x00F3F3F3
	// Text: #1E1E1E -> BGR: 0x001E1E1E
	procSetBkColor.Call(hdc, 0x00F3F3F3)   // Light gray background
	procSetTextColor.Call(hdc, 0x001E1E1E) // Near black text
	if whiteBrush != 0 {
		return whiteBrush
	}
	return 0
}

// handleCtlColorStatic sets white background for static controls (labels)
func handleCtlColorStatic(hdc uintptr) uintptr {
	// White background for labels to match window background
	// Background: #FFFFFF -> BGR: 0x00FFFFFF
	// Text: #1E1E1E -> BGR: 0x001E1E1E
	procSetBkColor.Call(hdc, 0x00FFFFFF)   // White background
	procSetTextColor.Call(hdc, 0x001E1E1E) // Near black text
	if whiteBrush != 0 {
		return whiteBrush
	}
	return 0
}

// updateFonts recreates fonts scaled to current window width and reassigns them to all controls.
func (a *app) updateFonts(w int32) {
	// Scale relative to 800px base width; clamp to a readable minimum.
	fontPx := int32(-13 * w / 800)
	if fontPx > -8 {
		fontPx = -8
	}
	if fontPx == a.lastFontPx {
		return // No change, skip recreation
	}
	a.lastFontPx = fontPx

	// Destroy old fonts
	if a.uiFont != 0 {
		procDeleteObject.Call(a.uiFont)
	}
	if a.pemFont != 0 {
		procDeleteObject.Call(a.pemFont)
	}

	a.uiFont = createControlFont(fontPx, "Microsoft YaHei UI")
	a.pemFont = createControlFont(fontPx, "Consolas")

	// UI font → labels & buttons
	if a.uiFont != 0 {
		for _, h := range []uintptr{
			a.hwndPubLabel, a.hwndPrvLabel, a.hwndStatusLabel,
			a.hwndBrowseBtn, a.hwndBrowseFolderBtn,
			a.hwndEncryptBtn, a.hwndDecryptBtn,
			a.hwndImportPubBtn, a.hwndImportPrvBtn,
			a.hwndSavePubBtn, a.hwndSavePrvBtn,
			a.hwndKeyTitle, a.hwndFileTitle,
			a.hwndGenKeyBtn, a.hwndSaveBtn,
		} {
			setControlFont(h, a.uiFont, true)
		}
	}

	// PEM font → text boxes, tab buttons, attestation controls
	if a.pemFont != 0 {
		for _, h := range []uintptr{
			a.hwndPublicKey, a.hwndPrivateKey,
			a.hwndEncryptViewBtn, a.hwndAttestationViewBtn,
			a.hwndReportFileLabel, a.hwndReportFileInput,
			a.hwndReportBrowseBtn, a.hwndVerifyChainCheck,
			a.hwndVerifyBtn, a.hwndAttestationTable,
		} {
			setControlFont(h, a.pemFont, true)
		}
	}
}

func (a *app) onDestroy() {
	// Cleanup solid brush
	if whiteBrush != 0 {
		procDeleteObject.Call(whiteBrush)
		whiteBrush = 0
	}
	// Cleanup scaled fonts
	if a.uiFont != 0 {
		procDeleteObject.Call(a.uiFont)
		a.uiFont = 0
	}
	if a.pemFont != 0 {
		procDeleteObject.Call(a.pemFont)
		a.pemFont = 0
	}
}

func (a *app) onSize(hwnd uintptr) {
	var r rect
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	w := r.right
	h := r.bottom
	if w > 0 && h > 0 {
		a.layoutControls(w, h)
	}
}

func (a *app) createControls(w, h int32) {
	// Create Tab Control first
	a.createTabControl(w, h)

	// Controls will be created in layoutControls after we know the positions
	a.layoutControls(w, h)

	// Force initial repaint of all controls
	if a.hwnd != 0 {
		procInvalidateRect.Call(a.hwnd, 0, 1)
		procUpdateWindow.Call(a.hwnd)
	}
}

// createTabControl creates the view switch buttons (called once)
func (a *app) createTabControl(w, h int32) {
	if a.hwndEncryptViewBtn != 0 {
		return // Already created
	}

	btnH := int32(32)
	gap := int32(8)
	topY := int32(8)
	pad := int32(16)
	btnW := (w - pad*2 - gap) / 2

	a.hwndEncryptViewBtn = createNativeButton(a.hwnd, "🔐 加密/解密", pad, topY, btnW, btnH)
	a.hwndAttestationViewBtn = createNativeButton(a.hwnd, "🛡️ 远程报告验证", pad+btnW+gap, topY, btnW, btnH)

	a.currentView = 0
}

// layoutTabControl repositions the view switch buttons to match current window size
func (a *app) layoutTabControl(w int32) {
	if a.hwndEncryptViewBtn == 0 {
		return
	}
	btnH := int32(32)
	gap := int32(8)
	topY := int32(8)
	pad := int32(16)
	btnW := (w - pad*2 - gap) / 2

	procMoveWindow.Call(a.hwndEncryptViewBtn, uintptr(pad), uintptr(topY), uintptr(btnW), uintptr(btnH), 1)
	procMoveWindow.Call(a.hwndAttestationViewBtn, uintptr(pad+btnW+gap), uintptr(topY), uintptr(btnW), uintptr(btnH), 1)
}

// layoutSizes holds the fixed pixel values shared by all layout calculations.
type layoutSizes struct {
	pad, cardPad, gap, topPad, bottomPad int32
	btnH, statusH, progressH, sectionGap int32
}

func defaultLayoutSizes(w, h int32) layoutSizes {
	return layoutSizes{
		pad:        16,
		cardPad:    16,
		gap:        8,
		topPad:     48,
		bottomPad:  6,
		btnH:       int32(float32(h) * 0.06),
		statusH:    32,
		progressH:  8,
		sectionGap: 10,
	}
}

// fileSectionH returns the height of the file section (2 button rows + 1 gap).
func (s layoutSizes) fileSectionH() int32 {
	return s.btnH*2 + s.gap
}

// unifiedSectionH computes the height for the merged key+file section (single card).
func (s layoutSizes) unifiedSectionH(windowH int32) int32 {
	available := windowH - (s.topPad + s.progressH + 2 + s.statusH + s.bottomPad)
	// Minimum: label + 5 buttons + gaps + tight separator + file rows
	minH := s.btnH + s.gap + s.btnH*5 + s.gap*4 + s.gap/2 + 2 + s.gap/2 + s.fileSectionH()
	if available < minH {
		return minH
	}
	return available
}

// createAttestationControls creates the attestation verification controls (called once)
func (a *app) createAttestationControls(w, h, pad, gap, topPad, btnH, labelW int32) {
	if a.hwndReportFileInput != 0 {
		return // Already created
	}

	s := defaultLayoutSizes(w, h)
	sectionH := s.unifiedSectionH(h)
	cardPad := s.cardPad
	attestationH := sectionH
	y := topPad

	if a.hwndAttestationPanel == 0 {
		a.hwndAttestationPanel = createNativePanel(a.hwnd, pad, y, w-pad*2, attestationH)
	}

	browseBtnW := int32(80)
	reportLabelW := int32(70)
	labelYOffset := int32(3)
	innerY := gap * 2

	a.hwndReportFileInput = createNativeEdit(a.hwndAttestationPanel, "", cardPad+reportLabelW+gap, innerY, w-pad*2-cardPad*2-reportLabelW-gap-browseBtnW-gap, btnH, false)
	a.hwndReportBrowseBtn = createNativeButton(a.hwndAttestationPanel, "浏览", w-pad*2-cardPad-browseBtnW, innerY, browseBtnW, btnH)
	a.hwndReportFileLabel = createNativeLabel(a.hwndAttestationPanel, "报告文件", cardPad, innerY+labelYOffset, reportLabelW, btnH-labelYOffset)
	innerY += btnH + gap

	a.hwndVerifyChainCheck = createNativeCheckbox(a.hwndAttestationPanel, "验证证书链（联网获取证书）", cardPad, innerY, w-pad*2-cardPad*2, btnH)
	innerY += btnH + gap

	verifyBtnW := w - pad*2 - cardPad*2
	a.hwndVerifyBtn = createNativeButton(a.hwndAttestationPanel, "🛡️ 开始验证", cardPad, innerY, verifyBtnW, btnH)
	innerY += btnH + gap

	resultH := attestationH - innerY - gap*2
	listViewWidth := w - pad*2 - cardPad*2
	a.hwndAttestationTable = createNativeListView(a.hwndAttestationPanel, cardPad, innerY, listViewWidth, resultH)
	if a.hwndAttestationTable != 0 {
		col1Width := int32(200)
		col2Width := listViewWidth - col1Width - 4
		if col2Width < 300 {
			col2Width = 300
		}
		listViewInsertColumn(a.hwndAttestationTable, 0, "字段", col1Width)
		listViewInsertColumn(a.hwndAttestationTable, 1, "值", col2Width)
		verifyChain := false
		if a.hwndVerifyChainCheck != 0 {
			checked, _, _ := procSendMessageW.Call(a.hwndVerifyChainCheck, bmGetCheck, 0, 0)
			verifyChain = checked == 1
		}
		rows := buildAttestationFieldRows("", verifyChain, nil)
		populateAttestationTable(a.hwndAttestationTable, rows)
		log("ListView created: width=%d, col1=%d, col2=%d, rows=%d", listViewWidth, col1Width, col2Width, len(rows))
	} else {
		log("Failed to create ListView")
	}

	a.showAttestationControls(false)
}

// layoutAttestationControls repositions attestation controls to match current window size
func (a *app) layoutAttestationControls(w, h, pad, gap, topPad, btnH int32) {
	if a.hwndAttestationPanel == 0 || a.hwndReportFileInput == 0 {
		return
	}

	s := defaultLayoutSizes(w, h)
	sectionH := s.unifiedSectionH(h)
	cardPad := s.cardPad
	attestationH := sectionH

	// Reposition panel
	procMoveWindow.Call(a.hwndAttestationPanel, uintptr(pad), uintptr(topPad), uintptr(w-pad*2), uintptr(attestationH), 1)

	// Reposition inner controls
	browseBtnW := int32(80)
	reportLabelW := int32(70)
	labelYOffset := int32(3)
	panelInnerW := w - pad*2 - cardPad*2
	innerY := gap * 2

	procMoveWindow.Call(a.hwndReportFileInput, uintptr(cardPad+reportLabelW+gap), uintptr(innerY), uintptr(panelInnerW-reportLabelW-gap-browseBtnW-gap), uintptr(btnH), 1)
	procMoveWindow.Call(a.hwndReportBrowseBtn, uintptr(w-pad*2-cardPad-browseBtnW), uintptr(innerY), uintptr(browseBtnW), uintptr(btnH), 1)
	procMoveWindow.Call(a.hwndReportFileLabel, uintptr(cardPad), uintptr(innerY+labelYOffset), uintptr(reportLabelW), uintptr(btnH-labelYOffset), 1)
	innerY += btnH + gap

	procMoveWindow.Call(a.hwndVerifyChainCheck, uintptr(cardPad), uintptr(innerY), uintptr(panelInnerW), uintptr(btnH), 1)
	innerY += btnH + gap

	verifyBtnW := panelInnerW
	procMoveWindow.Call(a.hwndVerifyBtn, uintptr(cardPad), uintptr(innerY), uintptr(verifyBtnW), uintptr(btnH), 1)
	innerY += btnH + gap

	resultH := attestationH - innerY - gap*2
	listViewWidth := panelInnerW
	procMoveWindow.Call(a.hwndAttestationTable, uintptr(cardPad), uintptr(innerY), uintptr(listViewWidth), uintptr(resultH), 1)

	// Resize ListView columns proportionally
	if a.hwndAttestationTable != 0 {
		col1Width := int32(200)
		col2Width := listViewWidth - col1Width - 4
		if col2Width < 100 {
			col2Width = 100
		}
		procSendMessageW.Call(a.hwndAttestationTable, 0x101E, 1, uintptr(col2Width)) // LVM_SETCOLUMNWIDTH
	}
}

func (a *app) layoutControls(w, h int32) {
	// Scale fonts to match current window width (no-op if size unchanged)
	a.updateFonts(w)

	s := defaultLayoutSizes(w, h)
	pad := s.pad
	cardPad := s.cardPad
	gap := s.gap
	topPad := s.topPad
	bottomPad := s.bottomPad
	btnH := s.btnH

	// Adaptive component sizes (based on window dimensions)
	btnW := int32(float32(w) * 0.12)   // 12% of window width
	labelW := int32(float32(w) * 0.15) // 15% of window width
	// actionW is calculated locally in the file section below
	saveBtnW := int32(float32(w) * 0.15) // 15% of window width

	// Reposition tab buttons to fill current width
	a.layoutTabControl(w)

	// Create attestation controls (once), then reposition to current size
	a.createAttestationControls(w, h, pad, gap, topPad, btnH, labelW)
	a.layoutAttestationControls(w, h, pad, gap, topPad, btnH)

	// Status message - position from bottom
	statusY := h - bottomPad - s.statusH
	if a.hwndStatusLabel == 0 {
		a.hwndStatusLabel = createNativeLabel(a.hwnd, "", pad, statusY, w-pad-saveBtnW-gap*2, s.statusH)
	} else {
		procMoveWindow.Call(a.hwndStatusLabel, uintptr(pad), uintptr(statusY), uintptr(w-pad-saveBtnW-gap*2), uintptr(s.statusH), 1)
	}

	// Save button - on the right side of status bar (initially hidden)
	if a.hwndSaveBtn == 0 {
		a.hwndSaveBtn = createNativeButton(a.hwnd, "💾 保存文件", w-pad-saveBtnW, statusY, saveBtnW, s.statusH)
		procShowWindow.Call(a.hwndSaveBtn, 0) // SW_HIDE = 0
	} else {
		procMoveWindow.Call(a.hwndSaveBtn, uintptr(w-pad-saveBtnW), uintptr(statusY), uintptr(saveBtnW), uintptr(s.statusH), 1)
	}

	// Progress bar - above status label
	progressY := statusY - s.progressH - 2
	if a.hwndProgressBar == 0 {
		a.hwndProgressBar = createNativeProgressBar(a.hwnd, pad, progressY, w-pad*2, s.progressH)
	} else {
		procMoveWindow.Call(a.hwndProgressBar, uintptr(pad), uintptr(progressY), uintptr(w-pad*2), uintptr(s.progressH), 1)
	}

	// ── Unified section (key management + file operations in one card) ──
	sectionH := s.unifiedSectionH(h)
	y := topPad

	// Create single panel for the entire section
	if a.hwndKeyPanel == 0 {
		a.hwndKeyPanel = createNativePanel(a.hwnd, pad, y, w-pad*2, sectionH)
	} else {
		procMoveWindow.Call(a.hwndKeyPanel, uintptr(pad), uintptr(y), uintptr(w-pad*2), uintptr(sectionH), 1)
	}

	keyInnerTop := gap * 2 // Relative to panel
	innerW := w - pad*2 - cardPad*2

	// 4-column layout: 密钥管理 | 公钥PEM | 私钥PEM | 按钮区
	titleW := int32(24)
	btnColW := innerW * 18 / 100
	remainingW := innerW - titleW - gap - btnColW - gap
	pemW := (remainingW - gap) / 2

	// Vertical positions (relative to panel)
	labelY := keyInnerTop
	inputY := labelY + btnH + gap
	btnStartY := inputY

	// PEM input height: exactly match 5 stacked buttons + 4 gaps (never expands)
	inputH := btnH*5 + gap*4

	// Separator and file section positions (relative to panel)
	sepY := inputY + inputH + gap/2
	fileY := sepY + 2 + gap/2 // 2px separator height + tight gap
	fileRow2Y := fileY + btnH + gap

	labelOffset := int32(4)
	// Vertical centering heights for labels within their respective areas
	keyAreaH := sepY - keyInnerTop    // key area: from keyInnerTop to separator
	fileAreaH := s.fileSectionH() + s.gap // file area: fixed to content + bottom padding

	if a.hwndPubLabel == 0 {
		// 密钥管理 vertical label (centered in key area)
		a.hwndKeyTitle = createNativeVerticalLabel(a.hwndKeyPanel, "密钥管理", cardPad, keyInnerTop, titleW, keyAreaH)

		// 公钥 PEM
		pubX := cardPad + titleW + gap
		a.hwndPubLabel = createNativeLabel(a.hwndKeyPanel, "🔑 公钥 PEM", pubX+labelOffset, labelY, pemW, btnH)
		a.hwndPublicKey = createNativeEdit(a.hwndKeyPanel, "", pubX, inputY, pemW, inputH, true)

		// 私钥 PEM
		prvX := pubX + pemW + gap
		a.hwndPrvLabel = createNativeLabel(a.hwndKeyPanel, "🔐 私钥 PEM", prvX+labelOffset, labelY, pemW, btnH)
		a.hwndPrivateKey = createNativeEdit(a.hwndKeyPanel, "", prvX, inputY, pemW, inputH, true)

		// 按钮区
		btnX := prvX + pemW + gap
		a.hwndGenKeyBtn = createNativeButton(a.hwndKeyPanel, "⚙️ 生成密钥", btnX, btnStartY, btnColW, btnH)
		a.hwndSavePubBtn = createNativeButton(a.hwndKeyPanel, "💾 保存公钥", btnX, btnStartY+(btnH+gap)*1, btnColW, btnH)
		a.hwndSavePrvBtn = createNativeButton(a.hwndKeyPanel, "💾 保存私钥", btnX, btnStartY+(btnH+gap)*2, btnColW, btnH)
		a.hwndImportPubBtn = createNativeButton(a.hwndKeyPanel, "🔑 导入公钥", btnX, btnStartY+(btnH+gap)*3, btnColW, btnH)
		a.hwndImportPrvBtn = createNativeButton(a.hwndKeyPanel, "🔐 导入私钥", btnX, btnStartY+(btnH+gap)*4, btnColW, btnH)

		// Gray separator line
		a.hwndSeparator = createNativeSeparator(a.hwndKeyPanel, cardPad, sepY, innerW)

		// 加密管理 vertical label (centered in file area)
		a.hwndFileTitle = createNativeVerticalLabel(a.hwndKeyPanel, "加密管理", cardPad, fileY, titleW, fileAreaH)

		// File section: left = file input (spans 2 rows), right = 2x2 button grid
		fileContentX := cardPad + titleW + gap
		buttonGap := int32(8)
		fileInputW := innerW - titleW - gap - cardPad - btnW*2 - buttonGap
		fileInputH := btnH*2 + gap // span both rows
		a.hwndFileInput = createNativeEdit(a.hwndKeyPanel, "", fileContentX, fileY, fileInputW, fileInputH, false)
		// Top-right: 选择文件, 加密
		a.hwndBrowseBtn = createNativeButton(a.hwndKeyPanel, "📄 选择文件", fileContentX+fileInputW+buttonGap, fileY, btnW, btnH)
		a.hwndEncryptBtn = createNativeButton(a.hwndKeyPanel, "🔒 加密", fileContentX+fileInputW+buttonGap+btnW, fileY, btnW, btnH)
		// Bottom-right: 选择文件夹, 解密
		a.hwndBrowseFolderBtn = createNativeButton(a.hwndKeyPanel, "📁 选择文件夹", fileContentX+fileInputW+buttonGap, fileRow2Y, btnW, btnH)
		a.hwndDecryptBtn = createNativeButton(a.hwndKeyPanel, "🔓 解密", fileContentX+fileInputW+buttonGap+btnW, fileRow2Y, btnW, btnH)
	} else {
		pubX := cardPad + titleW + gap
		prvX := pubX + pemW + gap
		btnX := prvX + pemW + gap

		procMoveWindow.Call(a.hwndKeyTitle, uintptr(cardPad), uintptr(keyInnerTop), uintptr(titleW), uintptr(keyAreaH), 1)
		procMoveWindow.Call(a.hwndPubLabel, uintptr(pubX+labelOffset), uintptr(labelY), uintptr(pemW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndPublicKey, uintptr(pubX), uintptr(inputY), uintptr(pemW), uintptr(inputH), 1)
		procMoveWindow.Call(a.hwndPrvLabel, uintptr(prvX+labelOffset), uintptr(labelY), uintptr(pemW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndPrivateKey, uintptr(prvX), uintptr(inputY), uintptr(pemW), uintptr(inputH), 1)
		procMoveWindow.Call(a.hwndGenKeyBtn, uintptr(btnX), uintptr(btnStartY), uintptr(btnColW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndSavePubBtn, uintptr(btnX), uintptr(btnStartY+(btnH+gap)*1), uintptr(btnColW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndSavePrvBtn, uintptr(btnX), uintptr(btnStartY+(btnH+gap)*2), uintptr(btnColW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndImportPubBtn, uintptr(btnX), uintptr(btnStartY+(btnH+gap)*3), uintptr(btnColW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndImportPrvBtn, uintptr(btnX), uintptr(btnStartY+(btnH+gap)*4), uintptr(btnColW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndSeparator, uintptr(cardPad), uintptr(sepY), uintptr(innerW), 2, 1)

		// 加密管理 vertical label
		procMoveWindow.Call(a.hwndFileTitle, uintptr(cardPad), uintptr(fileY), uintptr(titleW), uintptr(fileAreaH), 1)

		// File section: left = file input (spans 2 rows), right = 2x2 button grid
		fileContentX := cardPad + titleW + gap
		buttonGap := int32(8)
		fileInputW := innerW - titleW - gap - cardPad - btnW*2 - buttonGap
		fileInputH := btnH*2 + gap
		procMoveWindow.Call(a.hwndFileInput, uintptr(fileContentX), uintptr(fileY), uintptr(fileInputW), uintptr(fileInputH), 1)
		procMoveWindow.Call(a.hwndBrowseBtn, uintptr(fileContentX+fileInputW+buttonGap), uintptr(fileY), uintptr(btnW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndEncryptBtn, uintptr(fileContentX+fileInputW+buttonGap+btnW), uintptr(fileY), uintptr(btnW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndBrowseFolderBtn, uintptr(fileContentX+fileInputW+buttonGap), uintptr(fileRow2Y), uintptr(btnW), uintptr(btnH), 1)
		procMoveWindow.Call(a.hwndDecryptBtn, uintptr(fileContentX+fileInputW+buttonGap+btnW), uintptr(fileRow2Y), uintptr(btnW), uintptr(btnH), 1)
	}
}

func (a *app) onPaint(hwnd uintptr) {
	// Must call BeginPaint/EndPaint to validate the paint region
	// Otherwise the window will keep receiving WM_PAINT messages
	var ps paintStruct
	procBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
	procEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
}


// onDropFiles handles files dropped onto the window
func (a *app) onDropFiles(hDrop uintptr) {
	// Get the number of dropped files
	fileCount, _, _ := procDragQueryFileW.Call(hDrop, 0xFFFFFFFF, 0, 0)

	if fileCount > 0 {
		// Get the first file path
		buf := make([]uint16, 260) // MAX_PATH
		procDragQueryFileW.Call(hDrop, 0, uintptr(unsafe.Pointer(&buf[0])), 260)
		filePath := syscall.UTF16ToString(buf)

		// Set the file path to the input field
		setEditText(a.hwndFileInput, filePath)

		// Visual feedback: briefly highlight the file input field
		a.highlightControl(a.hwndFileInput, 0x00FF00, 500) // Green highlight for 500ms
	}

	// Finish the drag operation
	procDragFinish.Call(hDrop)
}

// highlightControl briefly highlights a control with a color
func (a *app) highlightControl(hwnd uintptr, color uint32, durationMs int) {
	if hwnd == 0 {
		return
	}

	// Store original color
	origColor, _, _ := procGetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)))

	// Set highlight color
	procSetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)), uintptr(color))
	procInvalidateRect.Call(hwnd, 0, 1)

	// Schedule restoration after duration
	// Use a simple approach: restore immediately for now
	// In a full implementation, we'd use a timer
	procSetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)), origColor)
	procInvalidateRect.Call(hwnd, 0, 1)
}

// shakeControl creates a shake animation for error feedback
func (a *app) shakeControl(hwnd uintptr) {
	if hwnd == 0 {
		return
	}

	// Get current position
	var rc rect
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))

	// Convert to client coordinates
	var pt point
	pt.x = rc.left
	pt.y = rc.top
	procScreenToClient.Call(a.hwnd, uintptr(unsafe.Pointer(&pt)))

	origX := pt.x
	origY := pt.y

	// Shake parameters
	shakeOffset := int32(5)
	shakeCount := 3

	// Perform shake animation
	for i := 0; i < shakeCount; i++ {
		// Move right
		procMoveWindow.Call(hwnd, uintptr(origX+shakeOffset), uintptr(origY), uintptr(rc.right-rc.left), uintptr(rc.bottom-rc.top), 1)

		// Move left
		procMoveWindow.Call(hwnd, uintptr(origX-shakeOffset), uintptr(origY), uintptr(rc.right-rc.left), uintptr(rc.bottom-rc.top), 1)

		// Back to center
		procMoveWindow.Call(hwnd, uintptr(origX), uintptr(origY), uintptr(rc.right-rc.left), uintptr(rc.bottom-rc.top), 1)
	}
}

// pulseControl creates a pulse animation for success feedback
func (a *app) pulseControl(hwnd uintptr, color uint32) {
	if hwnd == 0 {
		return
	}

	// Simple pulse: set color then restore
	procSetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)), uintptr(color))
	procInvalidateRect.Call(hwnd, 0, 1)
	procUpdateWindow.Call(hwnd)

	// Restore to default after brief delay
	// In a full implementation, we'd use a timer for smooth animation
	procSetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)), 0)
	procInvalidateRect.Call(hwnd, 0, 1)
}

// onDrawItem handles WM_DRAWITEM for owner-draw buttons
func (a *app) onDrawItem(lParam uintptr) uintptr {
	return 0 // Not used with native buttons
}

// === Event handlers ===

func (a *app) onBrowse() {
	path := openFileDlg(a.hwnd, "选择文件", "所有文件 (*.*)\x00*.*\x00\x00")
	if path != "" {
		setEditText(a.hwndFileInput, path)
	}
	// Force redraw of file panel and its children after file dialog closes
	if a.hwndKeyPanel != 0 {
		procRedrawWindow.Call(a.hwndKeyPanel, 0, 0, 0x0247) // RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE | RDW_ALLCHILDREN
	}
	if a.hwndFileInput != 0 {
		procRedrawWindow.Call(a.hwndFileInput, 0, 0, 0x0247)
	}
	// Force redraw of PEM text boxes
	if a.hwndPublicKey != 0 {
		procRedrawWindow.Call(a.hwndPublicKey, 0, 0, 0x0247)
	}
	if a.hwndPrivateKey != 0 {
		procRedrawWindow.Call(a.hwndPrivateKey, 0, 0, 0x0247)
	}
}

func (a *app) onBrowseFolder() {
	path := openFolderDlg(a.hwnd, "选择文件夹")
	if path != "" {
		setEditText(a.hwndFileInput, path)
	}
	// Force redraw of file panel and its children after folder dialog closes
	if a.hwndKeyPanel != 0 {
		procRedrawWindow.Call(a.hwndKeyPanel, 0, 0, 0x0247) // RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE | RDW_ALLCHILDREN
	}
	if a.hwndFileInput != 0 {
		procRedrawWindow.Call(a.hwndFileInput, 0, 0, 0x0247)
	}
	// Force redraw of PEM text boxes
	if a.hwndPublicKey != 0 {
		procRedrawWindow.Call(a.hwndPublicKey, 0, 0, 0x0247)
	}
	if a.hwndPrivateKey != 0 {
		procRedrawWindow.Call(a.hwndPrivateKey, 0, 0, 0x0247)
	}
}

func (a *app) onImportPub() {
	path := openFileDlg(a.hwnd, "导入公钥文件", "PEM 文件 (*.pem;*.key)\x00*.pem;*.key\x00所有文件 (*.*)\x00*.*\x00\x00")
	if path != "" {
		content, err := readPEMFile(path)
		if err != nil {
			a.showError(err.Error())
		} else {
			setEditText(a.hwndPublicKey, content)
		}
	}
}

func (a *app) onImportPrv() {
	path := openFileDlg(a.hwnd, "导入私钥文件", "PEM 文件 (*.pem;*.key)\x00*.pem;*.key\x00所有文件 (*.*)\x00*.*\x00\x00")
	if path != "" {
		content, err := readPEMFile(path)
		if err != nil {
			a.showError(err.Error())
		} else {
			setEditText(a.hwndPrivateKey, content)
		}
	}
}

// onSavePEM saves the PEM content from an edit control to a user-chosen file.
func (a *app) onSavePEM(hwnd uintptr, title, defaultName string) {
	content := strings.TrimSpace(getEditText(hwnd))
	if content == "" {
		a.showError("没有可保存的内容")
		return
	}
	path := saveFileDlg(a.hwnd, title, "PEM 文件 (*.pem)\x00*.pem\x00所有文件 (*.*)\x00*.*\x00\x00", defaultName, false)
	if path == "" {
		return
	}
	if err := os.WriteFile(path, []byte(content+"\n"), 0644); err != nil {
		a.showError("保存失败: " + err.Error())
		return
	}
	a.showStatus("✓ 已保存: "+filepath.Base(path), false)
}

func (a *app) onGenKeys() {
	// Show progress and disable button
	startProgressMarquee(a.hwndProgressBar)
	enableControl(a.hwndGenKeyBtn, false)
	a.showStatus("正在生成密钥...", false)

	pub, priv, err := generateSM2KeyPEM()

	// Hide progress and re-enable button
	stopProgressMarquee(a.hwndProgressBar)
	enableControl(a.hwndGenKeyBtn, true)

	if err != nil {
		a.showError(err.Error())
		return
	}
	setEditText(a.hwndPublicKey, strings.TrimLeft(pub, "\n\r"))
	setEditText(a.hwndPrivateKey, strings.TrimLeft(priv, "\n\r"))
	a.showStatus("✓ 已生成 SM2 密钥对", false)
}

func (a *app) onEncrypt() {
	filePath := strings.TrimSpace(getEditText(a.hwndFileInput))
	publicPEM := strings.TrimSpace(getEditText(a.hwndPublicKey))

	if filePath == "" {
		a.showError("请先选择输入文件")
		a.shakeControl(a.hwndFileInput)
		return
	}
	if publicPEM == "" {
		a.showError("请提供 SM2 公钥")
		a.shakeControl(a.hwndPublicKey)
		return
	}

	// Validate PEM format
	if !strings.Contains(publicPEM, "-----BEGIN") || !strings.Contains(publicPEM, "-----END") {
		a.showError("公钥 PEM 格式无效")
		a.shakeControl(a.hwndPublicKey)
		return
	}

	// Show progress and disable buttons
	startProgressMarquee(a.hwndProgressBar)
	enableControl(a.hwndEncryptBtn, false)
	enableControl(a.hwndDecryptBtn, false)
	enableControl(a.hwndBrowseBtn, false)
	a.showStatus("正在加密...", false)

	artifact, err := encryptFileAction(filePath, publicPEM)

	// Hide progress and re-enable buttons
	stopProgressMarquee(a.hwndProgressBar)
	enableControl(a.hwndEncryptBtn, true)
	enableControl(a.hwndDecryptBtn, true)
	enableControl(a.hwndBrowseBtn, true)

	if err != nil {
		a.showError(err.Error())
		return
	}
	a.encResult = artifact
	// Show save button
	procShowWindow.Call(a.hwndSaveBtn, swShow)
	enableControl(a.hwndSaveBtn, true)
	a.resultInfo = fmt.Sprintf("%s (%d bytes)", artifact.Name, len(artifact.Data))
	a.showStatus("✓ 加密成功", false)

	// Success animation: pulse the save button
	a.pulseControl(a.hwndSaveBtn, 0x00FF00)
}

func (a *app) onDecrypt() {
	filePath := strings.TrimSpace(getEditText(a.hwndFileInput))
	privatePEM := strings.TrimSpace(getEditText(a.hwndPrivateKey))

	if filePath == "" {
		a.showError("请先选择输入文件")
		a.shakeControl(a.hwndFileInput)
		return
	}
	if privatePEM == "" {
		a.showError("请提供 SM2 私钥")
		a.shakeControl(a.hwndPrivateKey)
		return
	}

	// Validate PEM format
	if !strings.Contains(privatePEM, "-----BEGIN") || !strings.Contains(privatePEM, "-----END") {
		a.showError("私钥 PEM 格式无效")
		a.shakeControl(a.hwndPrivateKey)
		return
	}

	// Show progress and disable buttons
	startProgressMarquee(a.hwndProgressBar)
	enableControl(a.hwndEncryptBtn, false)
	enableControl(a.hwndDecryptBtn, false)
	enableControl(a.hwndBrowseBtn, false)
	a.showStatus("正在解密...", false)

	artifact, err := decryptFileAction(filePath, privatePEM)

	// Hide progress and re-enable buttons
	stopProgressMarquee(a.hwndProgressBar)
	enableControl(a.hwndEncryptBtn, true)
	enableControl(a.hwndDecryptBtn, true)
	enableControl(a.hwndBrowseBtn, true)

	if err != nil {
		a.showError(err.Error())
		return
	}
	a.encResult = artifact
	// Show save button so user can choose where to save decrypted files
	procShowWindow.Call(a.hwndSaveBtn, swShow)
	enableControl(a.hwndSaveBtn, true)
	if strings.Contains(artifact.OutputPath, "teecrypto_extract") {
		// Archive extraction result (temp dir)
		a.resultInfo = fmt.Sprintf("%s (已解压，待保存)", artifact.Name)
	} else {
		// Raw file (not extracted from archive)
		a.resultInfo = fmt.Sprintf("%s (已解密，待保存)", artifact.Name)
	}
	a.showStatus("✓ 解密成功，请点击保存按钮选择保存位置", false)

	// Success animation: pulse the save button
	a.pulseControl(a.hwndSaveBtn, 0x00FF00)
}

func (a *app) onSave() {
	if a.encResult == nil {
		a.showError("请先执行加密或解密操作")
		return
	}

	// Check if this is a decryption result with archive extraction (OutputPath points to temp dir)
	if a.encResult.OutputPath != "" && strings.Contains(a.encResult.OutputPath, "teecrypto_extract") {
		tempSourcePath := a.encResult.OutputPath

		// Check if temp source still exists
		info, statErr := os.Stat(tempSourcePath)
		if statErr != nil {
			// Temp directory is gone — try to re-extract from stored data
			if a.encResult.Data == nil {
				a.showError(fmt.Sprintf("临时文件已丢失且无备份数据: %v", statErr))
				return
			}
			// Re-extract to a new temp directory
			var reExtractPath string
			var reErr error
			switch {
			case isGzipData(a.encResult.Data):
				reExtractPath, reErr = extractGzipToTempDir(a.encResult.Data)
			case isZipData(a.encResult.Data):
				reExtractPath, reErr = extractZipToTempDir(a.encResult.Data)
			default:
				a.showError("临时文件已丢失，无法重新解压")
				return
			}
			if reErr != nil {
				a.showError(fmt.Sprintf("重新解压失败: %v", reErr))
				return
			}
			tempSourcePath = reExtractPath
			a.encResult.OutputPath = reExtractPath
			info, statErr = os.Stat(tempSourcePath)
			if statErr != nil {
				a.showError(fmt.Sprintf("访问解压文件失败: %v", statErr))
				return
			}
		}

		var userPath string
		if info.IsDir() {
			// Multiple files or folder - let user choose a directory
			userPath = openFolderDlg(a.hwnd, "选择保存位置")
			if userPath == "" {
				return // User cancelled
			}
			err := moveExtractedContent(tempSourcePath, userPath)
			if err != nil {
				a.showError(fmt.Sprintf("保存文件失败: %v", err))
				return
			}
		} else {
			// Single file - let user choose file save location
			filter := "所有文件 (*.*)\x00*.*\x00\x00"
			userPath = saveFileDlg(a.hwnd, "保存解密文件", filter, a.encResult.Name, false)
			if userPath == "" {
				return // User cancelled
			}
			err := moveExtractedContent(tempSourcePath, userPath)
			if err != nil {
				a.showError(fmt.Sprintf("保存文件失败: %v", err))
				return
			}
		}

		// Clean up temp directory
		tempDir := tempSourcePath
		if !info.IsDir() {
			tempDir = filepath.Dir(tempSourcePath)
		}
		os.RemoveAll(tempDir)

		a.showStatus(fmt.Sprintf("✓ 已保存到: %s", userPath), false)
		return
	}

	// Encryption result - use existing save logic
	isEncrypted := strings.HasSuffix(strings.ToLower(a.encResult.Name), ".enc")
	var filter, title string
	forceEnc := false
	if isEncrypted {
		filter = "密文文件 (*.enc)\x00*.enc\x00所有文件 (*.*)\x00*.*\x00\x00"
		title = "保存密文"
		forceEnc = true
	} else {
		filter = "所有文件 (*.*)\x00*.*\x00\x00"
		title = "保存明文"
	}

	path := saveFileDlg(a.hwnd, title, filter, a.encResult.Name, forceEnc)
	if path != "" {
		a.encResult.OutputPath = path
		_, err := saveFileArtifact(a.encResult)
		if err != nil {
			a.showError(err.Error())
		} else {
			a.showStatus("✓ 已保存到 "+path, false)
		}
	}
}

func (a *app) onHelp() {
	messageBox(a.hwnd,
		"格物平台加密工具 v1.0\n\n"+
			"使用说明:\n"+
			"1. 选择要加密或解密的文件\n"+
			"2. 输入或导入 SM2 公钥/私钥\n"+
			"3. 点击「加密」或「解密」按钮\n"+
			"4. 保存结果文件\n\n"+
			"加密流程:\n"+
			"文件 → SM4-GCM 加密 → SM2 包裹密钥 → .enc 文件\n\n"+
			"解密流程:\n"+
			".enc 文件 → SM2 解包密钥 → SM4-GCM 解密 → 明文\n\n"+
			"密钥生成:\n"+
			"点击「生成密钥」自动生成 SM2 密钥对",
		"使用说明", 0x40)
}

func (a *app) showError(msg string) {
	if a.hwndStatusLabel != 0 {
		setEditText(a.hwndStatusLabel, "✗ "+msg)
	}
}

func (a *app) showStatus(msg string, isError bool) {
	if a.hwndStatusLabel != 0 {
		setEditText(a.hwndStatusLabel, msg)
	}
}

func log(format string, args ...interface{}) {
	msg := fmt.Sprintf("[teecrypto-gui] "+format+"\n", args...)
	fmt.Printf("%s", msg)
	// Also write to log file for debugging
	logPath := filepath.Join(os.TempDir(), "teecrypto-gui.log")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(msg)
	}
}

func (a *app) onCommand(ctrlID, notification uint32, ctrlHwnd uintptr) {
	// Handle edit control notifications
	if notification == enChange {
		// Validate input in real-time
		switch ctrlHwnd {
		case a.hwndPublicKey:
			a.validatePEM(ctrlHwnd)
		case a.hwndPrivateKey:
			a.validatePEM(ctrlHwnd)
		case a.hwndFileInput:
			a.validateFilePath(ctrlHwnd)
		}
		return
	}

	// BN_CLICKED = 0
	if notification != 0 {
		return
	}

	// Match control by hwnd
	switch ctrlHwnd {
	case a.hwndEncryptViewBtn:
		a.switchView(0) // Switch to encrypt/decrypt view
	case a.hwndAttestationViewBtn:
		a.switchView(1) // Switch to attestation view
	case a.hwndBrowseBtn:
		a.onBrowse()
	case a.hwndBrowseFolderBtn:
		a.onBrowseFolder()
	case a.hwndEncryptBtn:
		a.onEncrypt()
	case a.hwndDecryptBtn:
		a.onDecrypt()
	case a.hwndSaveBtn:
		a.onSave()
	case a.hwndImportPubBtn:
		a.onImportPub()
	case a.hwndImportPrvBtn:
		a.onImportPrv()
	case a.hwndSavePubBtn:
		a.onSavePEM(a.hwndPublicKey, "保存公钥", "public_key.pem")
	case a.hwndSavePrvBtn:
		a.onSavePEM(a.hwndPrivateKey, "保存私钥", "private_key.pem")
	case a.hwndGenKeyBtn:
		a.onGenKeys()
	case a.hwndVerifyBtn:
		a.onVerifyAttestation()
	case a.hwndReportBrowseBtn:
		a.onBrowseReport()
	}
}

// validatePEM validates PEM format and provides visual feedback
func (a *app) validatePEM(hwnd uintptr) {
	text := getEditText(hwnd)

	// Empty is valid (not an error state)
	if text == "" {
		setEditBorderColor(hwnd, 0) // Default border
		return
	}

	// Check for PEM markers (same for both public and private keys)
	hasBegin := strings.Contains(text, "-----BEGIN")
	hasEnd := strings.Contains(text, "-----END")

	if hasBegin && hasEnd {
		// Valid PEM format - green border
		setEditBorderColor(hwnd, 0x00FF00) // Green
	} else if hasBegin || hasEnd {
		// Partial PEM - yellow border
		setEditBorderColor(hwnd, 0x00FFFF) // Yellow
	} else {
		// Invalid format - red border
		setEditBorderColor(hwnd, 0xFF0000) // Red
	}
}

// validateFilePath validates file path and shows result in status bar
func (a *app) validateFilePath(hwnd uintptr) {
	text := getEditText(hwnd)

	// Empty is valid (not an error state)
	if text == "" {
		a.showStatus("", false)
		return
	}

	// Check if file exists
	if fileExists(text) {
		// File exists - show success in status bar
		a.showStatus("✓ 文件已就绪", false)
	} else {
		// File doesn't exist - show error in status bar
		a.showStatus("✗ 文件不存在", true)
	}
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	// Simple check - try to get file attributes
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	attrs, _, _ := procGetFileAttributesW.Call(uintptr(unsafe.Pointer(pathPtr)))
	return attrs != 0xFFFFFFFF
}

// setEditBorderColor changes the border color of an edit control
func setEditBorderColor(hwnd uintptr, color uint32) {
	// Store the color in the control's user data
	// GWLP_USERDATA = -21 (0xFFFFFFFFFFFFFFEB for 64-bit)
	procSetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)), uintptr(color))
	// Force redraw
	procInvalidateRect.Call(hwnd, 0, 1)
}

// handleCtlColorEdit handles WM_CTLCOLOREDIT for custom border colors
func handleCtlColorEdit(hwnd uintptr, wParam uintptr) uintptr {
	// Get the stored color
	// GWLP_USERDATA = -21 (0xFFFFFFFFFFFFFFEB for 64-bit)
	color, _, _ := procGetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFEB)))

	if color != 0 {
		// Create brush with the border color
		brush, _, _ := procCreateSolidBrush.Call(color)

		// Set text color
		procSetTextColor.Call(wParam, 0x000000) // Black text

		// Set background mode to transparent
		procSetBkMode.Call(wParam, 1) // TRANSPARENT

		return brush
	}

	// Use default handling
	return 0
}

// switchView switches between encrypt/decrypt view and attestation view
func (a *app) switchView(viewIndex int) {
	a.currentView = viewIndex

	if viewIndex == 0 {
		// Hide attestation controls first
		a.showAttestationControls(false)
		// Show encrypt/decrypt controls
		a.showEncryptDecryptControls(true)
	} else {
		// Hide encrypt/decrypt controls first
		a.showEncryptDecryptControls(false)
		// Show attestation controls
		a.showAttestationControls(true)
	}

	// Force complete repaint to clear any visual artifacts from hidden controls
	if a.hwnd != 0 {
		// Invalidate entire client area
		procInvalidateRect.Call(a.hwnd, 0, 1)
		// Force immediate repaint
		procUpdateWindow.Call(a.hwnd)
	}
}

// showEncryptDecryptControls shows or hides encrypt/decrypt controls
func (a *app) showEncryptDecryptControls(show bool) {
	showCmd := int32(0) // SW_HIDE
	if show {
		showCmd = 5 // SW_SHOW
	}

	controls := []uintptr{
		a.hwndKeyPanel,
		a.hwndEncryptBtn,
		a.hwndDecryptBtn,
		a.hwndProgressBar,
		a.hwndFileInput,
		a.hwndBrowseBtn,
		a.hwndBrowseFolderBtn,
		a.hwndSeparator,
		a.hwndFileTitle,
	}

	for _, ctrl := range controls {
		if ctrl != 0 {
			procShowWindow.Call(ctrl, uintptr(showCmd))
		}
	}
}

// showAttestationControls shows or hides attestation controls
func (a *app) showAttestationControls(show bool) {
	showCmd := int32(0) // SW_HIDE
	if show {
		showCmd = 5 // SW_SHOW
	}

	// Hide/show child controls first, then the panel
	childControls := []uintptr{
		a.hwndReportFileInput,
		a.hwndReportBrowseBtn,
		a.hwndVerifyChainCheck,
		a.hwndVerifyBtn,
		a.hwndAttestationTable,
	}

	for _, ctrl := range childControls {
		if ctrl != 0 {
			procShowWindow.Call(ctrl, uintptr(showCmd))
			// Force each control to update immediately
			if !show {
				procInvalidateRect.Call(ctrl, 0, 1)
			}
		}
	}

	// Then hide/show the panel
	if a.hwndAttestationPanel != 0 {
		procShowWindow.Call(a.hwndAttestationPanel, uintptr(showCmd))
		if !show {
			procInvalidateRect.Call(a.hwndAttestationPanel, 0, 1)
		}
	}
}

// onVerifyAttestation handles the verify button click
func (a *app) onVerifyAttestation() {
	reportFile := strings.TrimSpace(getEditText(a.hwndReportFileInput))
	log("onVerifyAttestation: reportFile='%s'", reportFile)
	if reportFile == "" {
		a.showError("请选择报告文件")
		return
	}

	// Check if report file exists
	if _, err := os.Stat(reportFile); os.IsNotExist(err) {
		a.showError("报告文件不存在")
		return
	}

	verifyChain := false
	if a.hwndVerifyChainCheck != 0 {
		checked, _, _ := procSendMessageW.Call(a.hwndVerifyChainCheck, bmGetCheck, 0, 0)
		verifyChain = checked == 1
	}
	log("onVerifyAttestation: verifyChain=%v", verifyChain)

	a.showStatus("正在验证报告...", false)
	result, err := verifyAttestationReportStructured(reportFile, verifyChain)
	if err != nil {
		log("onVerifyAttestation: error=%v", err)
		a.showError(fmt.Sprintf("验证失败: %v", err))
	} else {
		log("onVerifyAttestation: success, ReportVerified=%v, ChainVerified=%v", result.ReportVerified, result.ChainVerified)
		if result.CertDetails != nil {
			log("onVerifyAttestation: HRK.SelfSig=%v, HSK.SigByHRK=%v, CEK.SigByHSK=%v, PEK.SigByCEK=%v",
				result.CertDetails.HRK.SelfSignatureVerified,
				result.CertDetails.HSK.SignedByHRKVerified,
				result.CertDetails.CEK.SignedByHSKVerified,
				result.CertDetails.PEK.SignedByCEKVerified)
		}
		a.showStatus("✓ 验证完成", false)
	}

	if a.hwndAttestationTable == 0 {
		a.showError("表格控件未初始化")
		return
	}

	rows := buildAttestationFieldRows(reportFile, verifyChain, result)
	log("onVerifyAttestation: generated %d rows", len(rows))
	populateAttestationTable(a.hwndAttestationTable, rows)
}

// onBrowseReport triggers report file selection and auto-parses the report.
func (a *app) onBrowseReport() {
	path := openFileDlg(a.hwnd, "选择报告文件", "证书文件 (*.cert)\x00*.cert\x00所有文件 (*.*)\x00*.*\x00\x00")
	if path != "" {
		setEditText(a.hwndReportFileInput, path)
		a.onParseReport()
	}
}

// onParseReport auto-parses the report file and populates the table with base fields.
func (a *app) onParseReport() {
	reportFile := strings.TrimSpace(getEditText(a.hwndReportFileInput))
	log("onParseReport: reportFile='%s'", reportFile)
	if reportFile == "" {
		return
	}

	verifyChain := false
	if a.hwndVerifyChainCheck != 0 {
		checked, _, _ := procSendMessageW.Call(a.hwndVerifyChainCheck, bmGetCheck, 0, 0)
		verifyChain = checked == 1
	}
	log("onParseReport: verifyChain=%v, tableHwnd=%v", verifyChain, a.hwndAttestationTable)

	result, err := verifyAttestationReportStructured(reportFile, verifyChain)
	if err != nil {
		log("onParseReport: error=%v", err)
		a.showStatus(fmt.Sprintf("报告解析完成: %v", err), true)
	} else {
		log("onParseReport: success")
		a.showStatus("✓ 报告已解析", false)
	}
	rows := buildAttestationFieldRows(reportFile, verifyChain, result)
	log("onParseReport: generated %d rows", len(rows))
	populateAttestationTable(a.hwndAttestationTable, rows)
}
