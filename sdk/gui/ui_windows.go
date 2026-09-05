//go:build windows

package main

import (
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// Win32 clipboard
var (
	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procGetClipboardData = user32.NewProc("GetClipboardData")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procGlobalFree       = kernel32.NewProc("GlobalFree")
	procSetCursor        = user32.NewProc("SetCursor")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
	idcIbeam      = 32513
	idcArrow      = 32512
)

// control is the interface for all UI controls
type control interface {
	getBounds() rect
	setBounds(r rect)
	draw(res *d2dResources)
	onMouseDown(x, y int) bool // returns true if handled
	onMouseUp(x, y int)
	onMouseMove(x, y int)
	onKeyDown(key uint32, ch uint16) bool
	needsFocus() bool
	setFocus(focused bool)
}

// baseCtrl provides common functionality for controls
type baseCtrl struct {
	rc      rect
	focused bool
}

func (c *baseCtrl) getBounds() rect                      { return c.rc }
func (c *baseCtrl) setBounds(r rect)                     { c.rc = r }
func (c *baseCtrl) needsFocus() bool                     { return false }
func (c *baseCtrl) setFocus(f bool)                      { c.focused = f }
func (c *baseCtrl) onMouseUp(x, y int)                   {}
func (c *baseCtrl) onMouseMove(x, y int)                 {}
func (c *baseCtrl) onKeyDown(key uint32, ch uint16) bool { return false }
func (c *baseCtrl) draw(res *d2dResources)               {}
func (c *baseCtrl) onMouseDown(x, y int) bool            { return false }

func (c *baseCtrl) hitTest(x, y int) bool {
	return x >= int(c.rc.left) && x < int(c.rc.right) &&
		y >= int(c.rc.top) && y < int(c.rc.bottom)
}

// === Label Control ===
type labelCtrl struct {
	baseCtrl
	text    string
	fmt     uintptr
	brush   uintptr
	visible bool
}

func newLabel(text string) *labelCtrl {
	return &labelCtrl{text: text, visible: true}
}

func (l *labelCtrl) draw(res *d2dResources) {
	if !l.visible {
		return
	}
	fmt := l.fmt
	if fmt == 0 {
		fmt = res.fmtBody
	}
	brush := l.brush
	if brush == 0 {
		brush = res.brushText
	}
	res.drawText(l.text, fmt, brush,
		float32(l.rc.left), float32(l.rc.top),
		float32(l.rc.right), float32(l.rc.bottom))
}

// === Button Control ===
type buttonCtrl struct {
	baseCtrl
	text       string
	onClick    func()
	enabled    bool
	visible    bool
	primary    bool // primary (blue) or secondary (white border)
	centerText bool // center text horizontally (default: left-aligned)
	hovered    bool
	pressed    bool
}

func newButton(text string, primary bool, onClick func()) *buttonCtrl {
	return &buttonCtrl{
		text:    text,
		onClick: onClick,
		enabled: true,
		visible: true,
		primary: primary,
	}
}

func (b *buttonCtrl) draw(res *d2dResources) {
	if !b.visible {
		return
	}
	l, t, r, bt := float32(b.rc.left), float32(b.rc.top), float32(b.rc.right), float32(b.rc.bottom)
	rx := float32(4)

	var bgBrush, textBrush uintptr
	if !b.enabled {
		bgBrush = res.brushDisabled
		textBrush = res.brushWhite
	} else if b.pressed {
		bgBrush = res.brushPress
		textBrush = res.brushWhite
	} else if b.hovered {
		bgBrush = res.brushHover
		textBrush = res.brushWhite
	} else if b.primary {
		bgBrush = res.brushPrimary
		textBrush = res.brushWhite
	} else {
		bgBrush = res.brushCard
		textBrush = res.brushPrimary
	}

	// Shadow for primary buttons
	if b.primary && b.enabled {
		res.drawShadow(l, t, r, bt, rx, rx, 3)
	}

	res.fillRoundedRect(bgBrush, l, t, r, bt, rx, rx)

	// Border for secondary buttons
	if !b.primary && b.enabled {
		res.drawRoundedRect(res.brushPrimary, l+0.5, t+0.5, r-0.5, bt-0.5, rx, rx, 1)
	}

	// Text - centered or left-aligned based on centerText flag
	pad := float32(12)
	if b.centerText {
		res.drawText(b.text, res.fmtBtn, textBrush, l, t, r, bt)
	} else {
		res.drawTextLeft(b.text, res.fmtBtn, textBrush, l+pad, t, r-pad, bt)
	}
}

func (b *buttonCtrl) onMouseDown(x, y int) bool {
	if !b.visible || !b.enabled || !b.hitTest(x, y) {
		return false
	}
	b.pressed = true
	return true
}

func (b *buttonCtrl) onMouseUp(x, y int) {
	if b.pressed && b.visible && b.enabled && b.hitTest(x, y) && b.onClick != nil {
		b.onClick()
	}
	b.pressed = false
}

func (b *buttonCtrl) onMouseMove(x, y int) {
	old := b.hovered
	b.hovered = b.visible && b.enabled && b.hitTest(x, y)
	if old != b.hovered {
		// cursor will be updated by the app
	}
}

// === Text Input Control ===
type textInput struct {
	baseCtrl
	text        string
	placeholder string
	cursor      int
	selStart    int
	onChange    func(string)
	readOnly    bool
	scrollOff   float32 // horizontal scroll offset
	lastRes     *d2dResources
}

// nativeInput wraps a Windows EDIT control for proper text input handling
type nativeInput struct {
	baseCtrl
	hwnd        uintptr
	placeholder string
	onChange    func(string)
}

var (
	procSetWindowTextW    = user32.NewProc("SetWindowTextW")
	procGetWindowTextW    = user32.NewProc("GetWindowTextW")
	procGetWindowTextLenW = user32.NewProc("GetWindowTextLengthW")
	procMoveWindow        = user32.NewProc("MoveWindow")
	procSetFocus          = user32.NewProc("SetFocus")
	procSetWindowPos      = user32.NewProc("SetWindowPos")
	procRedrawWindow      = user32.NewProc("RedrawWindow")
	procEnableWindow      = user32.NewProc("EnableWindow")
	procCreateFontW       = gdi32Main.NewProc("CreateFontW")
)

const (
	wmSetFont      = 0x0030
	emSetReadOnly  = 0x00CF
	wsChild        = 0x40000000
	wsVisible      = 0x10000000
	wsBorder       = 0x00800000
	esAutoHScroll  = 0x0080
	esLeft         = 0x0000
	esMultiline    = 0x0004
	esAutoVScroll  = 0x0040
	esWantReturn   = 0x0004
	wsVScroll      = 0x00200000
	wsHScroll      = 0x00100000
	wsTabStop      = 0x00010000
	wsExClientEdge = 0x00000200
	bsPushButton   = 0x00000000
	bsGroupBox     = 0x00000007
	bsAutoCheckbox = 0x00000003
	bsOwnerDraw    = 0x0000000B

	// Progress bar styles
	pbsMarquee = 0x08

	// Progress bar messages
	pbmSetMarquee = 0x0400 + 10 // WM_USER + 10
	ssLeft         = 0x00000000
	ssVertical     = 0x00000002
	ssCenterImage  = 0x00001000
	ssIcon         = 0x00000003
	hwndTop        = 0
	hwndBottom     = 1           // HWND_BOTTOM = 1
	hwndTopMost    = ^uintptr(0) // HWND_TOPMOST = -1
	swpNoMove      = 0x0002
	swpNoSize      = 0x0001
	swpShowWindow  = 0x0040
	rdwInvalidate  = 0x0001
	rdwErase       = 0x0004
	rdwFrame       = 0x0400
	rdwUpdatNow = 0x0100

	// ListView messages
	lvmInsertColumnW  = 0x1061
	lvmInsertItemW    = 0x104D
	lvmSetItemTextW   = 0x1074
	lvmDeleteAllItems = 0x1009

	// ListView styles
	lvsReport        = 0x0001
	lvsSingleSel     = 0x0004
	lvsShowSelAlways = 0x0008

	// ListView extended styles
	lvsExFullRowSelect          = 0x00000020
	lvsExGridLines              = 0x00000001
	lvsExDoubleBuffer           = 0x01000000
	lvmSetExtendedListViewStyle = 0x1036

	// ListView column format
	lvCFFmt    = 0x0001
	lvCFWidth  = 0x0002
	lvCFText   = 0x0004
	lvCFMTLeft = 0x0000

	// Common controls
	iccListViewClasses = 0x0001
)

// Native control IDs
var nextCtrlID uint32 = 100

func getCtrlID() uint32 {
	id := nextCtrlID
	nextCtrlID++
	return id
}

func newNativeInput(parent uintptr, placeholder string) *nativeInput {
	className := utf16PtrStr("EDIT")
	emptyStr := utf16PtrStr("")

	style := uintptr(wsChild | wsVisible | esAutoHScroll | esLeft)
	exStyle := uintptr(wsExClientEdge)

	hwnd, _, _ := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(emptyStr)),
		style,
		0, 0, 100, 24, // Initial size, will be resized
		parent,
		0,
		getModuleHandle(),
		0,
	)

	// Explicitly show and bring to topmost
	if hwnd != 0 {
		procShowWindow.Call(hwnd, 5) // SW_SHOW
		procSetWindowPos.Call(hwnd, hwndTopMost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)
	}

	// Set placeholder text (will be shown when empty)
	if hwnd != 0 && placeholder != "" {
		textPtr := utf16PtrStr(placeholder)
		procSendMessageW.Call(hwnd, 0x1501, 0, uintptr(unsafe.Pointer(textPtr))) // EM_SETCUEBANNER
	}

	return &nativeInput{
		hwnd:        hwnd,
		placeholder: placeholder,
	}
}

func (ni *nativeInput) setText(text string) {
	if ni.hwnd == 0 {
		return
	}
	textPtr := utf16PtrStr(text)
	procSetWindowTextW.Call(ni.hwnd, uintptr(unsafe.Pointer(textPtr)))
	if ni.onChange != nil {
		ni.onChange(text)
	}
}

func (ni *nativeInput) getText() string {
	if ni.hwnd == 0 {
		return ""
	}
	length, _, _ := procGetWindowTextLenW.Call(ni.hwnd)
	if length == 0 {
		return ""
	}
	buf := make([]uint16, length+1)
	procGetWindowTextW.Call(ni.hwnd, uintptr(unsafe.Pointer(&buf[0])), length+1)
	return syscall.UTF16ToString(buf)
}

func (ni *nativeInput) setBounds(r rect) {
	ni.rc = r
	if ni.hwnd != 0 {
		width := r.right - r.left
		height := r.bottom - r.top
		procMoveWindow.Call(ni.hwnd, uintptr(r.left), uintptr(r.top), uintptr(width), uintptr(height), 1)
		// Bring to topmost to ensure it's visible above D2D rendering
		procSetWindowPos.Call(ni.hwnd, hwndTopMost, 0, 0, 0, 0, swpNoMove|swpNoSize|swpShowWindow)
	}
}

func (ni *nativeInput) needsFocus() bool { return false } // Native control handles its own focus
func (ni *nativeInput) setFocus(f bool)  {}
func (ni *nativeInput) draw(res *d2dResources) {
	// Native control draws itself
}
func (ni *nativeInput) onMouseDown(x, y int) bool { return false }
func (ni *nativeInput) onMouseUp(x, y int)        {}
func (ni *nativeInput) onMouseMove(x, y int)      {}
func (ni *nativeInput) onKeyDown(key uint32, ch uint16) bool { return false }

func newTextInput(placeholder string) *textInput {
	return &textInput{
		placeholder: placeholder,
		cursor:      0,
		selStart:    -1,
	}
}

func (ti *textInput) needsFocus() bool { return true }

func (ti *textInput) setText(text string) {
	ti.text = strings.TrimRight(text, "\r\n\t ")
	runes := []rune(ti.text)
	ti.cursor = len(runes)
	if ti.cursor < 0 {
		ti.cursor = 0
	}
	ti.selStart = -1
	if ti.onChange != nil {
		ti.onChange(ti.text)
	}
}

func (ti *textInput) getText() string { return ti.text }

func (ti *textInput) draw(res *d2dResources) {
	ti.lastRes = res
	l, t, r, bt := float32(ti.rc.left), float32(ti.rc.top), float32(ti.rc.right), float32(ti.rc.bottom)

	// Background
	res.fillRoundedRect(res.brushInputBg, l, t, r, bt, 3, 3)

	// Border
	borderBrush := res.brushBorder
	if ti.focused {
		borderBrush = res.brushPrimary
	}
	res.drawRoundedRect(borderBrush, l+0.5, t+0.5, r-0.5, bt-0.5, 3, 3, 1)

	// Clip to text area
	pad := float32(8)
	res.clipPush(l+pad, t+2, r-pad, bt-2) // Add vertical padding for better centering

	// Text or placeholder - adjust vertical position
	textTop := t + 2
	textBottom := bt - 2
	if ti.text == "" && !ti.focused {
		res.drawTextLeft(ti.placeholder, res.fmtBody, res.brushTextSec, l+pad-ti.scrollOff, textTop, r-pad, textBottom)
	} else {
		res.drawTextLeft(ti.text, res.fmtBody, res.brushText, l+pad-ti.scrollOff, textTop, r-pad, textBottom)
	}

	res.clipPop()

	// Cursor — use measured text width for accurate positioning
	if ti.focused {
		runes := []rune(ti.text)
		var cursorX float32
		if ti.cursor == 0 {
			cursorX = l + pad - ti.scrollOff
		} else if ti.cursor <= len(runes) {
			// Measure text before cursor
			textBefore := string(runes[:ti.cursor])
			textWidth := res.measureTextWidth(textBefore, res.fmtBody)
			// Position cursor at the end of measured text
			cursorX = l + pad - ti.scrollOff + textWidth
		} else {
			cursorX = l + pad - ti.scrollOff
		}
		if cursorX >= l+pad-1 && cursorX <= r-pad+1 {
			res.drawLine(res.brushText, cursorX, t+6, cursorX, bt-6, 1)
		}
	}
}

func (ti *textInput) onMouseDown(x, y int) bool {
	if !ti.hitTest(x, y) {
		return false
	}
	// Find cursor position from click using text measurement
	pad := float32(8)
	// Calculate click position relative to text start
	targetX := float32(x) - float32(ti.rc.left) - pad + ti.scrollOff
	runes := []rune(ti.text)
	pos := len(runes) // default: end of text

	// Build cumulative width array for accurate positioning
	widths := make([]float32, len(runes)+1)
	widths[0] = 0
	for i := 0; i < len(runes); i++ {
		widths[i+1] = ti.lastRes.measureTextWidth(string(runes[:i+1]), ti.lastRes.fmtBody)
	}

	// Find the position closest to targetX
	for i := 0; i < len(runes); i++ {
		if targetX < widths[i+1] {
			// Click is within character i (between widths[i] and widths[i+1])
			mid := (widths[i] + widths[i+1]) / 2
			if targetX < mid {
				pos = i // Before this character
			} else {
				pos = i + 1 // After this character
			}
			break
		}
	}

	if pos < 0 {
		pos = 0
	}
	if pos > len(runes) {
		pos = len(runes)
	}
	ti.cursor = pos
	ti.selStart = -1
	return true
}

func (ti *textInput) onKeyDown(key uint32, ch uint16) bool {
	if ti.readOnly {
		return false
	}
	runes := []rune(ti.text)
	switch key {
	case 0x08: // VK_BACK
		if ti.cursor > 0 {
			runes = append(runes[:ti.cursor-1], runes[ti.cursor:]...)
			ti.cursor--
			ti.text = string(runes)
			if ti.onChange != nil {
				ti.onChange(ti.text)
			}
		}
		return true
	case 0x2E: // VK_DELETE
		if ti.cursor < len(runes) {
			runes = append(runes[:ti.cursor], runes[ti.cursor+1:]...)
			ti.text = string(runes)
			if ti.onChange != nil {
				ti.onChange(ti.text)
			}
		}
		return true
	case 0x25: // VK_LEFT
		if ti.cursor > 0 {
			ti.cursor--
		}
		return true
	case 0x27: // VK_RIGHT
		if ti.cursor < len(runes) {
			ti.cursor++
		}
		return true
	case 0x24: // VK_HOME
		ti.cursor = 0
		return true
	case 0x23: // VK_END
		ti.cursor = len(runes)
		return true
	}
	// Character input
	if ch >= 32 && ch != 127 {
		newRunes := make([]rune, len(runes)+1)
		copy(newRunes, runes[:ti.cursor])
		newRunes[ti.cursor] = rune(ch)
		copy(newRunes[ti.cursor+1:], runes[ti.cursor:])
		ti.text = string(newRunes)
		ti.cursor++
		if ti.onChange != nil {
			ti.onChange(ti.text)
		}
		return true
	}
	return false
}

// === Text Area Control (multi-line) ===
type textArea struct {
	baseCtrl
	text        string
	placeholder string
	cursor      int
	selStart    int
	scrollY     float32
	readOnly    bool
	lineHeight  float32
}

func newTextArea(placeholder string) *textArea {
	return &textArea{
		placeholder: placeholder,
		lineHeight:  20,
		selStart:    -1,
	}
}

func (ta *textArea) needsFocus() bool { return true }

func (ta *textArea) setText(text string) {
	ta.text = text
	ta.cursor = len([]rune(text))
	ta.selStart = -1
}

func (ta *textArea) getText() string { return ta.text }

func (ta *textArea) draw(res *d2dResources) {
	l, t, r, bt := float32(ta.rc.left), float32(ta.rc.top), float32(ta.rc.right), float32(ta.rc.bottom)

	// Background
	res.fillRoundedRect(res.brushInputBg, l, t, r, bt, 3, 3)

	// Border
	borderBrush := res.brushBorder
	if ta.focused {
		borderBrush = res.brushPrimary
	}
	res.drawRoundedRect(borderBrush, l+0.5, t+0.5, r-0.5, bt-0.5, 3, 3, 1)

	// Clip
	pad := float32(8)
	scrollbarWidth := float32(10)
	hasScroll := ta.getContentHeight() > (bt - t)
	contentRight := r
	if hasScroll {
		contentRight = r - scrollbarWidth - 2
	}
	res.clipPush(l+1, t+1, contentRight-1, bt-1)

	if ta.text == "" && !ta.focused {
		res.drawTextLeft(ta.placeholder, res.fmtBody, res.brushTextSec, l+pad, t, contentRight-pad, bt)
	} else {
		// Draw text with scroll offset (use monospace for PEM content)
		res.drawTextLeft(ta.text, res.fmtMono, res.brushText, l+pad, t+pad-ta.scrollY, contentRight-pad, bt+ta.scrollY+100)
	}

	res.clipPop()

	// Draw scrollbar if needed
	if hasScroll {
		ta.drawScrollbar(res, l, t, r, bt, scrollbarWidth)
	}
}

func (ta *textArea) onMouseDown(x, y int) bool {
	if !ta.hitTest(x, y) {
		return false
	}
	// Rough cursor positioning
	charW := float32(7.8) // Consolas 13px approximate
	pad := float32(8)
	lines := strings.Split(ta.text, "\n")
	relY := float32(y) - float32(ta.rc.top) - pad + ta.scrollY
	lineIdx := int(relY / ta.lineHeight)
	if lineIdx < 0 {
		lineIdx = 0
	}
	if lineIdx >= len(lines) {
		lineIdx = len(lines) - 1
	}
	if lineIdx < 0 {
		lineIdx = 0
	}

	relX := float32(x) - float32(ta.rc.left) - pad
	col := int(relX/charW + 0.5)
	if col < 0 {
		col = 0
	}
	if col > len([]rune(lines[lineIdx])) {
		col = len([]rune(lines[lineIdx]))
	}

	// Convert line+col to absolute cursor position
	pos := 0
	for i := 0; i < lineIdx && i < len(lines); i++ {
		pos += len([]rune(lines[i])) + 1 // +1 for newline
	}
	pos += col
	runes := []rune(ta.text)
	if pos > len(runes) {
		pos = len(runes)
	}
	ta.cursor = pos
	return true
}

func (ta *textArea) getContentHeight() float32 {
	lines := strings.Split(ta.text, "\n")
	return float32(len(lines)) * ta.lineHeight
}

func (ta *textArea) ensureCursorVisible() {
	// Calculate cursor line index
	lines := strings.Split(ta.text, "\n")
	lineIdx := 0
	pos := 0
	for i, line := range lines {
		ll := len([]rune(line))
		if pos+ll >= ta.cursor {
			lineIdx = i
			break
		}
		pos += ll + 1
	}

	// Calculate cursor Y position relative to content
	cursorY := float32(lineIdx) * ta.lineHeight
	pad := float32(8)
	viewH := float32(ta.rc.bottom - ta.rc.top) - pad*2

	// Scroll down if cursor is below visible area
	if cursorY-ta.scrollY > viewH-ta.lineHeight {
		ta.scrollY = cursorY - viewH + ta.lineHeight
	}

	// Scroll up if cursor is above visible area
	if cursorY < ta.scrollY {
		ta.scrollY = cursorY
	}

	// Clamp scroll position
	maxScroll := ta.getContentHeight() - viewH
	if maxScroll < 0 {
		maxScroll = 0
	}
	if ta.scrollY < 0 {
		ta.scrollY = 0
	}
	if ta.scrollY > maxScroll {
		ta.scrollY = maxScroll
	}
}

func (ta *textArea) drawScrollbar(res *d2dResources, l, t, r, bt, width float32) {
	// Scrollbar track
	trackX := r - width - 1
	trackY := t + 1
	trackH := bt - t - 2
	res.fillRoundedRect(res.brushBorder, trackX, trackY, r-1, bt-1, 3, 3)

	// Scrollbar thumb
	contentH := ta.getContentHeight()
	if contentH <= 0 {
		return
	}
	viewH := bt - t
	thumbH := (viewH / contentH) * trackH
	if thumbH < 20 {
		thumbH = 20
	}
	maxScroll := contentH - viewH
	if maxScroll < 0 {
		maxScroll = 0
	}
	thumbY := trackY
	if maxScroll > 0 {
		thumbY = trackY + (ta.scrollY/maxScroll)*(trackH-thumbH)
	}
	res.fillRoundedRect(res.brushBorder, trackX, thumbY, r-1, thumbY+thumbH, 3, 3)
}

func (ta *textArea) onKeyDown(key uint32, ch uint16) bool {
	if ta.readOnly {
		return false
	}
	runes := []rune(ta.text)
	switch key {
	case 0x08: // VK_BACK
		if ta.cursor > 0 {
			runes = append(runes[:ta.cursor-1], runes[ta.cursor:]...)
			ta.cursor--
			ta.text = string(runes)
		}
		ta.ensureCursorVisible()
		return true
	case 0x2E: // VK_DELETE
		if ta.cursor < len(runes) {
			runes = append(runes[:ta.cursor], runes[ta.cursor+1:]...)
			ta.text = string(runes)
		}
		ta.ensureCursorVisible()
		return true
	case 0x25: // VK_LEFT
		if ta.cursor > 0 {
			ta.cursor--
		}
		ta.ensureCursorVisible()
		return true
	case 0x27: // VK_RIGHT
		if ta.cursor < len(runes) {
			ta.cursor++
		}
		ta.ensureCursorVisible()
		return true
	case 0x26: // VK_UP
		ta.moveCursorVertical(runes, -1)
		ta.ensureCursorVisible()
		return true
	case 0x28: // VK_DOWN
		ta.moveCursorVertical(runes, 1)
		ta.ensureCursorVisible()
		return true
	case 0x24: // VK_HOME
		// Go to start of current line
		for ta.cursor > 0 && runes[ta.cursor-1] != '\n' {
			ta.cursor--
		}
		ta.ensureCursorVisible()
		return true
	case 0x23: // VK_END
		// Go to end of current line
		for ta.cursor < len(runes) && runes[ta.cursor] != '\n' {
			ta.cursor++
		}
		ta.ensureCursorVisible()
		return true
	case 0x0D: // VK_RETURN
		// Insert newline
		newRunes := make([]rune, len(runes)+1)
		copy(newRunes, runes[:ta.cursor])
		newRunes[ta.cursor] = '\n'
		copy(newRunes[ta.cursor+1:], runes[ta.cursor:])
		ta.text = string(newRunes)
		ta.cursor++
		ta.ensureCursorVisible()
		return true
	}
	// Character input
	if ch >= 32 && ch != 127 {
		newRunes := make([]rune, len(runes)+1)
		copy(newRunes, runes[:ta.cursor])
		newRunes[ta.cursor] = rune(ch)
		copy(newRunes[ta.cursor+1:], runes[ta.cursor:])
		ta.text = string(newRunes)
		ta.cursor++
		ta.ensureCursorVisible()
		return true
	}
	return false
}

func (ta *textArea) moveCursorVertical(runes []rune, dir int) {
	lines := strings.Split(ta.text, "\n")
	pos := 0
	lineIdx := 0
	col := 0
	for i, line := range lines {
		lineLen := len([]rune(line))
		if pos+lineLen >= ta.cursor {
			lineIdx = i
			col = ta.cursor - pos
			break
		}
		pos += lineLen + 1
	}

	newLine := lineIdx + dir
	if newLine < 0 || newLine >= len(lines) {
		return
	}

	// Calculate new position
	newPos := 0
	for i := 0; i < newLine; i++ {
		newPos += len([]rune(lines[i])) + 1
	}
	newCol := col
	lineRunes := []rune(lines[newLine])
	if newCol > len(lineRunes) {
		newCol = len(lineRunes)
	}
	newPos += newCol
	ta.cursor = newPos
}

// === Card Control ===
type cardCtrl struct {
	baseCtrl
	title    string
	children []control
}

func newCard(title string) *cardCtrl {
	return &cardCtrl{title: title}
}

func (c *cardCtrl) addChild(ctrl control) {
	c.children = append(c.children, ctrl)
}

func (c *cardCtrl) draw(res *d2dResources) {
	l, t, r, bt := float32(c.rc.left), float32(c.rc.top), float32(c.rc.right), float32(c.rc.bottom)

	// Shadow
	res.drawShadow(l, t, r, bt, 6, 6, 4)

	// Card background
	res.fillRoundedRect(res.brushCard, l, t, r, bt, 6, 6)

	// Title
	if c.title != "" {
		res.drawText(c.title, res.fmtBodyBold, res.brushText,
			l+16, t+12, r-16, t+36)
	}
}

// === Progress/Status Control ===
type statusCtrl struct {
	baseCtrl
	text    string
	isError bool
	visible bool
}

func newStatus() *statusCtrl {
	return &statusCtrl{}
}

func (s *statusCtrl) setStatus(text string, isError bool) {
	s.text = text
	s.isError = isError
	s.visible = text != ""
}

func (s *statusCtrl) draw(res *d2dResources) {
	if !s.visible {
		return
	}
	brush := res.brushSuccess
	iconChar := "✓"
	if s.isError {
		brush = res.brushError
		iconChar = "✕"
	}
	l, t, r, bt := float32(s.rc.left), float32(s.rc.top), float32(s.rc.right), float32(s.rc.bottom)
	res.fillRoundedRect(brush, l, t, r, bt, 4, 4)

	// Draw icon in white rounded box
	iconBoxSize := float32(24)
	iconX := l + 8
	iconY := t + (bt-t-iconBoxSize)/2
	res.fillRoundedRect(res.brushWhite, iconX, iconY, iconX+iconBoxSize, iconY+iconBoxSize, 4, 4)
	// Icon character in colored text
	res.drawText(iconChar, res.fmtBodyBold, brush, iconX, iconY-1, iconX+iconBoxSize, iconY+iconBoxSize)

	// Text after icon (strip the leading "✓ " or "✕ " if present)
	text := s.text
	if strings.HasPrefix(text, "✓ ") || strings.HasPrefix(text, "✕ ") {
		text = text[4:] // UTF-8: ✓ is 3 bytes + space
	}
	// Draw text left-aligned and vertically centered with the icon
	textX := iconX + iconBoxSize + 8
	textY := iconY
	res.drawTextLeft(text, res.fmtBody, res.brushWhite, textX, textY, r-12, iconY+iconBoxSize)
}

// === Clipboard helpers ===
func clipboardGetText() string {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return ""
	}
	defer procCloseClipboard.Call()

	hMem, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if hMem == 0 {
		return ""
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(hMem)

	// Read null-terminated UTF-16 string
	p := (*[1 << 20]uint16)(unsafe.Pointer(ptr))
	n := 0
	for p[n] != 0 {
		n++
	}
	return string(utf16.Decode(p[:n]))
}

func clipboardSetText(text string) {
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()

	utf16Str := utf16.Encode([]rune(text))
	utf16Str = append(utf16Str, 0) // null terminator
	size := len(utf16Str) * 2

	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if hMem == 0 {
		return
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16Str))
	copy(dst, utf16Str)
	procGlobalUnlock.Call(hMem)

	procSetClipboardData.Call(cfUnicodeText, hMem)
}

// setCursor changes the mouse cursor
func setIBeamCursor() {
	h, _, _ := procLoadCursorW.Call(0, idcIbeam)
	procSetCursor.Call(h)
}

func setArrowCursor() {
	h, _, _ := procLoadCursorW.Call(0, idcArrow)
	procSetCursor.Call(h)
}

// === Native Control Creation Functions ===

func createNativeButton(parent uintptr, text string, x, y, w, h int32) uintptr {
	className := utf16PtrStr("BUTTON")
	textPtr := utf16PtrStr(text)
	style := uintptr(wsChild | wsVisible | bsPushButton | wsTabStop)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativeCheckbox(parent uintptr, text string, x, y, w, h int32) uintptr {
	className := utf16PtrStr("BUTTON")
	textPtr := utf16PtrStr(text)
	style := uintptr(wsChild | wsVisible | bsAutoCheckbox | wsTabStop)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativeEdit(parent uintptr, text string, x, y, w, h int32, multiline bool) uintptr {
	className := utf16PtrStr("EDIT")
	textPtr := utf16PtrStr(text)
	style := uintptr(wsChild | wsVisible | wsTabStop | esLeft)
	if multiline {
		// For multiline: no ES_AUTOHSCROLL to enable word wrap
		style |= esMultiline | esAutoVScroll | wsVScroll | esWantReturn
	} else {
		// For single-line: enable horizontal auto-scroll
		style |= esAutoHScroll
	}
	hwnd, _, _ := procCreateWindowExW.Call(
		wsExClientEdge,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativeProgressBar(parent uintptr, x, y, w, h int32) uintptr {
	className := utf16PtrStr("msctls_progress32")
	// Create hidden initially (no wsVisible), will be shown when needed
	style := uintptr(wsChild | pbsMarquee)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0,
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

// createNativeSeparator creates a horizontal etched line (SS_ETCHEDHORZ)
func createNativeSeparator(parent uintptr, x, y, w int32) uintptr {
	className := utf16PtrStr("STATIC")
	style := uintptr(wsChild | wsVisible | 0x0010) // SS_ETCHEDHORZ = 0x10
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0,
		style,
		uintptr(x), uintptr(y), uintptr(w), 2,
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativeVerticalLabel(parent uintptr, text string, x, y, w, h int32) uintptr {
	className := utf16PtrStr("STATIC")
	textPtr := utf16PtrStr(text)
	style := uintptr(wsChild | wsVisible | ssVertical | ssCenterImage)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativeLabel(parent uintptr, text string, x, y, w, h int32) uintptr {
	className := utf16PtrStr("STATIC")
	textPtr := utf16PtrStr(text)
	style := uintptr(wsChild | wsVisible | ssLeft)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativeIcon(parent uintptr, x, y, w, h int32) uintptr {
	// Use text label for debugging
	return createNativeLabel(parent, "文件", x, y, w, h)
}

func createNativeGroup(parent uintptr, text string, x, y, w, h int32) uintptr {
	// Use STATIC control with border instead of GROUPBOX
	// This allows full control over background color
	className := utf16PtrStr("STATIC")
	textPtr := utf16PtrStr(text)
	style := uintptr(wsChild | wsVisible | ssLeft | wsBorder)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(textPtr)),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	return hwnd
}

func createNativePanel(parent uintptr, x, y, w, h int32) uintptr {
	// Create a STATIC control as a container panel with border
	// Child controls will be created with this panel as parent
	className := utf16PtrStr("STATIC")
	style := uintptr(wsChild | wsVisible | ssLeft | wsBorder | wsClipChildren)
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0,  // No text
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)

	// Subclass the panel to handle child control messages
	if hwnd != 0 {
		// Store original window procedure
		origProc, _, _ := procGetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFFC))) // GWL_WNDPROC = -4
		panelOrigProcs[hwnd] = origProc

		// Set new window procedure
		procSetWindowLongPtr.Call(hwnd, uintptr(uint64(0xFFFFFFFFFFFFFFFC)), uintptr(syscall.NewCallback(panelWndProc)))
	}

	return hwnd
}

// Panel window procedure to handle child control messages
func panelWndProc(hwnd uintptr, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	switch msg {
	case 0x0138: // WM_CTLCOLORSTATIC
		// Handle static control colors (labels)
		hdc := wParam
		procSetBkColor.Call(hdc, 0x00FFFFFF)    // White background
		procSetTextColor.Call(hdc, 0x001E1E1E)  // Near black text
		if whiteBrush != 0 {
			return whiteBrush
		}
		return 0

	case 0x0133: // WM_CTLCOLOREDIT
		// Handle edit control colors
		hdc := wParam
		procSetBkColor.Call(hdc, 0x00FFFFFF)    // White background
		procSetTextColor.Call(hdc, 0x001E1E1E)  // Near black text
		if whiteBrush != 0 {
			return whiteBrush
		}
		return 0

	case 0x0111: // WM_COMMAND
		// Forward command messages to parent window
		parentHwnd, _, _ := procGetParent.Call(hwnd)
		if parentHwnd != 0 {
			procSendMessageW.Call(parentHwnd, 0x0111, wParam, lParam)
		}
		return 0
	}

	// Call original window procedure for other messages
	if origProc, ok := panelOrigProcs[hwnd]; ok {
		ret, _, _ := procCallWindowProc.Call(origProc, hwnd, uintptr(msg), wParam, lParam)
		return ret
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return ret
}

// Store original window procedures for panels
var panelOrigProcs = make(map[uintptr]uintptr)

func getEditText(hwnd uintptr) string {
	if hwnd == 0 {
		return ""
	}
	length, _, _ := procGetWindowTextLenW.Call(hwnd)
	if length == 0 {
		return ""
	}
	buf := make([]uint16, length+1)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), length+1)
	return syscall.UTF16ToString(buf)
}

func setEditText(hwnd uintptr, text string) {
	if hwnd == 0 {
		return
	}
	textPtr := utf16PtrStr(text)
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(textPtr)))
	// Force immediate redraw to show the new text
	procInvalidateRect.Call(hwnd, 0, 1)
	procUpdateWindow.Call(hwnd)
}

func enableControl(hwnd uintptr, enable bool) {
	if hwnd == 0 {
		return
	}
	if enable {
		procEnableWindow.Call(hwnd, 1)
	} else {
		procEnableWindow.Call(hwnd, 0)
	}
}

// Progress bar control functions
func startProgressMarquee(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	// Show the progress bar
	procShowWindow.Call(hwnd, swShow)
	// Start marquee mode (indeterminate progress)
	procSendMessageW.Call(hwnd, pbmSetMarquee, 1, 50) // 50ms update interval
}

func stopProgressMarquee(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	// Stop marquee mode
	procSendMessageW.Call(hwnd, pbmSetMarquee, 0, 0)
	// Hide the progress bar
	procShowWindow.Call(hwnd, 0) // SW_HIDE = 0
}

// Create a font for controls
func createControlFont(height int32, faceName string) uintptr {
	faceNamePtr := utf16PtrStr(faceName)
	font, _, _ := procCreateFontW.Call(
		uintptr(height),    // height
		0,                  // width
		0,                  // escapement
		0,                  // orientation
		400,                // weight (FW_NORMAL)
		0,                  // italic
		0,                  // underline
		0,                  // strikeout
		1,                  // charset (DEFAULT_CHARSET)
		0,                  // outPrecision
		0,                  // clipPrecision
		0,                  // quality
		0,                  // pitchAndFamily
		uintptr(unsafe.Pointer(faceNamePtr)),
	)
	return font
}

// Set font for a control
func setControlFont(hwnd, font uintptr, redraw bool) {
	if hwnd != 0 && font != 0 {
		redrawParam := uintptr(0)
		if redraw {
			redrawParam = 1
		}
		procSendMessageW.Call(hwnd, wmSetFont, font, redrawParam)
	}
}

// === ListView helpers (SysListView32) ===

type lvColumnW struct {
	Mask      uint32
	Fmt       int32
	Cx        int32
	PszText   *uint16
	CchTextMax int32
	ISubItem  int32
	IImage    int32
	IOrder    int32
	CxMin     int32
	CxDefault int32
	CxIdeal   int32
}

type lvItemW struct {
	Mask       uint32
	IItem      int32
	ISubItem   int32
	State      uint32
	StateMask  uint32
	PszText    *uint16
	CchTextMax int32
	IImage     int32
	LParam     uintptr
	IIndent    int32
	IGroupId   int32
	CColumns   uint32
	PuColumns  *uint32
	PxColumns  *uint32
}

type initCommonControlsEx struct {
	DwSize uint32
	DwICC  uint32
}

func initListViewClass() {
	var icc initCommonControlsEx
	icc.DwSize = uint32(unsafe.Sizeof(icc))
	icc.DwICC = iccListViewClasses
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
}

func createNativeListView(parent uintptr, x, y, w, h int32) uintptr {
	className := utf16PtrStr("SysListView32")
	style := uintptr(wsChild | wsVisible | lvsReport | lvsShowSelAlways | lvsSingleSel | wsVScroll | wsBorder)
	exStyle := uintptr(wsExClientEdge)
	hwnd, _, _ := procCreateWindowExW.Call(
		exStyle,
		uintptr(unsafe.Pointer(className)),
		0,
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent,
		uintptr(getCtrlID()),
		getModuleHandle(),
		0,
	)
	if hwnd != 0 {
		procSendMessageW.Call(hwnd, lvmSetExtendedListViewStyle,
			uintptr(lvsExFullRowSelect|lvsExGridLines|lvsExDoubleBuffer), 0)
	}
	return hwnd
}

func listViewInsertColumn(hwnd uintptr, col int32, text string, width int32) {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	column := lvColumnW{
		Mask:    lvCFFmt | lvCFWidth | lvCFText,
		Fmt:     lvCFMTLeft,
		Cx:      width,
		PszText: textPtr,
	}
	procSendMessageW.Call(hwnd, lvmInsertColumnW, uintptr(col), uintptr(unsafe.Pointer(&column)))
}

func listViewInsertItem(hwnd uintptr, index int32, text string) int32 {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	item := lvItemW{
		Mask:    0x0001, // LVIF_TEXT
		IItem:   index,
		ISubItem: 0,
		PszText: textPtr,
	}
	ret, _, _ := procSendMessageW.Call(hwnd, lvmInsertItemW, 0, uintptr(unsafe.Pointer(&item)))
	return int32(ret)
}

func listViewSetItemText(hwnd uintptr, index int32, subItem int32, text string) {
	textPtr, _ := syscall.UTF16PtrFromString(text)
	item := lvItemW{
		PszText:  textPtr,
		ISubItem: subItem,
	}
	procSendMessageW.Call(hwnd, lvmSetItemTextW, uintptr(index), uintptr(unsafe.Pointer(&item)))
}

func listViewClear(hwnd uintptr) {
	procSendMessageW.Call(hwnd, lvmDeleteAllItems, 0, 0)
}

func populateAttestationTable(hwnd uintptr, rows []attestationFieldRow) {
	if hwnd == 0 {
		log("populateAttestationTable: hwnd is 0")
		return
	}
	log("populateAttestationTable: clearing and adding %d rows", len(rows))
	listViewClear(hwnd)
	for i, row := range rows {
		idx := listViewInsertItem(hwnd, int32(i), row.Name)
		log("populateAttestationTable: inserted item %d '%s' -> index %d", i, row.Name, idx)
		listViewSetItemText(hwnd, int32(i), 1, row.Value)
	}
}

